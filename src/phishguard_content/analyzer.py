from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from phishguard_content.models import ContentEvidence, ContentResult


class ContentAnalyzerError(ValueError):
    """Raised when content exceeds parser or input safety limits."""


@dataclass(frozen=True)
class ContentLimits:
    max_bytes: int = 2_000_000
    max_tags: int = 100_000
    max_text_characters: int = 500_000
    max_attribute_length: int = 4_096


_LOGIN_TERMS = re.compile(r"\b(log[- ]?in|sign[- ]?in|account|credential|password|verify|auth)\b", re.I)
_PAYMENT_TERMS = re.compile(r"\b(card|credit|debit|cvv|cvc|iban|payment|billing)\b", re.I)
_EMAIL_INPUTS = {"email", "e-mail"}
_EXFIL_TARGETS = re.compile(
    r"(telegram\.org|discord\.com|discordapp\.com|formspree\.io|formsubmit\.co|pipedream\.net|webhook\.site|pastebin\.com|ngrok\.io|serveo\.net)",
    re.I
)


@dataclass
class _FormState:
    action: str = ""
    method: str = "get"
    has_password: bool = False
    has_email: bool = False
    has_payment: bool = False
    input_count: int = 0


@dataclass
class _PageState:
    title: str = ""
    text: list[str] = field(default_factory=list)
    forms: int = 0
    password_inputs: int = 0
    email_inputs: int = 0
    payment_inputs: int = 0
    scripts: int = 0
    iframes: int = 0
    links: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    form_actions: list[str] = field(default_factory=list)
    forms_list: list[_FormState] = field(default_factory=list)
    tags: int = 0
    in_title: bool = False
    text_characters: int = 0


class _BoundedParser(HTMLParser):
    def __init__(self, limits: ContentLimits) -> None:
        super().__init__(convert_charrefs=True)
        self.limits = limits
        self.state = _PageState()
        self.current_form: _FormState | None = None

    def _attributes(self, attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        return {
            key.lower(): (value or "")[: self.limits.max_attribute_length]
            for key, value in attrs
            if len(key) <= self.limits.max_attribute_length
        }

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.state.tags += 1
        if self.state.tags > self.limits.max_tags:
            raise ContentAnalyzerError("HTML tag limit exceeded")
        normalized = tag.lower()
        values = self._attributes(attrs)
        if normalized == "title":
            self.state.in_title = True
        elif normalized == "form":
            self.state.forms += 1
            action = values.get("action", "").strip()
            method = values.get("method", "get").lower().strip()
            form_state = _FormState(action=action, method=method)
            self.current_form = form_state
            self.state.forms_list.append(form_state)
            if action:
                self.state.form_actions.append(action)
        elif normalized == "input":
            input_type = values.get("type", "text").lower()
            name = f"{values.get('name', '')} {values.get('autocomplete', '')}".lower()
            is_pwd = input_type == "password"
            is_email = input_type == "email" or any(term in name for term in _EMAIL_INPUTS)
            is_payment = any(term in name for term in ("card", "cvv", "cvc", "iban", "billing"))
            
            if is_pwd:
                self.state.password_inputs += 1
            if is_email:
                self.state.email_inputs += 1
            if is_payment:
                self.state.payment_inputs += 1
                
            if self.current_form:
                self.current_form.input_count += 1
                if is_pwd:
                    self.current_form.has_password = True
                if is_email:
                    self.current_form.has_email = True
                if is_payment:
                    self.current_form.has_payment = True
        elif normalized == "script":
            self.state.scripts += 1
        elif normalized == "iframe":
            self.state.iframes += 1
        elif normalized == "a" and values.get("href"):
            self.state.links.append(values["href"])
        if normalized in {"img", "script", "iframe", "link", "source"}:
            resource = values.get("src") or values.get("href")
            if resource:
                self.state.resources.append(resource)

    def handle_endtag(self, tag: str) -> None:
        normalized = tag.lower()
        if normalized == "title":
            self.state.in_title = False
        elif normalized == "form":
            self.current_form = None

    def handle_data(self, data: str) -> None:
        text = html.unescape(data)
        remaining = self.limits.max_text_characters - self.state.text_characters
        if remaining <= 0:
            return
        text = text[:remaining]
        self.state.text_characters += len(text)
        if text.strip():
            self.state.text.append(text)
            if self.state.in_title:
                self.state.title += text


def _is_external(value: str, base_url: str) -> bool:
    candidate = urljoin(base_url, value)
    candidate_host = urlsplit(candidate).hostname
    base_host = urlsplit(base_url).hostname
    return bool(candidate_host and base_host and candidate_host.lower() != base_host.lower())


def analyze_html(
    body: bytes,
    base_url: str,
    content_type: str | None = "text/html",
    limits: ContentLimits | None = None,
) -> ContentResult:
    limits = limits or ContentLimits()
    if not isinstance(body, bytes):
        raise ContentAnalyzerError("HTML body must be bytes")
    truncated = len(body) > limits.max_bytes
    bounded = body[: limits.max_bytes]
    if content_type is not None and "html" not in content_type.lower():
        return ContentResult(
            status="blocked",
            content_type=content_type,
            bytes_received=len(bounded),
            truncated=truncated,
            features={"content_available": 0.0, "content_non_html": 1.0},
            evidence=(),
            error_code="non_html_content_type",
            error_detail="Only text/html content is parsed",
        )
    try:
        parser = _BoundedParser(limits)
        parser.feed(bounded.decode("utf-8", errors="replace"))
        parser.close()
    except (ContentAnalyzerError, ValueError) as exc:
        return ContentResult(
            status="error",
            content_type=content_type,
            bytes_received=len(bounded),
            truncated=truncated,
            features={"content_available": 0.0},
            evidence=(),
            error_code="html_parse_limit",
            error_detail=str(exc)[:256],
        )
    state = parser.state
    text = " ".join(state.text)
    external_links = sum(_is_external(value, base_url) for value in state.links)
    external_resources = sum(_is_external(value, base_url) for value in state.resources)
    external_actions = sum(_is_external(value, base_url) for value in state.form_actions)

    # Heurística de Exfiltración de Credenciales en Formularios
    cred_exfil_count = 0
    webhook_exfil_count = 0
    insecure_form_count = 0
    script_form_count = 0

    base_is_https = base_url.lower().startswith("https:")
    for form in state.forms_list:
        act = form.action.strip()
        has_sensitive = form.has_password or form.has_payment
        if not act or act.startswith("#") or act.lower().startswith("javascript:") or act.lower().startswith("data:"):
            if has_sensitive:
                script_form_count += 1
            continue

        candidate = urljoin(base_url, act)
        candidate_host = (urlsplit(candidate).hostname or "").lower()
        base_host = (urlsplit(base_url).hostname or "").lower()
        is_cross = bool(candidate_host and base_host and candidate_host != base_host)

        # 1. Formulario con contraseña/tarjeta que exfiltra a host externo
        if has_sensitive and is_cross:
            cred_exfil_count += 1

        # 2. Exfiltración a webhook / drop service o IP numérica pública
        if _EXFIL_TARGETS.search(candidate) or re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", candidate_host):
            webhook_exfil_count += 1

        # 3. Envío inseguro de credenciales (base HTTPS pero destino HTTP plano)
        if base_is_https and candidate.lower().startswith("http:") and has_sensitive:
            insecure_form_count += 1

    # Score de riesgo compuesto de exfiltración
    exfil_risk = 0.0
    if cred_exfil_count > 0:
        exfil_risk = max(exfil_risk, 0.85)
    if webhook_exfil_count > 0:
        exfil_risk = max(exfil_risk, 0.95)
    if insecure_form_count > 0:
        exfil_risk = max(exfil_risk, 0.75)
    if script_form_count > 0:
        exfil_risk = max(exfil_risk, 0.65)

    features = {
        "content_available": 1.0,
        "content_truncated": float(truncated),
        "content_bytes": float(len(bounded)),
        "html_tag_count": float(state.tags),
        "html_title_length": float(len(state.title.strip())),
        "html_text_length": float(len(text)),
        "html_form_count": float(state.forms),
        "html_password_input_count": float(state.password_inputs),
        "html_email_input_count": float(state.email_inputs),
        "html_payment_input_count": float(state.payment_inputs),
        "html_script_count": float(state.scripts),
        "html_iframe_count": float(state.iframes),
        "html_link_count": float(len(state.links)),
        "html_external_link_count": float(external_links),
        "html_external_resource_count": float(external_resources),
        "html_external_form_action_count": float(external_actions),
        "html_login_term_count": float(len(_LOGIN_TERMS.findall(text))),
        "html_payment_term_count": float(len(_PAYMENT_TERMS.findall(text))),
        "html_credential_exfiltration_count": float(cred_exfil_count),
        "html_webhook_exfiltration_count": float(webhook_exfil_count),
        "html_insecure_credential_form_count": float(insecure_form_count),
        "html_script_credential_form_count": float(script_form_count),
        "form_exfiltration_risk_score": float(exfil_risk),
    }
    evidence = tuple(
        ContentEvidence(feature=name, value=value, source="html-dom", reliable=True)
        for name, value in sorted(features.items())
    )
    return ContentResult(
        status="success",
        content_type=content_type,
        bytes_received=len(bounded),
        truncated=truncated,
        features=features,
        evidence=evidence,
    )
