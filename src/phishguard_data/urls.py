from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit

from phishguard_data.psl import PublicSuffixList


_PERCENT_ESCAPE = re.compile(r"%([0-9a-fA-F]{2})")
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


class UrlValidationError(ValueError):
    """Raised for a URL that cannot be safely represented in the dataset."""


@dataclass(frozen=True)
class CanonicalUrl:
    value: str
    scheme: str
    host: str
    registered_domain: str
    has_userinfo: bool


def _normalize_percent_encoding(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        byte = int(match.group(1), 16)
        character = chr(byte)
        return character if character in _UNRESERVED else f"%{byte:02X}"

    return _PERCENT_ESCAPE.sub(replace, value)


def canonicalize_url(
    raw_url: str,
    psl: PublicSuffixList,
    allowed_schemes: tuple[str, ...] = ("http", "https"),
    max_length: int = 8192,
) -> CanonicalUrl:
    value = raw_url.strip()
    if not value or len(value) > max_length:
        raise UrlValidationError("empty_or_too_long")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise UrlValidationError("control_character")
    try:
        parsed = urlsplit(value)
        host_unicode = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise UrlValidationError("invalid_authority") from exc

    scheme = parsed.scheme.lower()
    if scheme not in allowed_schemes:
        raise UrlValidationError("disallowed_scheme")
    if not host_unicode:
        raise UrlValidationError("missing_host")
    try:
        host = host_unicode.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise UrlValidationError("invalid_idna") from exc
    if not host:
        raise UrlValidationError("missing_host")

    has_userinfo = "@" in parsed.netloc
    userinfo = parsed.netloc.rsplit("@", 1)[0] if has_userinfo else ""
    display_host = f"[{host}]" if ":" in host else host
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    authority = display_host if port is None or default_port else f"{display_host}:{port}"
    if has_userinfo:
        authority = f"{userinfo}@{authority}"

    path = _normalize_percent_encoding(parsed.path or "/")
    query = _normalize_percent_encoding(parsed.query)
    canonical = urlunsplit(SplitResult(scheme, authority, path, query, ""))
    return CanonicalUrl(
        value=canonical,
        scheme=scheme,
        host=host,
        registered_domain=psl.registrable_domain(host),
        has_userinfo=has_userinfo,
    )
