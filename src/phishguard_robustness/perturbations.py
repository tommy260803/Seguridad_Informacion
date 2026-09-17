from __future__ import annotations

import random
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


@dataclass(frozen=True)
class Perturbation:
    name: str
    original: str
    perturbed: str


def perturb_url(url: str, name: str) -> Perturbation:
    if name == "path_noise":
        parts = urlsplit(url)
        value = urlunsplit((parts.scheme, parts.netloc, "/static/" + parts.path.lstrip("/"), parts.query, parts.fragment))
    elif name == "leetspeak":
        value = url.replace("login", "l0gin").replace("secure", "s3cure")
    elif name == "homoglyph_ascii":
        value = url.replace("a", "4").replace("o", "0")
    else:
        raise ValueError(f"Unsupported URL perturbation: {name}")
    return Perturbation(name, url, value)


def perturb_html(html: str, name: str) -> Perturbation:
    if name == "whitespace":
        value = " ".join(html.split())
    elif name == "attribute_order":
        value = html.replace('<input type="password" name="password">', '<input name="password" type="password">')
    elif name == "wrapper":
        value = f"<div data-wrapper=\"1\">{html}</div>"
    else:
        raise ValueError(f"Unsupported HTML perturbation: {name}")
    return Perturbation(name, html, value)


def generate_suite(value: str, *, kind: str, seed: int = 0) -> list[Perturbation]:
    names = ("path_noise", "leetspeak", "homoglyph_ascii") if kind == "url" else ("whitespace", "attribute_order", "wrapper") if kind == "html" else ()
    if not names:
        raise ValueError("kind must be url or html")
    rng = random.Random(seed)
    shuffled = list(names); rng.shuffle(shuffled)
    return [(perturb_url if kind == "url" else perturb_html)(value, name) for name in shuffled]
