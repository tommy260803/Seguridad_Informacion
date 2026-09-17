from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PublicSuffixList:
    exact: frozenset[str]
    wildcard: frozenset[str]
    exception: frozenset[str]

    @classmethod
    def from_file(cls, path: Path) -> "PublicSuffixList":
        exact: set[str] = set()
        wildcard: set[str] = set()
        exception: set[str] = set()
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip().lower()
            if not line or line.startswith("//"):
                continue
            if line.startswith("!"):
                exception.add(line[1:])
            elif line.startswith("*."):
                wildcard.add(line[2:])
            else:
                exact.add(line)
        if not exact:
            raise ValueError(f"Public Suffix List is empty: {path}")
        return cls(frozenset(exact), frozenset(wildcard), frozenset(exception))

    def public_suffix(self, host: str) -> str:
        normalized = host.rstrip(".").lower()
        try:
            ipaddress.ip_address(normalized)
            return normalized
        except ValueError:
            pass

        labels = normalized.split(".")
        if not all(labels):
            raise ValueError(f"Invalid host: {host!r}")

        matching_exception: str | None = None
        matches: list[tuple[int, str]] = []
        for index in range(len(labels)):
            candidate = ".".join(labels[index:])
            if candidate in self.exception:
                matching_exception = candidate
            if candidate in self.exact:
                matches.append((len(labels) - index, candidate))
            if index > 0 and candidate in self.wildcard:
                wildcard_value = ".".join(labels[index - 1 :])
                matches.append((len(labels) - index + 1, wildcard_value))

        if matching_exception:
            return ".".join(matching_exception.split(".")[1:])
        if matches:
            return max(matches, key=lambda item: item[0])[1]
        return labels[-1]

    def registrable_domain(self, host: str) -> str:
        normalized = host.rstrip(".").lower()
        try:
            ipaddress.ip_address(normalized)
            return normalized
        except ValueError:
            pass
        suffix = self.public_suffix(normalized)
        host_labels = normalized.split(".")
        suffix_labels = suffix.split(".")
        if len(host_labels) <= len(suffix_labels):
            return normalized
        return ".".join(host_labels[-(len(suffix_labels) + 1) :])
