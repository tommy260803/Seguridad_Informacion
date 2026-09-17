from __future__ import annotations

import ipaddress
from urllib.parse import SplitResult, quote, urlsplit, urlunsplit

from phishguard_infra.config import InfrastructureConfig
from phishguard_infra.models import Resolution, ValidatedTarget


class UnsafeTargetError(ValueError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


_BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata.google.com",
        "instance-data",
    }
)
_BLOCKED_SUFFIXES = ("localhost", "local", "internal", "home", "lan")
_TRANSITION_NETWORKS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
    ipaddress.ip_network("2002::/16"),
    ipaddress.ip_network("2001::/32"),
)


def _is_forbidden_address(value: str) -> tuple[bool, str | None]:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise UnsafeTargetError("invalid_dns_address", f"Resolver returned invalid address: {value!r}") from exc
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return True, "ipv4_mapped_ipv6"
        if any(address in network for network in _TRANSITION_NETWORKS):
            return True, "ipv6_transition_prefix"
    if (
        not address.is_global
        or address.is_multicast
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
    ):
        return True, "non_global_address"
    return False, None


class TargetPolicy:
    def __init__(self, config: InfrastructureConfig) -> None:
        self.config = config

    def parse_url(self, value: str) -> tuple[str, str, int, str, str]:
        if not value or len(value) > self.config.max_url_length:
            raise UnsafeTargetError("url_length", "URL is empty or exceeds the configured limit")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise UnsafeTargetError("url_control_character", "URL contains a control character")
        try:
            parsed = urlsplit(value)
            host_unicode = parsed.hostname
            explicit_port = parsed.port
        except ValueError as exc:
            raise UnsafeTargetError("invalid_url", "URL authority is invalid") from exc
        scheme = parsed.scheme.lower()
        if scheme not in self.config.allowed_ports:
            raise UnsafeTargetError("disallowed_scheme", f"Scheme is not allowed: {scheme!r}")
        if parsed.username is not None or parsed.password is not None:
            raise UnsafeTargetError("userinfo_not_allowed", "Network acquisition does not accept URL credentials")
        if not host_unicode:
            raise UnsafeTargetError("missing_host", "URL has no host")
        try:
            host = host_unicode.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise UnsafeTargetError("invalid_host", "Hostname cannot be encoded as IDNA") from exc
        if not host or len(host) > 253:
            raise UnsafeTargetError("invalid_host", "Hostname length is invalid")
        if host in _BLOCKED_HOSTS or any(
            host == suffix or host.endswith(f".{suffix}") for suffix in _BLOCKED_SUFFIXES
        ):
            raise UnsafeTargetError("blocked_hostname", f"Hostname is locally scoped: {host}")
        default_port = 443 if scheme == "https" else 80
        port = explicit_port or default_port
        if port not in self.config.allowed_ports[scheme]:
            raise UnsafeTargetError("disallowed_port", f"Port {port} is not allowed for {scheme}")
        display_host = f"[{host}]" if ":" in host else host
        authority = display_host if port == default_port else f"{display_host}:{port}"
        path = parsed.path or "/"
        encoded_path = quote(path, safe="/%:@!$&'()*+,;=-._~")
        encoded_query = quote(parsed.query, safe="%/:@!$&'()*+,;=?-._~")
        request_target = encoded_path + (f"?{encoded_query}" if encoded_query else "")
        normalized_url = urlunsplit(SplitResult(scheme, authority, path, parsed.query, ""))
        return normalized_url, scheme, host, port, request_target

    def validate_resolution(self, url: str, resolution: Resolution) -> ValidatedTarget:
        normalized_url, scheme, host, port, request_target = self.parse_url(url)
        if resolution.host.lower().rstrip(".") != host:
            raise UnsafeTargetError("resolver_host_mismatch", "Resolution does not match requested hostname")
        if not resolution.addresses:
            raise UnsafeTargetError("dns_empty", f"DNS returned no addresses for {host}")
        normalized_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for raw_address in resolution.addresses:
            forbidden, reason = _is_forbidden_address(raw_address)
            if forbidden:
                raise UnsafeTargetError("blocked_address", f"DNS returned {reason} for {host}")
            normalized_addresses.append(ipaddress.ip_address(raw_address))
        unique = sorted(set(normalized_addresses), key=lambda address: (address.version, int(address)))
        addresses = tuple(str(address) for address in unique)
        return ValidatedTarget(
            url=normalized_url,
            scheme=scheme,
            host=host,
            port=port,
            request_target=request_target,
            addresses=addresses,
            pinned_ip=addresses[0],
            dns_elapsed_ms=resolution.elapsed_ms,
        )
