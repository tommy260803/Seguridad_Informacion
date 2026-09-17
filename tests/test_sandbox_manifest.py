from pathlib import Path


COMPOSE = Path("sandbox/compose.yaml").read_text(encoding="utf-8")
SQUID = Path("sandbox/squid.conf").read_text(encoding="utf-8")
DOCKERFILE = Path("sandbox/worker.Dockerfile").read_text(encoding="utf-8")


def test_worker_has_only_internal_network_and_hardening_controls() -> None:
    worker = COMPOSE.split("  infrastructure-worker:", 1)[1].split("\nnetworks:", 1)[0]

    assert "sandbox_internal: {}" in worker
    assert "egress_public" not in worker
    assert "read_only: true" in worker
    assert 'user: "65532:65532"' in worker
    assert "- ALL" in worker
    assert "no-new-privileges:true" in worker
    assert "pids_limit: 32" in worker
    assert "PHISHGUARD_SANDBOX: \"1\"" in worker
    assert "/var/run/docker.sock" not in worker


def test_internal_network_is_not_directly_routable() -> None:
    networks = COMPOSE.split("\nnetworks:", 1)[1]

    assert "sandbox_internal:" in networks
    assert "internal: true" in networks
    assert "subnet: 172.30.0.0/24" in networks


def test_worker_uses_the_hardened_dns_sidecar() -> None:
    worker = COMPOSE.split("  infrastructure-worker:", 1)[1].split("\nnetworks:", 1)[0]
    resolver = COMPOSE.split("  dns-resolver:", 1)[1].split("\n  egress-proxy:", 1)[0]

    assert "- 172.30.0.3" in worker
    assert "coredns/coredns:1.14.7@sha256:" in resolver
    assert 'user: "65532:65532"' in resolver
    assert "cap_drop:\n      - ALL" in resolver
    assert "cap_add:\n      - NET_BIND_SERVICE" in resolver
    assert "no-new-privileges:true" in resolver


def test_proxy_policy_is_default_deny_and_blocks_special_ranges() -> None:
    required_ranges = (
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "::1/128",
        "64:ff9b::/96",
        "2001::/32",
        "2002::/16",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )

    assert all(value in SQUID for value in required_ranges)
    assert "http_access deny !allowed_ports" in SQUID
    assert "http_access deny connect_method !tls_ports" in SQUID
    assert SQUID.index("http_access allow worker_net") < SQUID.index("http_access deny all")


def test_proxy_also_runs_without_root_or_linux_capabilities() -> None:
    proxy = COMPOSE.split("  egress-proxy:", 1)[1].split(
        "\n  infrastructure-worker:", 1
    )[0]

    assert 'user: "13:13"' in proxy
    assert "cap_drop:\n      - ALL" in proxy
    assert "no-new-privileges:true" in proxy


def test_worker_image_is_non_root_and_does_not_copy_research_data() -> None:
    assert "USER 65532:65532" in DOCKERFILE
    assert "COPY src /app/src" in DOCKERFILE
    assert "COPY ." not in DOCKERFILE
    assert "python:3.13.15-slim-bookworm@sha256:" in DOCKERFILE


def test_target_url_is_mounted_instead_of_exposed_as_an_environment_value() -> None:
    worker = COMPOSE.split("  infrastructure-worker:", 1)[1].split("\nnetworks:", 1)[0]

    assert "TARGET_URL_FILE" in worker
    assert "--url-file" in worker
    assert "TARGET_URL:" not in worker


def test_batch_worker_preserves_isolation_and_mounts_dataset_read_only() -> None:
    pilot = COMPOSE.split("  infrastructure-pilot:", 1)[1].split("\nnetworks:", 1)[0]

    assert "sandbox_internal: {}" in pilot
    assert "egress_public" not in pilot
    assert "read_only: true" in pilot
    assert 'user: "65532:65532"' in pilot
    assert "cap_drop:\n      - ALL" in pilot
    assert "DATASET_PATH" in pilot
    assert "target: /run/input/dataset\n        read_only: true" in pilot
    assert "phishguard_infra.batch_cli" in pilot
