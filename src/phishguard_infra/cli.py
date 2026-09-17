from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from phishguard_data.psl import PublicSuffixList
from phishguard_infra.analyzer import InfrastructureAnalyzer
from phishguard_infra.config import InfrastructureConfigError, load_infrastructure_config
from phishguard_infra.resolver import SocketResolver
from phishguard_infra.transport import PinnedHttpTransport


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishinfra", description="Acquire safe infrastructure evidence")
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--psl", required=True, type=Path)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--url")
    target.add_argument("--url-file", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def _target_url(url: str | None, url_file: Path | None) -> str:
    if url is not None:
        return url
    if url_file is None:
        raise InfrastructureConfigError("A URL or URL file is required")
    lines = url_file.read_text(encoding="utf-8").splitlines()
    if len(lines) != 1 or not lines[0].strip():
        raise InfrastructureConfigError("URL file must contain exactly one non-empty line")
    return lines[0].strip()


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    try:
        config = load_infrastructure_config(args.config)
        if config.require_sandbox_marker and os.environ.get("PHISHGUARD_SANDBOX") != "1":
            raise InfrastructureConfigError(
                "Network acquisition is disabled outside PHISHGUARD_SANDBOX=1"
            )
        psl = PublicSuffixList.from_file(args.psl)
        analyzer = InfrastructureAnalyzer(
            config,
            psl,
            SocketResolver(),
            PinnedHttpTransport(config),
        )
        result = analyzer.analyze(_target_url(args.url, args.url_file))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(result.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (InfrastructureConfigError, OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2) from exc
    print(json.dumps({"status": result.status, "output": str(args.output)}, ensure_ascii=False))
