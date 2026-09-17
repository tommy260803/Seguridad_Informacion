from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from phishguard_data.psl import PublicSuffixList
from phishguard_infra.analyzer import InfrastructureAnalyzer
from phishguard_infra.batch import PilotConfigError, load_pilot_config, prepare_pilot, run_pilot
from phishguard_infra.config import InfrastructureConfigError, load_infrastructure_config
from phishguard_infra.resolver import SocketResolver
from phishguard_infra.transport import PinnedHttpTransport


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishinfra-batch")
    parser.add_argument("--pilot-config", required=True, type=Path)
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--analyzer-config", type=Path)
    parser.add_argument("--psl", type=Path)
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    try:
        pilot_config = load_pilot_config(args.pilot_config)
        if args.plan_only:
            _, result = prepare_pilot(pilot_config, args.dataset, args.output)
        else:
            if args.analyzer_config is None or args.psl is None:
                raise PilotConfigError("Acquisition requires --analyzer-config and --psl")
            config = load_infrastructure_config(args.analyzer_config)
            if config.require_sandbox_marker and os.environ.get("PHISHGUARD_SANDBOX") != "1":
                raise InfrastructureConfigError(
                    "Network acquisition is disabled outside PHISHGUARD_SANDBOX=1"
                )
            analyzer = InfrastructureAnalyzer(
                config,
                PublicSuffixList.from_file(args.psl),
                SocketResolver(),
                PinnedHttpTransport(config),
            )
            result = run_pilot(pilot_config, args.dataset, args.output, analyzer)
    except (InfrastructureConfigError, PilotConfigError, OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        raise SystemExit(2) from exc
    print(json.dumps({"status": "success", "result": result}, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
