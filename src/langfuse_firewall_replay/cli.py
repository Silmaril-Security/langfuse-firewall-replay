"""Command-line entrypoint for Langfuse Firewall replay."""

from __future__ import annotations

import argparse
import os
import secrets
from collections import Counter
from pathlib import Path
from typing import Sequence

from langfuse_firewall_replay.extractor import extract_observation
from langfuse_firewall_replay.loader import ExportLoadError, discover_export_files, iter_export_file
from langfuse_firewall_replay.replay import DEFAULT_RETRIES, DEFAULT_RETRY_BACKOFF, replay_iter
from langfuse_firewall_replay.report import timestamped_run_dir, write_reports

DEFAULT_TENANT = "default"
DEFAULT_STAGE = "prod"
DEFAULT_REGION = "us-west-2"
DEFAULT_WORKERS = 1


def resolve_api_url(args: argparse.Namespace, env: dict[str, str]) -> str | None:
    return args.api_url or env.get("SILMARIL_API_URL")


def resolve_api_url_source(args: argparse.Namespace, env: dict[str, str]) -> str | None:
    if args.api_url:
        return "--api-url"
    if env.get("SILMARIL_API_URL"):
        return "SILMARIL_API_URL"
    return None


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Replay Langfuse observations_v2 exports through Silmaril Firewall.",
    )
    parser.add_argument("--input", type=Path, required=True, help="Langfuse export file or directory")
    parser.add_argument("--out", type=Path, help="Output directory for report artifacts")
    parser.add_argument("--tenant", default=DEFAULT_TENANT)
    parser.add_argument("--stage", default=DEFAULT_STAGE)
    parser.add_argument("--region", default=DEFAULT_REGION)
    parser.add_argument("--api-url", help="Silmaril /classify endpoint URL")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--limit", type=int, help="Maximum replay items to classify")
    parser.add_argument("--timeout", type=float, default=30.0, help="SDK HTTP timeout in seconds")
    parser.add_argument(
        "--retries",
        type=int,
        default=DEFAULT_RETRIES,
        help="Retries for transient classify failures",
    )
    parser.add_argument(
        "--retry-backoff",
        type=float,
        default=DEFAULT_RETRY_BACKOFF,
        help="Initial retry backoff in seconds; doubles after each retry",
    )
    parser.add_argument("--include-text", action="store_true", help="Write full text to results.jsonl")
    parser.add_argument("--include-preview", action="store_true", help="Write short text previews")
    parser.add_argument(
        "--include-error-details",
        action="store_true",
        help="Write raw exception messages to results.jsonl",
    )
    parser.add_argument(
        "--plain-identifiers",
        action="store_true",
        help="Write raw trace, observation, session, and user identifiers",
    )
    parser.add_argument(
        "--hash-salt",
        help="Salt for hashed text and identifiers; defaults to a random per-run value",
    )
    parser.add_argument(
        "--identifier-salt",
        dest="hash_salt",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--include-source-paths",
        action="store_true",
        help="Write input file paths to report artifacts",
    )
    parser.add_argument("--dry-run", action="store_true", help="Parse and report without API calls")
    return parser.parse_args(argv)


def _validate_args(args: argparse.Namespace, api_key: str | None, api_url: str | None) -> None:
    if args.workers < 1:
        raise SystemExit("--workers must be >= 1")
    if args.limit is not None and args.limit < 1:
        raise SystemExit("--limit must be >= 1")
    if args.retries < 0:
        raise SystemExit("--retries must be >= 0")
    if args.retry_backoff < 0:
        raise SystemExit("--retry-backoff must be >= 0")
    if not args.dry_run:
        if not api_key:
            raise SystemExit("SILMARIL_API_KEY is required unless --dry-run is set")
        if not api_url:
            raise SystemExit("Silmaril API URL is required. Use --api-url or SILMARIL_API_URL.")


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    env = os.environ.copy()
    api_key = env.get("SILMARIL_API_KEY")
    api_url = resolve_api_url(args, env)
    api_url_source = resolve_api_url_source(args, env)
    _validate_args(args, api_key, api_url)

    input_path = args.input.expanduser()
    export_files = discover_export_files(input_path)
    stats = {
        "observations": 0,
        "items": 0,
        "limit_reached": False,
    }
    skipped: Counter[str] = Counter()

    def iter_items():
        for export_file in export_files:
            for observation in iter_export_file(export_file):
                stats["observations"] += 1
                extraction = extract_observation(observation)
                skipped.update(extraction.skipped)
                for item in extraction.items:
                    if args.limit is not None and stats["items"] >= args.limit:
                        stats["limit_reached"] = True
                        return
                    stats["items"] += 1
                    yield item

    out_dir = args.out.expanduser() if args.out else timestamped_run_dir()
    results = replay_iter(
        iter_items(),
        api_key=api_key,
        api_url=api_url,
        workers=args.workers,
        dry_run=args.dry_run,
        timeout=args.timeout,
        retries=args.retries,
        retry_backoff=args.retry_backoff,
    )
    hash_identifiers = not args.plain_identifiers
    hash_salt = args.hash_salt or secrets.token_hex(16)
    try:
        paths = write_reports(
            out_dir,
            results=results,
            observation_count=lambda: int(stats["observations"]),
            skipped=lambda: dict(skipped),
            config={
                "tenant": args.tenant,
                "stage": args.stage,
                "region": args.region,
                "api_url_source": api_url_source,
                "api_url_configured": bool(api_url),
                "input": str(input_path) if args.include_source_paths else None,
                "export_file_count": len(export_files),
                "export_files": [str(path) for path in export_files]
                if args.include_source_paths
                else None,
                "workers": args.workers,
                "retries": args.retries,
                "retry_backoff": args.retry_backoff,
                "limit": args.limit,
                "dry_run": args.dry_run,
                "include_text": args.include_text,
                "include_preview": args.include_preview,
                "include_error_details": args.include_error_details,
                "plain_identifiers": args.plain_identifiers,
                "include_source_paths": args.include_source_paths,
            },
            include_text=args.include_text,
            include_preview=args.include_preview,
            include_error_details=args.include_error_details,
            hash_identifiers=hash_identifiers,
            identifier_salt=hash_salt,
            include_source_paths=args.include_source_paths,
        )
    except ExportLoadError as exc:
        raise SystemExit(str(exc)) from exc

    print(f"Loaded observations: {stats['observations']}")
    print(f"Replay items: {stats['items']}")
    print(f"Results: {paths['results']}")
    print(f"Trace summary: {paths['trace_summary']}")
    print(f"Summary: {paths['summary']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
