# Langfuse Firewall Replay

Replay Langfuse `observations_v2` exports through the Silmaril Firewall Python SDK.

This tool is built for offline analysis of Langfuse Blob Storage exports. It reads
enriched observation rows, maps LLM and tool surfaces to Silmaril hook labels, calls
`Firewall.classify(...)` one item at a time, and writes local JSON reports.

It is useful when you want to answer questions like:

- Which historical traces would Silmaril have blocked?
- Which hooks or tools create the highest-risk replay items?
- Which traces should be reviewed before enabling enforcement?

The replay runner is read-only with respect to Langfuse and Silmaril application
state. It does not write scores back to Langfuse and does not import findings into
any downstream system.

## License

This repository uses the same source-available license style as the Silmaril SDKs.
See [LICENSE](LICENSE). The repository can be public, but the license is not an
OSI open source license.

## Quick Start

```bash
git clone https://github.com/Silmaril-Security/langfuse-firewall-replay.git
cd langfuse-firewall-replay

python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

export SILMARIL_API_KEY="..."
export SILMARIL_API_URL="https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/classify"

langfuse-firewall-replay \
  --input /path/to/langfuse-export/observations_v2 \
  --out runs/replay
```

For parser validation without API calls:

```bash
langfuse-firewall-replay --input /path/to/observations_v2 --dry-run
```

## Install

Install from GitHub:

```bash
pip install "git+https://github.com/Silmaril-Security/langfuse-firewall-replay.git@main"
```

If the package has been published to your package index, install it with:

```bash
pip install langfuse-firewall-replay silmaril-security-sdk
```

For local development from a checkout:

```bash
pip install -e ".[dev]"
```

If you are developing against a local Silmaril SDK checkout instead of the
published package, install that SDK in the same virtual environment.

## Supported Input

The primary input is Langfuse Blob Storage `observations_v2`, also called
enriched observations. Supported file types:

- `.jsonl`
- `.json`
- `.jsonl.gz`
- `.json.gz`

JSONL is preferred for large exports. `.json` and `.json.gz` files are parsed as
single JSON documents and are capped to avoid accidental huge loads.

`--input` may point to one file or a directory. If the directory contains an
`observations_v2` subtree, only files from that subtree are replayed. This avoids
accidentally processing `scores`, legacy `traces`, or legacy `observations` files
from the same export root.

## Configuration

The CLI defaults are generic metadata values:

```text
--tenant default
--stage prod
--region us-west-2
```

These values are written to `summary.json` and are also used to derive an optional
tenant-specific API URL environment variable.

API URL resolution order:

1. `--api-url`
2. `SILMARIL_<TENANT>_<STAGE>_API_URL`
3. `SILMARIL_API_URL`

For example:

```bash
export SILMARIL_ACME_PROD_API_URL="https://<api-id>.execute-api.us-west-2.amazonaws.com/prod/classify"

langfuse-firewall-replay \
  --tenant acme \
  --stage prod \
  --input ./exports/observations_v2
```

`SILMARIL_API_KEY` is required for live replay. `--dry-run` does not require
credentials.

Useful options:

```text
--workers N       Classify items concurrently, still one classify(...) call per item.
--limit N         Replay only the first N extracted items.
--include-text    Include full input text in results.jsonl.
--include-preview Include short text previews in results.jsonl.
--plain-identifiers
                  Write raw trace, observation, session, and user identifiers.
--hash-salt VALUE Use a deterministic salt for hashed text and identifiers.
--include-error-details
                  Write raw exception messages.
--include-source-paths
                  Write input file paths to report artifacts.
--dry-run         Extract and report without calling the firewall.
```

## Hook Mapping

| Langfuse surface | Silmaril hook |
| --- | --- |
| Last user/human message in generation input | `user_input` |
| Plain generation input | `user_input` |
| Tool/function messages in generation input | `tool_response` |
| Generation output | `llm_output` |
| `tool_calls` payloads/arguments | `tool_call` |
| Tool/retriever span input | `tool_call` |
| Tool/retriever span output | `tool_response` |
| System messages | skipped and counted |

The replay runner intentionally never calls `classify_batch`. Each extracted item
is sent in shadow mode via:

```python
fw.classify(text, hook=hook, tool_name=tool_name, shadow_mode=True)
```

That keeps SDK sanitization, retry behavior, and long-input chunking in one place.
Shadow mode ensures malicious replay items are recorded as `MALICIOUS` results
instead of raising block exceptions.

## Output Files

Each run writes three local artifacts:

- `results.jsonl`: one row per replay item with trace/observation ids, hook, tool
  name, source field, prediction, score, optional outcome fields, error details,
  salted text hash, length, and optional preview.
- `trace_summary.jsonl`: one row per trace with max score, malicious count, errors,
  hooks/tools seen, and top triggering item.
- `summary.json`: run config, observation counts, replay counts, skip counts,
  prediction totals, hook totals, errors, and score aggregates.

Full text and text previews are omitted by default. `--include-preview` adds a
short preview, and `--include-text` writes the full replay text.

Text and identifiers are hashed by default with a random per-run salt. Use
`--hash-salt` for stable hashes across runs, or `--plain-identifiers` for raw
identifiers. The configured `/classify` URL is not written to `summary.json`;
only the source of the setting is recorded.

## Development

```bash
pytest -q
ruff check src tests
python -m build
```

The tests include a guard fake client where `classify_batch` raises if it is ever
called.
