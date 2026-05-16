# Langfuse Firewall Replay

Replay Langfuse `observations_v2` exports through Silmaril Firewall to understand
how historical traces would classify before changing production behavior.

The tool reads a local Langfuse export, extracts user inputs, model outputs, tool
calls, and tool responses, then calls `Firewall.classify(...)` once per extracted
item. It writes local JSON reports for trace analysis.

## Requirements

- Python 3.10 or newer
- A Langfuse `observations_v2` export
- A Silmaril API key
- A Silmaril `/classify` endpoint URL
- Optional: `jq` for the report inspection commands below

Install from GitHub:

```bash
python -m venv .venv
source .venv/bin/activate

pip install "git+https://github.com/Silmaril-Security/langfuse-firewall-replay.git@main"
```

This installs the replay CLI and its Silmaril Python SDK dependency.

For local development from a checkout:

```bash
git clone https://github.com/Silmaril-Security/langfuse-firewall-replay.git
cd langfuse-firewall-replay

python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Input

Use a Langfuse Blob Storage export for `observations_v2`, also called enriched
observations.

Supported files:

- `.jsonl`
- `.jsonl.gz`
- `.json`
- `.json.gz`

Point `--input` at either a single file or the exported `observations_v2`
directory:

```bash
langfuse-firewall-replay --input ./langfuse-export/observations_v2 --dry-run
```

JSONL is preferred for large exports. Single-document `.json` files are capped to
avoid accidental huge loads. CSV is not supported.

## Configure Silmaril

Set the API key and classify endpoint:

```bash
export SILMARIL_API_KEY="..."
export SILMARIL_API_URL="https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/classify"
```

Resolution order:

1. `--api-url`
2. `SILMARIL_API_URL`

## Run A Replay

First validate extraction without API calls:

```bash
langfuse-firewall-replay \
  --input ./langfuse-export/observations_v2 \
  --out runs/dry-run \
  --dry-run \
  --include-preview
```

Then run a live replay:

```bash
langfuse-firewall-replay \
  --input ./langfuse-export/observations_v2 \
  --out runs/replay \
  --tenant acme \
  --stage prod \
  --region us-west-2 \
  --workers 4 \
  --retries 2 \
  --include-preview
```

Each replay item is sent through the Python SDK as:

```python
fw.classify(text, hook=hook, tool_name=tool_name, shadow_mode=True)
```

## What Gets Classified

| Langfuse surface | Silmaril hook |
| --- | --- |
| Last user/human message in generation input | `user_input` |
| Plain generation input | `user_input` |
| Generation output | `llm_output` |
| Tool/function messages in generation input | `tool_response` |
| `tool_calls` arguments or payloads | `tool_call` |
| Tool/retriever span input | `tool_call` |
| Tool/retriever span output | `tool_response` |
| System messages | skipped and counted |

## Output Files

Each run writes three files under `--out`.

### `results.jsonl`

One row per classified replay item. Useful fields:

- `trace_id`
- `observation_id`
- `hook`
- `tool_name`
- `source_field`
- `prediction`
- `score`
- `blocked`
- `error_class`
- `text_hash`
- `text_length`
- `text_preview`, when `--include-preview` is set
- `text`, when `--include-text` is set

Show triggering items:

```bash
jq -r '
  select(.prediction == "MALICIOUS") |
  [.trace_id, .observation_id, .hook, (.tool_name // "-"), .score, (.text_preview // "")]
  | @tsv
' runs/replay/results.jsonl
```

### `trace_summary.jsonl`

One row per trace. Useful fields:

- `trace_id`
- `trace_name`
- `item_count`
- `malicious_count`
- `error_count`
- `max_score`
- `top_hook`
- `top_tool_name`
- `hooks`
- `tools`

Rank traces by highest score:

```bash
jq -s -r '
  sort_by(.max_score // 0) | reverse |
  .[] |
  [.trace_id, (.trace_name // "-"), .malicious_count, .max_score]
  | @tsv
' runs/replay/trace_summary.jsonl
```

### `summary.json`

Run-level counts and aggregate statistics:

- observations processed
- replay items classified
- traces seen
- predictions by label
- hooks seen
- skipped system messages
- errors by class
- max and mean score

Inspect the run summary:

```bash
jq . runs/replay/summary.json
```

## Common Options

```text
--input PATH              Langfuse export file or directory.
--out PATH                Output directory. Defaults to runs/<timestamp>.
--tenant NAME             Tenant label written to summary.json. Default: default.
--stage NAME              Stage label written to summary.json. Default: prod.
--region NAME             Region label written to summary.json. Default: us-west-2.
--api-url URL             Silmaril classify endpoint.
--workers N              Number of concurrent classify calls. Default: 1.
--retries N              Retries for transient classify failures. Default: 2.
--retry-backoff SECONDS  Initial retry backoff; doubles per retry. Default: 0.5.
--limit N                Stop after N extracted replay items.
--dry-run                Parse and write reports without API calls.
--include-preview        Write a short text preview for each item.
--include-text           Write full replay text for each item.
--plain-identifiers      Write raw trace, observation, session, and user ids.
--hash-salt VALUE        Use stable hashes across runs.
--include-error-details  Write raw exception messages.
--include-source-paths   Write input file paths to report artifacts.
```

## Development

```bash
pytest -q
ruff check src tests
python -m build
```
