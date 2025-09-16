## Overview

This repository provides an IDA Pro 9.1+ script that automatically proposes meaningful names for private functions and unnamed global/static data in binaries using an LLM (OpenAI-compatible Chat Completions API). It also exports a function call graph (FCG) and an optional data-aware graph that links functions to strings and data items.

The tool is generic and not tied to any specific operating system or vendor. It works with compiled binaries as analyzed by IDA Pro and Hex-Rays.

## Key Features

- **Private function renaming**: Proposes human-readable names for functions with generic names (e.g., `sub_...`).
- **Function Call Graph (FCG) export**: Exports JSON/DOT/TXT/CSV with nodes, edges, degrees, and summary.
- **Batch and concurrent LLM calls**: Async (aiohttp) or thread pool, with per-minute rate limiting and retries.
- **Robust naming fallback**: If a proposed name conflicts, falls back to `name_0xEA` safely.
- **Inline function comments**: Writes rationale, confidence, and timestamp into function comments.
- **Data-aware mode (optional)**:
  - Collects links: function → strings/data via data references.
  - Detects indirect string-array usage via LLM checks.
  - Computes metrics and proposes names for unnamed non-string data only.
  - Exports `data_aware_graph.json` alongside FCG.
- **Detailed logging**: Plain log + JSONL of LLM requests/responses.

## Requirements

- IDA Pro 9.1 or later
- Hex-Rays decompiler license (for pseudocode-based context; without it, fewer signals are available)
- Python 3 in IDA (IDAPython)
- Network access to an OpenAI-compatible endpoint (Chat Completions)
- Python packages inside IDA:
  - `requests` (required)
  - `aiohttp` (optional, for async mode)

## Files

- `renamer.py`: Main script (generic; not OS-specific).
- `llmsss_config.json` or `llm_config.json`: Configuration file (the script prefers `llmsss_config.json` if present).
- `fcg_output/`: Generated output directory with timestamped subfolders.

## Configuration

Create `llmsss_config.json` (preferred) or `llm_config.json` next to the script. Example:

```json
{
  "api_base_url": "https://api.your-endpoint.example/v1",
  "api_key": "YOUR_API_KEY",
  "model_name": "gpt-4o-mini",
  "max_context_depth": 1,
  "max_asm_lines": 1000,
  "max_pseudocode_lines": 2000,
  "batch_size": 10,
  "max_workers": 4,
  "use_async": true,
  "requests_per_min": 60,
  "max_retries": 3,
  "retry_backoff_base": 0.5,
  "detailed_log_file": "auto",
  "console_quiet": true,
  "fcg_export_enabled": true,
  "fcg_output_dir": "fcg_output",
  "fcg_export_formats": ["json", "dot", "txt", "csv"],
  "fcg_summary_topn": 20,
  "data_aware_enabled": true,
  "min_string_len": 3,
  "zero_gap_max": 32,
  "indirect_string_scan_window": 512,
  "max_indirect_checks_per_run": 50,
  "data_batch_size": 5,
  "max_data_pseudocode_lines": 600,
  "export_data_graph": true,
  "indirect_batch_size": 10,
  "indirect_max_workers": 6
}
```

Notes:
- Set `detailed_log_file` to `"auto"` to auto-generate a timestamped JSONL log file.
- `use_async` requires `aiohttp`; otherwise the script uses threads.
- Tune `requests_per_min` and `max_workers` to fit your API quotas.

## Usage

1) Open your binary in IDA Pro, wait for auto-analysis to complete.

2) Run the script inside IDA:
- IDA menu: File → Script file… → select `renamer_ida91.py`, or
- From IDAPython console:

```python
exec(open(r"/absolute/path/to/renamer_ida91.py").read())
```

3) Choose a task when prompted:
- `1` Rename private functions (and export function call graph)
- `2` Rename unnamed global/static data (build data-aware graph and apply non-string data renames)

4) Outputs are written under `fcg_output/<YYYYMMDD_HHMMSS>/`:
- `call_graph.json`, `call_graph.dot`, `call_graph_summary.txt`, `call_graph_edges.csv`
- `data_aware_graph.json` (when data-aware mode is enabled)
- Logs: a plain log and optional JSONL with LLM exchanges

## OpenAI-Compatible API

The script calls `POST {api_base_url}/chat/completions` with standard fields:
- `model`, `messages`, `temperature`, `max_tokens`
It expects a `choices[0].message.content` string and (optionally) a `usage` object.

## Tuning & Tips

- For large binaries, reduce `batch_size` or degrees of concurrency, and increase timeouts.
- If you get 429/5xx errors, lower `requests_per_min` and/or `max_workers`, or add retries.
- If Hex-Rays is unavailable, the script still runs with reduced context; decompilation-based cues will be missing.
- All applied names are validated; conflicts fall back to `name_0xEA` automatically.

## Troubleshooting

- "Import could not be resolved" in linters: run the script inside IDA; those modules are provided by IDA.
- No edges in the call graph: ensure IDA auto-analysis has completed, and the architecture’s call mnemonics are recognized.
- Empty or very short pseudocode: re-run Hex-Rays decompilation; the script attempts a light reanalysis when inconsistency is detected.

## License

No license specified. If you intend to distribute or use this commercially, please add a license file appropriate to your needs.


