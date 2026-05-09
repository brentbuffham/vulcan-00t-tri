# OL-GW autonomous OOT-parser cracking agent

`OL_GW_*` = **O**l**l**ama-**G**w**en** (Qwen). All files in this directory are
part of the local-LLM agent harness.

A Python loop that uses local Ollama (with Qwen or any code-capable model)
to propose, test, and commit incremental improvements to the .00t parser.

## What it does each iteration

1. Snapshots current parser regression scores (DXF matches + ground-truth coverage)
2. Builds a prompt with: parser source, ground truth, history, current scores
3. Calls Ollama, expects a hypothesis + unified diff
4. Static safety check: rejects per-file fingerprints (`if filename ==`,
   `n_verts == X and n_faces == Y`, hardcoded DXF coords, etc.)
5. Applies diff with `git apply`
6. Re-runs regression
7. **Commits + pushes** if any score improved AND no solved-file regression
8. **Reverts** otherwise
9. Logs everything to `agent_runs/log.jsonl`

## Requirements

```
brew install ollama
ollama serve              # leave running in another terminal
ollama pull qwen3:32b     # or whichever model you prefer
pip install ezdxf         # for DXF-based scoring
```

Default model is `qwen3:32b`. To use a different one:
```
export OLLAMA_MODEL=qwen2.5-coder:14b
# or
export OLLAMA_MODEL=qwen3:8b
```

## Run

From the repo root:
```
python3 scripts/OL_GW_agent_loop.py
```

It will run until you stop it. To stop gracefully (after the current iteration):
```
touch agent_runs/STOP
```

Or just Ctrl-C — the parser will be reverted to HEAD before exit.

## Configuration via env vars

| Var | Default | Meaning |
|---|---|---|
| `OLLAMA_URL` | `http://localhost:11434/api/generate` | Ollama API endpoint |
| `OLLAMA_MODEL` | `qwen3:32b` | Model name pulled in Ollama |
| `AGENT_DELAY` | `2` | Seconds between iterations |
| `AGENT_MAX_ITERS` | `0` (unlimited) | Stop after N iterations |

## Files in this directory

- `OL_GW_agent_loop.py` — main loop
- `OL_GW_regression.py` — runs the parser, scores against DXF + ground truth
- `OL_GW_ground_truth.py` — known cube corners + thresholds for solved files
- `OL_GW_llm_client.py` — Ollama API client
- `OL_GW_agent_safety.py` — forbidden-pattern static checks
- `README.md` — this file

## What the agent CAN'T do

- Write per-file fingerprint shortcuts (auto-rejected by safety check)
- Hardcode DXF coordinate values (auto-rejected)
- Modify any file outside `python/oot_parser_v2.py` (it tries to but the
  diff won't include other files unless the LLM proposes one — which gets
  rejected by `git apply` if invalid path)
- Skip regression — every change is tested before commit
- Hide failures — every iteration is logged

## Watching it work

```
tail -f agent_runs/log.jsonl
```

Each line is a JSON object with `iter`, `ts`, `hypothesis`, `decision`,
and either `improvements`, `regressions`, or `error`.

To see commits the agent made:
```
git log --oneline | grep AGENT-
```

## Debugging

If iterations keep failing at "no diff" or "diff didn't apply":
- The LLM probably isn't returning the right format
- Check `agent_runs/log.jsonl` — recent entries show what the LLM said
- Try a different model (qwen2.5-coder is usually good at diffs; tiny models
  might need more guidance)
- Increase the prompt detail in `OL_GW_agent_loop.py`'s `build_prompt()`

If scores never improve:
- Check that the baseline scores are sensible: `python3 scripts/OL_GW_regression.py`
- The agent is asking the LLM to crack genuinely hard remaining problems;
  you may need to tune the prompt with hints about what to focus on
