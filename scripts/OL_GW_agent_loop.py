#!/usr/bin/env python3
"""
Autonomous OOT-parser cracking loop using local Ollama (Qwen).

For each iteration:
  1. Snapshot current parser regression scores
  2. Build prompt with: parser source, ground truth, history, baseline scores
  3. Ask LLM for a hypothesis + unified diff
  4. Static safety check on the diff (forbidden patterns)
  5. Apply diff to python/oot_parser_v2.py
  6. Run regression
  7. If improved AND no solved-file regression → commit + push. Else → revert.
  8. Append iteration log to agent_runs/log.jsonl
  9. Repeat until interrupted (Ctrl-C) or stop_file present

Run:
  python3 scripts/OL_GW_agent_loop.py
Stop gracefully:
  touch agent_runs/STOP

Configure via env:
  OLLAMA_MODEL=qwen3:32b           (default)
  AGENT_DELAY=2                    (seconds between iterations)
  AGENT_MAX_ITERS=0                (0 = unlimited)
"""
import json
import os
import re
import subprocess
import sys
import time
import datetime
import traceback
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / 'scripts'))

import OL_GW_llm_client as llm_client
import OL_GW_agent_safety as agent_safety
import OL_GW_regression as regression


PARSER_PATH = ROOT / 'python' / 'oot_parser_v2.py'
JS_PATH = ROOT / 'js' / 'oot-compare.html'
HISTORY_PATH = ROOT / 'HistoryOfTests.md'
RESEARCH_PATH = ROOT / 'CUBE_GRAMMAR_RESEARCH.md'
LOG_PATH = ROOT / 'agent_runs' / 'log.jsonl'
STOP_FILE = ROOT / 'agent_runs' / 'STOP'

DELAY = float(os.environ.get('AGENT_DELAY', '2'))
MAX_ITERS = int(os.environ.get('AGENT_MAX_ITERS', '0'))


def git(*args, check=True, capture=True):
    """Run a git command, return CompletedProcess."""
    return subprocess.run(['git'] + list(args), check=check,
                          capture_output=capture, text=True, cwd=str(ROOT))


def parser_source() -> str:
    return PARSER_PATH.read_text()


def history_excerpt(max_chars=3000) -> str:
    if not HISTORY_PATH.exists():
        return ''
    text = HISTORY_PATH.read_text()
    return text[-max_chars:]


def research_excerpt(max_chars=3000) -> str:
    if not RESEARCH_PATH.exists():
        return ''
    text = RESEARCH_PATH.read_text()
    return text[-max_chars:]


def parser_assign_axes_section(max_chars=4000) -> str:
    """Extract just the assign_axes function from the parser (most relevant
    for axis cracking). If we can't find it, fall back to last 4KB."""
    src = parser_source()
    # Find the start of `def assign_axes(`
    start = src.find('def assign_axes(')
    if start < 0:
        return src[-max_chars:]
    # End at the next top-level `def ` or class
    rest = src[start:]
    end = max_chars
    # Find a sensible cutoff — first `\n\n\ndef ` or `\nclass ` after start
    for marker in ['\n\n\ndef ', '\nclass ', '\n\ndef trim_coord_groups']:
        idx = rest.find(marker, 100)
        if 0 < idx < end:
            end = idx
    return rest[:end]


def build_prompt(scores_before: dict) -> str:
    """Compose the full prompt to send to the LLM."""
    return f'''You are reverse-engineering the binary structure of Maptek Vulcan's
.00t triangulation file format. The Python parser is at python/oot_parser_v2.py.

YOUR ROLE: propose ONE specific code change per iteration that improves the
parser's correctness on cube test files WITHOUT regressing solved files.

================================================================
GROUND TRUTH (only what's known — do NOT hardcode these in the parser)
================================================================
- cube1: axis-aligned 50³ box, corners X∈{{50,100}} Y∈{{25,75}} Z∈{{10,60}}
- cube2: cube1 rotated -25° around Z (8 unique X, 8 unique Y, 2 unique Z)
- cube3: cube1 rotated -75° around Z
- cube4, cube5: rotated multi-axis (exact rotation TBD)
- cube.00t: ~10x10x40 box at UTM corner (27170, 157410, 1000), opposite (27180, 157420, 1040)
- tri-crack-solid: original solved cube, X∈{{100,300}} Y∈{{500,600}} Z∈{{900,950}}
- All other tri-crack-* files: scored against their .dxf siblings

================================================================
ABSOLUTE RULES (violations cause automatic rejection)
================================================================
1. NO `if filename == "..."` shortcuts (per-file fingerprints)
2. NO `if n_verts == X and n_faces == Y` signature gates
3. NO hardcoded DXF coordinate constants in the parser
4. Every rule must apply uniformly across ALL files; if it only fires on
   cube1, that's a fingerprint
5. Solved files MUST keep their match scores (Triangle 3/3, Plane 4/4,
   Linear 7/7, Cube 8/8, Prism 4/4, 4-Prism 5/5 — these are non-negotiable)
6. Brute-force experiments are FINE; per-file gates are NOT

================================================================
CURRENT BASELINE SCORES (cube4/cube5 have no ground truth yet)
================================================================
{regression.summarize(scores_before)}

================================================================
RECENT TEST HISTORY (last 8KB)
================================================================
{history_excerpt()}

================================================================
RESEARCH NOTES (last 8KB of CUBE_GRAMMAR_RESEARCH.md)
================================================================
{research_excerpt()}

================================================================
CURRENT PARSER — assign_axes() function (python/oot_parser_v2.py)
This is the function most likely to need updating for axis-related rules.
================================================================
{parser_assign_axes_section()}

================================================================
YOUR OUTPUT (strictly this format, nothing else)
================================================================
HYPOTHESIS: <one-line description of the rule you're testing>

SEARCH:
```
<exact code from python/oot_parser_v2.py that you want to replace —
copy it VERBATIM including indentation. Must be unique in the file.>
```

REPLACE:
```
<new code to replace it with — full block including indentation>
```

EXAMPLE:
HYPOTHESIS: lo=B in E0 tag means cycle forward (cube.00t evidence)

SEARCH:
```
                elif first_e0_lo < 7:
                    sm_pred = (prev_g.axis - 1) % 3  # CYCLE BACK
                else:  # lo in {{8, 9, B, C, D, E, F}}
                    sm_pred = (prev_g.axis + 1) % 3  # CYCLE FORWARD
```

REPLACE:
```
                elif first_e0_lo < 7:
                    sm_pred = (prev_g.axis - 1) % 3  # CYCLE BACK
                elif first_e0_lo == 0xB:
                    sm_pred = (prev_g.axis + 1) % 3  # cube.00t-style overlay
                else:
                    sm_pred = (prev_g.axis + 1) % 3  # CYCLE FORWARD
```

If you can't think of a productive change, output:
HYPOTHESIS: SKIP — <reason>

(no SEARCH/REPLACE — the agent will skip this iteration)
'''


THINK_RE = re.compile(r'<think>.*?</think>', re.DOTALL | re.IGNORECASE)
SEARCH_RE = re.compile(r'SEARCH:\s*```(?:\w+)?\n(.*?)```', re.DOTALL | re.IGNORECASE)
REPLACE_RE = re.compile(r'REPLACE:\s*```(?:\w+)?\n(.*?)```', re.DOTALL | re.IGNORECASE)


def strip_thinking(response: str) -> str:
    """Remove <think>...</think> blocks (qwen3 default thinking mode)."""
    return THINK_RE.sub('', response).strip()


def parse_response(response: str):
    """Extract (hypothesis, search_block, replace_block) from the LLM response."""
    body = strip_thinking(response)

    hypothesis = ''
    for line in body.splitlines():
        if line.strip().upper().startswith('HYPOTHESIS:'):
            hypothesis = line.split(':', 1)[1].strip()
            break
    if not hypothesis:
        hypothesis = '(no hypothesis line)'

    if hypothesis.upper().startswith('SKIP'):
        return hypothesis, None, None

    s = SEARCH_RE.search(body)
    r = REPLACE_RE.search(body)
    if not s or not r:
        return hypothesis, None, None
    return hypothesis, s.group(1), r.group(1)


def apply_search_replace(search: str, replace: str) -> tuple:
    """Find `search` in PARSER_PATH and replace with `replace`.
    Tries exact match, then progressively more lenient matching to handle
    minor LLM formatting variations (trailing spaces, tab/space mix, etc.)."""
    src = PARSER_PATH.read_text()
    # 1. Exact match
    if search in src and src.count(search) == 1:
        PARSER_PATH.write_text(src.replace(search, replace))
        return True, 'exact'
    if search in src and src.count(search) > 1:
        return False, f'SEARCH matches {src.count(search)} times — must be unique'

    # 2. Stripped (leading/trailing whitespace)
    stripped = search.strip()
    if stripped in src and src.count(stripped) == 1:
        PARSER_PATH.write_text(src.replace(stripped, replace.strip()))
        return True, 'stripped'

    # 3. Normalize trailing whitespace per line
    norm_search = '\n'.join(line.rstrip() for line in search.strip().splitlines())
    norm_src = '\n'.join(line.rstrip() for line in src.splitlines())
    if norm_search in norm_src and norm_src.count(norm_search) == 1:
        # Find the actual block in the original src that matches
        # (with original trailing whitespace)
        src_lines = src.splitlines(keepends=False)
        search_lines_norm = norm_search.splitlines()
        for i in range(len(src_lines) - len(search_lines_norm) + 1):
            if all(src_lines[i + j].rstrip() == search_lines_norm[j]
                   for j in range(len(search_lines_norm))):
                # Reconstruct the block we'll actually replace
                actual_block = '\n'.join(src_lines[i:i + len(search_lines_norm)])
                if src.count(actual_block) == 1:
                    PARSER_PATH.write_text(src.replace(actual_block, replace.strip()))
                    return True, 'whitespace-normalized'
                break

    # 4. Try matching just the first line as an anchor (last resort)
    first_line = search.strip().splitlines()[0].strip() if search.strip() else ''
    if first_line and src.count(first_line) == 1:
        return False, f'SEARCH block not found exactly. Anchor line "{first_line[:60]}" exists once though — LLM probably altered the search block when copying.'

    return False, 'SEARCH block not found in parser source'


def revert():
    """Restore parser file to HEAD."""
    git('checkout', '--', str(PARSER_PATH))


def commit_and_push(iter_num: int, hypothesis: str, scores_before: dict, scores_after: dict, improvements: list):
    msg = f'AGENT-{iter_num:04d}: {hypothesis}\n\n'
    msg += 'Improvements:\n'
    for imp in improvements:
        msg += f'  - {imp["file"]} {imp["metric"]}: {imp["before"]} → {imp["after"]}\n'
    msg += '\nProposed by autonomous agent loop (Qwen via Ollama).\n'
    git('add', str(PARSER_PATH))
    git('commit', '-m', msg)
    p = git('push', check=False, capture=True)
    return p.returncode == 0


def append_log(entry: dict):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_PATH, 'a') as f:
        f.write(json.dumps(entry) + '\n')


def main():
    print(f'Agent loop starting. Model: {os.environ.get("OLLAMA_MODEL", "qwen3:32b")}')
    if not llm_client.check_available():
        print(f'❌ Ollama not reachable. Run `ollama serve` and pull the model first.')
        return 1
    print('✓ Ollama OK')

    # Verify the parser file is clean (only one we'll modify). Allow other
    # untracked/dirty files (.DS_Store, .claude/*, etc.) since the agent
    # doesn't touch them.
    p = git('status', '--porcelain', str(PARSER_PATH), check=False)
    if p.stdout.strip():
        print(f'❌ {PARSER_PATH} has uncommitted changes:')
        print(p.stdout)
        print('Commit or revert before running the agent.')
        return 1
    print(f'✓ {PARSER_PATH.name} is clean')

    iter_num = 0
    while True:
        iter_num += 1
        if MAX_ITERS and iter_num > MAX_ITERS:
            print(f'Reached MAX_ITERS={MAX_ITERS}, stopping.')
            break
        if STOP_FILE.exists():
            print(f'Stop file detected ({STOP_FILE}), stopping.')
            STOP_FILE.unlink()
            break

        ts = datetime.datetime.now().isoformat(timespec='seconds')
        print(f'\n=== iter {iter_num} @ {ts} ===')

        try:
            scores_before = regression.run_full_regression()
        except Exception as e:
            print(f'  baseline regression failed: {e}')
            time.sleep(DELAY)
            continue

        try:
            prompt = build_prompt(scores_before)
            response = llm_client.call(prompt)
        except Exception as e:
            print(f'  LLM call failed: {e}')
            append_log({'iter': iter_num, 'ts': ts, 'phase': 'llm_call', 'error': str(e)})
            time.sleep(DELAY * 5)
            continue

        hypothesis, search, replace = parse_response(response)
        print(f'  hypothesis: {hypothesis}')

        if search is None or replace is None:
            print(f'  → no SEARCH/REPLACE block (skip)')
            append_log({'iter': iter_num, 'ts': ts, 'hypothesis': hypothesis,
                        'decision': 'skip_no_blocks'})
            time.sleep(DELAY)
            continue

        # Safety check on the REPLACE block (the new code being added)
        # Format it as a fake "+" diff for the existing scan_diff function
        fake_diff = '\n'.join('+' + ln for ln in replace.splitlines())
        findings = agent_safety.scan_diff(fake_diff)
        if findings:
            reasons = '; '.join(f['reason'] for f in findings)
            print(f'  → REJECTED by safety check: {reasons}')
            append_log({'iter': iter_num, 'ts': ts, 'hypothesis': hypothesis,
                        'decision': 'reject_safety', 'findings': findings})
            time.sleep(DELAY)
            continue

        # Apply search/replace
        ok, err = apply_search_replace(search, replace)
        if not ok:
            print(f'  → patch did not apply: {err[:200]}')
            append_log({'iter': iter_num, 'ts': ts, 'hypothesis': hypothesis,
                        'decision': 'reject_apply', 'error': err[:500]})
            time.sleep(DELAY)
            continue

        # Run regression
        try:
            scores_after = regression.run_full_regression()
        except Exception as e:
            print(f'  → regression crashed: {e}; reverting')
            revert()
            append_log({'iter': iter_num, 'ts': ts, 'hypothesis': hypothesis,
                        'decision': 'revert_crash', 'error': str(e)})
            time.sleep(DELAY)
            continue

        regressions = regression.is_regression(scores_before, scores_after)
        improvements = regression.is_improvement(scores_before, scores_after)

        if regressions:
            reg_summary = '; '.join(f'{r["file"]} {r["before"]}→{r["after"]}'
                                    for r in regressions)
            print(f'  → REGRESSION ({reg_summary}); reverting')
            revert()
            append_log({'iter': iter_num, 'ts': ts, 'hypothesis': hypothesis,
                        'decision': 'revert_regression', 'regressions': regressions,
                        'improvements': improvements})
        elif improvements:
            imp_summary = '; '.join(f'{i["file"]} {i["metric"]} {i["before"]}→{i["after"]}'
                                    for i in improvements)
            print(f'  ✓ IMPROVEMENT ({imp_summary}); committing')
            ok = commit_and_push(iter_num, hypothesis, scores_before, scores_after, improvements)
            append_log({'iter': iter_num, 'ts': ts, 'hypothesis': hypothesis,
                        'decision': 'commit', 'pushed': ok,
                        'improvements': improvements})
        else:
            print(f'  → NO CHANGE (no regression, no improvement); reverting')
            revert()
            append_log({'iter': iter_num, 'ts': ts, 'hypothesis': hypothesis,
                        'decision': 'revert_neutral'})

        time.sleep(DELAY)

    return 0


if __name__ == '__main__':
    sys.exit(main())
