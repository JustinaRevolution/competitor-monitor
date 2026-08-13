#!/usr/bin/env python3
"""
PriceGazer review/fix loop — runs until a security review comes back with an
empty MUST-fix list, or a safety bound is hit.

Each iteration:
  1. Run an adversarial read-only review (Claude Code, Opus).
  2. Parse the MUST section.
     - Empty/None  -> CLEAN: write final report, exit 0.
     - Items       -> extract them, run a fix pass (Claude Code, Opus),
                      run the test suite + boot check, then loop.
Safety: max rounds, per-invocation timeout, session-limit detection.
Everything is logged to <project>/review-loop/.
"""

import re
import subprocess
import sys
import time
from pathlib import Path

PROJECT = Path("/home/justina/Desktop/Hermes/competitor-monitor")
LOGDIR = PROJECT / "review-loop"
LOGDIR.mkdir(exist_ok=True)
LOG = LOGDIR / "loop.log"
MAX_ROUNDS = 5
CMD_TIMEOUT = 1500  # 25 min per claude invocation

REVIEW_PROMPT = """SIXTH-ROUND SECURITY & CORRECTNESS REVIEW — read-only, do not modify files. This FastAPI app (PriceGazer, competitor price monitoring SaaS at /home/justina/Desktop/Hermes/competitor-monitor) has been through 5 fix rounds. Rounds 1-2 fixed: SSRF (IP pinning via validate_and_pin_async in app/security.py — fetch connects to validated IP with Host header + sni_hostname, manual redirect re-validation, 2MB cap), bcrypt off event loop, CSRF, SECRET_KEY guard, rate limiting, cookie flags, webhook/Stripe guards, scheduler timezone bug, ChangeEvent ordering, is_global check. Round 4 fixed: paywall gate (User.is_active paid flag), check_interval_hours validation (1-168), failure backoff, alert-send rollback, response size cap, bounded concurrency. Round 5 fixed: check_now honoring the failure cooldown, storage caps on ChangeEvent history, CSRF session binding, negative CSRF tests, webhook signature tests, cooldown test for check_now, IDOR tests. Tests exist in tests/test_fixes.py, tests/test_round3.py, and possibly tests/test_round5.py. Your job, adversarial — assume everything is still broken until proven otherwise: 1) Attack the backoff/cooldown: can ANY path (scheduler, check_now, add_url first-check) bypass the cooldown or drive unbounded fetches? 2) Attack CSRF: can a forged/missing token pass on any mutating route? Is the token properly bound to the browser's CSRF cookie? 3) Attack the paywall: can unpaid/unauthenticated users reach any URL-fetching or data-exposing route? Can a forged webhook activate accounts? Does is_active ever get revoked on cancel/expiry? 4) Re-verify SSRF pinning holds; check every fetch path validates (add_url immediate check, check_now, scheduler). 5) Check storage caps: can any user fill the disk? 6) Confirm the test suites genuinely cover the claims (no vacuous passes) and all pass. Report: severity + file:line + exploit scenario + fix per finding, then MUST fix before deploy / SHOULD fix soon / acceptable. Be specific and adversarial. End the MUST section with 'None' if there are no MUST-fix items."""

FIX_PROMPT_TEMPLATE = """Fix these findings from an adversarial review of the PriceGazer FastAPI app (competitor price monitoring SaaS at /home/justina/Desktop/Hermes/competitor-monitor). Read relevant files first, then make precise changes. Do NOT deploy, do NOT touch deploy/setup.sh unless strictly needed.

FINDINGS TO FIX (from the review):
%s

Constraints: Use existing patterns (app/security.py TokenBucket, validate_and_pin_async, etc.). Keep requirements.txt in sync. After fixing, verify: (a) app boots (source venv/bin/activate && python3 -c "import sys; sys.path.insert(0,'.'); from app.main import app; print(app.title)" prints PriceGazer), (b) ALL tests pass (python3 tests/test_fixes.py, python3 tests/test_round3.py, python3 tests/test_round5.py if present, and any new tests you add for the fixes), (c) the specific findings are closed. Report per fix: what changed, file:line, verification results."""


def log(msg: str):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with LOG.open("a") as f:
        f.write(line + "\n")


def run_claude(prompt: str, allowed_tools: str, max_turns: int, max_budget: str, out_name: str) -> str:
    """Run Claude Code in print mode, capture output to a file, return output."""
    cmd = [
        "claude", "-p", prompt,
        "--model", "opus",
        "--allowedTools", allowed_tools,
        "--max-turns", str(max_turns),
        "--max-budget-usd", max_budget,
    ]
    out_path = LOGDIR / out_name
    log(f"RUNNING claude: {out_name} (turns={max_turns}, budget=${max_budget})")
    try:
        proc = subprocess.run(
            cmd, cwd=str(PROJECT), capture_output=True, text=True, timeout=CMD_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        log(f"TIMEOUT after {CMD_TIMEOUT}s on {out_name}")
        (LOGDIR / f"{out_name}.TIMEOUT").touch()
        return ""
    combined = proc.stdout + "\n" + proc.stderr
    out_path.write_text(combined)
    log(f"FINISHED {out_name} (exit={proc.returncode}, {len(combined)} chars)")
    if "hit your session limit" in combined.lower() or "reached your session limit" in combined.lower():
        log("SESSION LIMIT DETECTED — stopping loop, will need manual resume after reset")
        (LOGDIR / "SESSION_LIMIT").touch()
        return "SESSION_LIMIT"
    return combined


def parse_must_section(review_text: str):
    """Return (is_clean, must_items_text)."""
    m = re.search(r"MUST\s+fix\s+before\s+deploy", review_text, re.IGNORECASE)
    if not m:
        # No MUST section at all — treat as inconclusive (dirty) to be safe.
        return False, "NO MUST SECTION FOUND — review format unexpected; manual review required."
    start = m.end()
    after = review_text[start:start + 4000]
    endm = re.search(r"SHOULD\s+fix\s+soon|ACCEPTABLE", after, re.IGNORECASE)
    section = after[:endm.start()] if endm else after
    # Clean if the section is empty/whitespace or contains only None/nothing markers.
    stripped = "\n".join(
        ln.strip() for ln in section.splitlines()
        if ln.strip() and not re.match(r"^[#\-\*\s]*$", ln)
    )
    if not stripped:
        return True, ""
    if re.search(r"^\s*[-*\s]*(none|nothing|no must|no items|clean)\s*$", stripped, re.IGNORECASE):
        return True, ""
    # Also handle "MUST fix before deploy\n\n**None.**" — the bold-markdown None case.
    if re.search(r"^\*\*\s*none\s*\.?\s*\*\*$", stripped, re.IGNORECASE):
        return True, ""
    return False, stripped


def verify_app() -> bool:
    log("VERIFY: boot check + test suites")
    boot = subprocess.run(
        ["bash", "-c", "source venv/bin/activate && python3 -c \"import sys; sys.path.insert(0,'.'); from app.main import app; print(app.title)\""],
        cwd=str(PROJECT), capture_output=True, text=True, timeout=120,
    )
    if "PriceGazer" not in boot.stdout:
        log(f"BOOT FAILED: {boot.stdout} {boot.stderr}")
        return False
    all_ok = True
    for t in ["tests/test_fixes.py", "tests/test_round3.py"]:
        p = PROJECT / t
        if not p.exists():
            continue
        r = subprocess.run(
            ["bash", "-c", f"source venv/bin/activate && python3 {t}"],
            cwd=str(PROJECT), capture_output=True, text=True, timeout=600,
        )
        tail = (r.stdout + r.stderr).strip().splitlines()[-1:] or [""]
        ok = "0 failed" in (r.stdout + r.stderr) or "passed, 0 failed" in (r.stdout + r.stderr)
        log(f"  {t}: {'OK' if ok else 'FAILED'} ({tail[0]})")
        all_ok = all_ok and ok
    return all_ok


def main():
    log("=== PRICEGAZER REVIEW/FIX LOOP STARTED ===")
    for round_no in range(1, MAX_ROUNDS + 1):
        log(f"--- ROUND {round_no} ---")
        review = run_claude(
            REVIEW_PROMPT,
            "Read,Grep,Glob,Bash(git *),Bash(ls *),Bash(find *),Bash(cat *),Bash(python3 -c *)",
            35, "5", f"review_round{round_no}.txt",
        )
        if review == "SESSION_LIMIT" or not review:
            log("Stopping: session limit or empty review output.")
            sys.exit(2)
        clean, must_items = parse_must_section(review)
        if clean:
            log("*** CLEAN REPORT — no MUST-fix items. DONE. ***")
            (LOGDIR / "CLEAN.txt").write_text(review)
            sys.exit(0)
        log(f"Round {round_no}: {len(must_items.splitlines())} MUST item line(s) found — fixing.")
        fix = run_claude(
            FIX_PROMPT_TEMPLATE % must_items,
            "Read,Edit,Write,Bash,Grep,Glob",
            60, "6", f"fix_round{round_no}.txt",
        )
        if fix == "SESSION_LIMIT" or not fix:
            log("Stopping: session limit or empty fix output.")
            sys.exit(2)
        if not verify_app():
            log("Verification FAILED after fix — stopping for manual review.")
            sys.exit(3)
        log(f"Round {round_no} verified green. Re-reviewing.")
    log(f"MAX_ROUNDS ({MAX_ROUNDS}) reached without a clean report — stopping for manual review.")
    sys.exit(4)


if __name__ == "__main__":
    main()
