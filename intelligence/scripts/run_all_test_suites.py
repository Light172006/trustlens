"""
TrustLens Intelligence — Unified Test Suite Runner & Audit Aggregator
Executes all four intelligence test suites in isolated subprocesses,
aggregates results, and outputs a clean scorecard for the backend handoff report.
"""

from pathlib import Path
import subprocess
import sys
import time

BASE_DIR = Path(__file__).resolve().parent.parent

SUITES = [
    {
        "name": "Threat Analysis Engine (trustlens_intelligence)",
        "cmd": [sys.executable, "-m", "pytest", "tests/", "-v"],
        "cwd": str(BASE_DIR),
    },
    {
        "name": "Collaborative Intelligence Engine (collaborative_intelligence)",
        "cmd": [sys.executable, "-m", "pytest", "collaborative_intelligence/tests/", "-v"],
        "cwd": str(BASE_DIR),
    },
    {
        "name": "Certificate Analyzer Engine (certificate_analyzer)",
        "cmd": [sys.executable, "-m", "pytest", "tests/", "-v"],
        "cwd": str(BASE_DIR / "certificate_analyzer"),
    },
    {
        "name": "Web Security Analyzer (web_security_analysis)",
        "cmd": [sys.executable, "-m", "pytest", "web_security_analysis/tests/", "-v"],
        "cwd": str(BASE_DIR),
    },
]


def run_all():
    print("=" * 80)
    print("TRUSTLENS INTELLIGENCE — UNIFIED TEST SUITE AUDIT")
    print("=" * 80)

    suite_results = []
    t_start = time.perf_counter()

    for suite in SUITES:
        print(f"\n---> Running Suite: {suite['name']}")
        print(f"     Command: {' '.join(suite['cmd'])} (cwd: {suite['cwd']})")

        res = subprocess.run(
            suite["cmd"],
            cwd=suite["cwd"],
            capture_output=True,
            text=True,
        )

        # Parse test count from output
        lines = res.stdout.strip().split("\n")
        summary_line = lines[-1] if lines else ""
        if "passed" not in summary_line and len(lines) > 1:
            summary_line = lines[-2]

        is_passed = res.returncode == 0
        suite_results.append({
            "name": suite["name"],
            "exit_code": res.returncode,
            "status": "PASSED" if is_passed else "FAILED",
            "summary": summary_line.strip("=").strip(),
            "stderr": res.stderr if not is_passed else "",
        })

        print(f"     Result: {'PASSED' if is_passed else 'FAILED'} -> {summary_line.strip('=').strip()}")
        if not is_passed:
            print(f"     Error details:\n{res.stdout}\n{res.stderr}")

    total_time = time.perf_counter() - t_start

    print("\n" + "=" * 80)
    print("INTELLIGENCE LAYER AUDIT SUMMARY SCORECARD")
    print("=" * 80)
    all_passed = True
    for res in suite_results:
        status_symbol = "[PASS]" if res["status"] == "PASSED" else "[FAIL]"
        if res["status"] != "PASSED":
            all_passed = False
        print(f" {status_symbol} {res['name']}: {res['summary']}")
    print("-" * 80)
    print(f" Total Execution Time: {total_time:.2f} seconds")
    print(f" Overall Status: {'ALL SUITES PASSED' if all_passed else 'FAILURES DETECTED'}")
    print("=" * 80)


if __name__ == "__main__":
    run_all()
