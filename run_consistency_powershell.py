import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parent
OUTPUT_DIR = ROOT / "outputs" / "powershell_consistency_runs"
RUN_COUNT = 5
SLEEP_SECONDS = 2


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")

    summary_lines = []
    started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary_lines.append(f"Started: {started_at}")
    summary_lines.append(f"Run count: {RUN_COUNT}")
    summary_lines.append("")

    print(f"[powershell-consistency] Writing artifacts to {OUTPUT_DIR}")

    for run_number in range(1, RUN_COUNT + 1):
        run_id = f"run_{run_number:02d}"
        run_log = OUTPUT_DIR / f"{run_id}.log"
        run_pdf = OUTPUT_DIR / f"{run_id}.pdf"

        env["RUN_ID"] = run_id
        print(f"[powershell-consistency] Starting {run_id}")

        run_started = time.perf_counter()
        with run_log.open("w", encoding="utf-8") as log_file:
            proc = subprocess.run(
                [sys.executable, "run_graph_powershell.py"],
                cwd=ROOT,
                env=env,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
            )
        elapsed_seconds = time.perf_counter() - run_started

        if proc.returncode == 0:
            latest_pdf = ROOT / "outputs" / "powershell_case" / "final_report_powershell.pdf"
            if latest_pdf.exists():
                shutil.copy2(latest_pdf, run_pdf)
            summary_lines.append(
                f"{run_id}: success | elapsed_seconds={elapsed_seconds:.3f} | log={run_log.name} | pdf={run_pdf.name}"
            )
            print(f"[powershell-consistency] Completed {run_id}")
        else:
            summary_lines.append(
                f"{run_id}: failed (exit {proc.returncode}) | elapsed_seconds={elapsed_seconds:.3f} | log={run_log.name}"
            )
            print(f"[powershell-consistency] {run_id} failed with exit code {proc.returncode}")

        if run_number < RUN_COUNT:
            time.sleep(SLEEP_SECONDS)

    finished_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary_lines.append("")
    summary_lines.append(f"Finished: {finished_at}")

    summary_path = OUTPUT_DIR / "summary.txt"
    summary_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
    print(f"[powershell-consistency] Summary written to {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
