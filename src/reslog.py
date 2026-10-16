"""
reslog.py — durable results log
===============================
Notebook output scrolls past and dies on re-run. Call log_result(...) at the end
of each gate to append a timestamped, readable record to reports/RESULTS_LOG.md
(and optionally drop a CSV next to it). This is what reconstructs the paper's
numbers later without re-running everything.
"""

import os
import datetime


def log_result(title, body, csv_df=None, csv_name=None, reports_dir="reports"):
    """Append a section to reports/RESULTS_LOG.md.

    title   : short header, e.g. 'Gate 2 v2 (e5+XGBoost) direct->indirect'
    body    : str (a table.to_string(), printed metrics, verdict text, ...)
    csv_df  : optional DataFrame also written to reports/<csv_name>
    """
    os.makedirs(reports_dir, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    md = os.path.join(reports_dir, "RESULTS_LOG.md")
    if not os.path.exists(md):
        with open(md, "w") as f:
            f.write("# Unexplained Traffic results log\n\nAppended automatically by each notebook.\n")
    with open(md, "a") as f:
        f.write(f"\n\n---\n## {title}\n_{stamp}_\n\n```\n{body.rstrip()}\n```\n")
    if csv_df is not None and csv_name:
        csv_df.to_csv(os.path.join(reports_dir, csv_name), index=False)
    print(f"[reslog] appended '{title}' to {md}"
          + (f" + {csv_name}" if csv_name else ""))
