"""
benchmark_mtta.py
------------------
Computes "time from first malicious event to threshold-crossing" for the
two real alerts in data/siem.db -- i.e. how quickly a *streaming* version
of this detector would have fired, based on genuine event timestamps.

Important honesty note: detection_rules.py's _sliding_window_bursts() is a
batch/offline function -- it scans a complete log file and reports the
*final, widest* qualifying window per burst (see its own docstring), not
the instant the threshold was first crossed. That's the right behavior for
a post-hoc incident report ("here's the full scope of the burst"), but it
is NOT the same number as alerting latency in a live system. This script
re-walks the same two-pointer logic to find the FIRST moment count crosses
threshold, which is what "mean time to alert" actually means for a
streaming detector. Run run_pipeline.py first to produce data/siem.db.

Run: python3 benchmark_mtta.py
"""
import os
import sqlite3
from datetime import datetime, timedelta

HERE = os.path.dirname(__file__)
DB_PATH = os.path.join(HERE, "data", "siem.db")

BRUTE_FORCE_WINDOW = timedelta(minutes=5)
BRUTE_FORCE_THRESHOLD = 8
PORT_SCAN_WINDOW = timedelta(seconds=30)
PORT_SCAN_THRESHOLD = 8


def first_crossing(timestamps, window, threshold):
    """Same two-pointer algorithm as detection_rules._sliding_window_bursts,
    but returns as soon as count first reaches threshold instead of
    continuing to the widest/final window."""
    left = 0
    for right in range(len(timestamps)):
        while timestamps[right] - timestamps[left] > window:
            left += 1
        count = right - left + 1
        if count >= threshold:
            return timestamps[0], timestamps[right], count
    return None


def main():
    if not os.path.exists(DB_PATH):
        raise SystemExit("data/siem.db not found -- run `python3 run_pipeline.py` first.")

    conn = sqlite3.connect(DB_PATH)

    bf_rows = conn.execute(
        "SELECT timestamp FROM events WHERE src_ip='203.0.113.77' "
        "AND event_type='auth_failed' ORDER BY timestamp"
    ).fetchall()
    bf_ts = [datetime.fromisoformat(r[0]) for r in bf_rows]
    bf_first, bf_cross, bf_count = first_crossing(bf_ts, BRUTE_FORCE_WINDOW, BRUTE_FORCE_THRESHOLD)
    bf_mtta = (bf_cross - bf_first).total_seconds()

    ps_rows = conn.execute(
        "SELECT timestamp FROM events WHERE src_ip='198.51.100.23' "
        "AND event_type='conn_block' ORDER BY timestamp"
    ).fetchall()
    ps_ts = [datetime.fromisoformat(r[0]) for r in ps_rows]
    ps_first, ps_cross, ps_count = first_crossing(ps_ts, PORT_SCAN_WINDOW, PORT_SCAN_THRESHOLD)
    ps_mtta = (ps_cross - ps_first).total_seconds()

    print(f"Brute force (203.0.113.77): first event {bf_first.isoformat()} "
          f"-> threshold crossed (count={bf_count}) at {bf_cross.isoformat()} = {bf_mtta:.1f}s")
    print(f"Port scan (198.51.100.23): first event {ps_first.isoformat()} "
          f"-> threshold crossed (count={ps_count}) at {ps_cross.isoformat()} = {ps_mtta:.1f}s")
    print(f"\nMean time-to-threshold across both real alerts: {(bf_mtta + ps_mtta) / 2:.1f}s")
    print("\n(This is time-to-threshold for a hypothetical streaming detector, computed from")
    print(" real event timestamps -- not a live-system measurement, since this pipeline runs")
    print(" in batch mode against a completed log file, not a live event stream.)")


if __name__ == "__main__":
    main()
