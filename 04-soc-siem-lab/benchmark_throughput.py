"""
benchmark_throughput.py
------------------------
Generates a large, realistic auth.log (reusing log_generator's actual line
formatters, not synthetic placeholder text) and times siem_ingest's real
parser/ingestion path against it, to report a genuine logs/sec throughput
number instead of asserting one.

Run: python3 benchmark_throughput.py
"""
import os
import random
import time
from datetime import datetime, timedelta

import log_generator
import siem_ingest

HERE = os.path.dirname(__file__)
BENCH_LOG = os.path.join(HERE, "data", "bench_auth.log")
BENCH_DB = os.path.join(HERE, "data", "bench_siem.db")

N_LINES = 500_000


def build_large_log(n_lines: int) -> list[str]:
    random.seed(7)
    lines = []
    t = datetime(2026, 1, 1)
    for i in range(n_lines):
        t += timedelta(seconds=random.randint(1, 4))
        username, home_ip = random.choice(log_generator.EMPLOYEE_ACCOUNTS)
        host = random.choice(log_generator.HOSTS)
        port = random.randint(1024, 65535)
        if i % 37 == 0:
            lines.append(log_generator.ssh_failed_line(t, host, home_ip, username, True, port))
        else:
            lines.append(log_generator.ssh_accepted_line(t, host, home_ip, username, port))
    return lines


def main():
    print(f"Building a {N_LINES:,}-line synthetic auth.log using the real line formatters...")
    lines = build_large_log(N_LINES)
    with open(BENCH_LOG, "w") as f:
        f.write("\n".join(lines) + "\n")
    size_mb = os.path.getsize(BENCH_LOG) / (1024 * 1024)
    print(f"Wrote {BENCH_LOG} ({size_mb:.1f} MB, {N_LINES:,} lines)")

    if os.path.exists(BENCH_DB):
        os.remove(BENCH_DB)

    print("Timing siem_ingest.ingest_file() ...")
    start = time.perf_counter()
    summary = siem_ingest.ingest_file(BENCH_LOG, BENCH_DB)
    elapsed = time.perf_counter() - start

    lines_per_sec = N_LINES / elapsed
    print(f"\nParsed {summary['parsed_events']}/{summary['total_lines']} lines "
          f"({summary['unparsed_lines']} unparsed)")
    print(f"Elapsed: {elapsed:.2f}s")
    print(f"Throughput: {lines_per_sec:,.0f} logs/sec")

    os.remove(BENCH_LOG)
    os.remove(BENCH_DB)
    print("(benchmark log/db cleaned up)")


if __name__ == "__main__":
    main()
