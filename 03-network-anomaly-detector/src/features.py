"""
Feature extraction: bins raw per-packet traffic (data/raw_traffic.csv) into
fixed-width time windows and computes a per-window feature vector suitable
for statistical anomaly detection.

Window size is 1 second. At an average baseline rate of ~8 packets/sec this
gives a reasonable sample size per window while still being fine-grained
enough to isolate short bursts like a 5-second port scan.
"""
import numpy as np
import pandas as pd

WINDOW_S = 1.0


def extract_features(raw_path: str = "data/raw_traffic.csv") -> pd.DataFrame:
    df = pd.read_csv(raw_path)
    df["window"] = (df["timestamp"] // WINDOW_S).astype(int)

    rows = []
    for window, g in df.groupby("window"):
        n = len(g)
        proto_counts = g["proto"].value_counts(normalize=True)
        syn_count = (g["tcp_flags"].fillna("").str.contains("S")).sum()
        # ground-truth label for this window: majority packet label (evaluation only)
        majority_label = g["label"].mode().iloc[0]

        rows.append({
            "window": window,
            "window_start_s": window * WINDOW_S,
            "packet_count": n,
            "mean_pkt_size": g["size_bytes"].mean(),
            "var_pkt_size": g["size_bytes"].var(ddof=0) if n > 1 else 0.0,
            "total_bytes": g["size_bytes"].sum(),
            "unique_dst_ports": g["dst_port"].nunique(),
            "unique_src_dst_pairs": g[["src_ip", "dst_ip"]].drop_duplicates().shape[0],
            "tcp_ratio": proto_counts.get("TCP", 0.0),
            "udp_ratio": proto_counts.get("UDP", 0.0),
            "icmp_ratio": proto_counts.get("ICMP", 0.0),
            "syn_ratio": syn_count / n if n else 0.0,
            "ground_truth": majority_label,
        })

    feat_df = pd.DataFrame(rows).sort_values("window").reset_index(drop=True)
    return feat_df


if __name__ == "__main__":
    feat_df = extract_features()
    out_path = "data/features.csv"
    feat_df.to_csv(out_path, index=False)
    print(f"Extracted {len(feat_df)} {WINDOW_S:.0f}s windows -> {out_path}")
    print(feat_df["ground_truth"].value_counts())
    print(feat_df[["window", "packet_count", "unique_dst_ports", "mean_pkt_size", "ground_truth"]].describe(include="all"))
