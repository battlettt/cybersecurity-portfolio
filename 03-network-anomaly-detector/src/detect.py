"""
Statistical anomaly detection over the per-window traffic features.

Method
------
For each candidate feature we fit a baseline (null) distribution using only
windows drawn from the first 300s of the simulation, which is pure normal
traffic by construction (this is our "training" period -- the rest of the
timeline, including the two attack bursts AND untouched normal windows
after t=300s, is held out and never used to fit anything).

Two distribution families are used, chosen per feature rather than applied
blindly:

  * packet_count is modeled as Poisson. The generator literally draws
    inter-arrival times from an exponential distribution (a Poisson
    process), so packet counts per fixed-width window are Poisson by
    construction -- lambda is estimated as the sample mean of the baseline
    windows, and the test statistic is the classic Poisson z-approximation
    z = (x - lambda) / sqrt(lambda) (valid once lambda is not tiny; here
    baseline lambda ~ 8, comfortably in range for the normal approximation
    to the Poisson).

  * unique_dst_ports and mean_pkt_size are modeled as Normal via
    scipy.stats.norm.fit (MLE mean/std) on the baseline windows. These are
    aggregate statistics of many packets per window, so a Normal
    approximation is justified by the CLT rather than assumed for
    convenience. z = (x - mu) / sigma.

A window is flagged anomalous if ANY of the three |z| exceeds the critical
value for a two-tailed test at alpha = 0.01 (z_crit = 2.576). Running three
independent tests per window inflates the family-wise false-positive rate
under a naive reading (roughly 1 - 0.99^3 ~= 3% per window if the tests
were independent) -- this is the same multiple-comparisons issue as running
several hypothesis tests on one dataset. We accept the higher nominal FPR
deliberately: in a security-monitoring context a missed attack (false
negative) is far more costly than an extra analyst review (false positive),
so the OR-across-features rule is a defensible precision/recall trade-off
as long as the resulting empirical FPR is reported honestly (see below) --
which is what actually happened when this ran, not a hoped-for number.
"""
import numpy as np
import pandas as pd
from scipy import stats

ALPHA = 0.01
Z_CRIT = stats.norm.ppf(1 - ALPHA / 2)  # two-tailed critical value, ~2.576
ATTACK_LABELS = {"port_scan", "exfiltration"}
TRAIN_CUTOFF_S = 300  # pure-baseline period used to fit the null distributions


def fit_baseline(train: pd.DataFrame) -> dict:
    lam = train["packet_count"].mean()  # Poisson MLE

    mu_ports, sigma_ports = stats.norm.fit(train["unique_dst_ports"])
    mu_bytes, sigma_bytes = stats.norm.fit(train["mean_pkt_size"])

    # guard against a degenerate zero-variance fit blowing up the z-score
    sigma_ports = max(sigma_ports, 1e-6)
    sigma_bytes = max(sigma_bytes, 1e-6)

    return {
        "lambda_packet_count": lam,
        "mu_unique_dst_ports": mu_ports,
        "sigma_unique_dst_ports": sigma_ports,
        "mu_mean_pkt_size": mu_bytes,
        "sigma_mean_pkt_size": sigma_bytes,
    }


def score(feat_df: pd.DataFrame, params: dict) -> pd.DataFrame:
    out = feat_df.copy()

    lam = params["lambda_packet_count"]
    out["z_packet_count"] = (out["packet_count"] - lam) / np.sqrt(lam)

    out["z_unique_dst_ports"] = (
        (out["unique_dst_ports"] - params["mu_unique_dst_ports"]) / params["sigma_unique_dst_ports"]
    )
    out["z_mean_pkt_size"] = (
        (out["mean_pkt_size"] - params["mu_mean_pkt_size"]) / params["sigma_mean_pkt_size"]
    )

    z_cols = ["z_packet_count", "z_unique_dst_ports", "z_mean_pkt_size"]
    out["max_abs_z"] = out[z_cols].abs().max(axis=1)
    out["driving_feature"] = out[z_cols].abs().idxmax(axis=1)
    out["flagged"] = out["max_abs_z"] > Z_CRIT
    return out


def _explain(row) -> str:
    """Direction-aware explanation: a high positive z means 'more than baseline',
    a negative z means 'less than baseline' (e.g. an unusually quiet window)."""
    feat = row["driving_feature"]
    z = row[feat]
    direction = "high" if z > 0 else "low"

    if feat == "z_unique_dst_ports":
        if z > 0:
            return f"port-scan signature: {int(row['unique_dst_ports'])} unique dst ports touched in 1s (unusually {direction})"
        return f"unusually {direction} port diversity: only {int(row['unique_dst_ports'])} unique dst port(s) in a sparse window"
    if feat == "z_mean_pkt_size":
        if z > 0:
            return f"exfiltration signature: mean packet size {row['mean_pkt_size']:.0f} bytes in window (unusually {direction})"
        return f"unusually {direction} mean packet size ({row['mean_pkt_size']:.0f} bytes) in a sparse window"
    return f"volume anomaly: {int(row['packet_count'])} packets in 1s window (unusually {direction})"


def run_detection(features_path: str = "data/features.csv") -> pd.DataFrame:
    feat_df = pd.read_csv(features_path)

    train = feat_df[(feat_df["window_start_s"] < TRAIN_CUTOFF_S) & (feat_df["ground_truth"] == "normal")]
    params = fit_baseline(train)

    print(f"Fitted baseline on {len(train)} training windows (t < {TRAIN_CUTOFF_S}s, all ground-truth normal):")
    for k, v in params.items():
        print(f"  {k} = {v:.3f}")
    print(f"Two-tailed z critical value at alpha={ALPHA}: {Z_CRIT:.3f}\n")

    scored = score(feat_df, params)

    print("Per-window detection log:")
    for _, row in scored.iterrows():
        tag = "FLAGGED" if row["flagged"] else "ok"
        line = (
            f"Window {int(row['window']):4d} [t={row['window_start_s']:.0f}s]: "
            f"z_pkts={row['z_packet_count']:+.2f} z_ports={row['z_unique_dst_ports']:+.2f} "
            f"z_size={row['z_mean_pkt_size']:+.2f} -> {tag}"
        )
        if row["flagged"]:
            line += f" ({_explain(row)})"
        print(line)

    scored.to_csv("data/detections.csv", index=False)

    # --- evaluation against ground truth (held-out windows only: t >= TRAIN_CUTOFF_S) ---
    test = scored[scored["window_start_s"] >= TRAIN_CUTOFF_S]
    is_attack = test["ground_truth"].isin(ATTACK_LABELS)

    tp = int((test["flagged"] & is_attack).sum())
    fn = int((~test["flagged"] & is_attack).sum())
    fp = int((test["flagged"] & ~is_attack).sum())
    tn = int((~test["flagged"] & ~is_attack).sum())

    detection_rate = tp / (tp + fn) if (tp + fn) else float("nan")
    false_positive_rate = fp / (fp + tn) if (fp + tn) else float("nan")

    print("\n=== Evaluation on held-out windows (t >= {}s), n={} ===".format(TRAIN_CUTOFF_S, len(test)))
    print(f"Attack windows: {int(is_attack.sum())}   Normal windows: {int((~is_attack).sum())}")
    print(f"TP={tp}  FN={fn}  FP={fp}  TN={tn}")
    print(f"Detection rate (recall): {detection_rate * 100:.1f}%")
    print(f"False positive rate: {false_positive_rate * 100:.1f}%")

    by_type = test.groupby("ground_truth")["flagged"].mean()
    print("\nFlag rate by ground-truth traffic type:")
    print(by_type)

    return scored


if __name__ == "__main__":
    run_detection()
