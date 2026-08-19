"""
Visualization: packet volume and unique-destination-ports over time, with
ground-truth attack windows shaded and detector-flagged windows marked.
Saves results/detection_plot.png.
"""
import matplotlib.pyplot as plt
import pandas as pd

ATTACK_LABELS = {"port_scan", "exfiltration"}


def plot_detections(detections_path: str = "data/detections.csv", out_path: str = "results/detection_plot.png"):
    df = pd.read_csv(detections_path)

    fig, axes = plt.subplots(2, 1, figsize=(13, 7), sharex=True)

    # shade ground-truth attack regions on both subplots
    def shade_attacks(ax):
        attack = df["ground_truth"].isin(ATTACK_LABELS)
        in_run = False
        run_start = None
        for i, row in df.iterrows():
            if attack[i] and not in_run:
                in_run = True
                run_start = row["window_start_s"]
            elif not attack[i] and in_run:
                in_run = False
                ax.axvspan(run_start, row["window_start_s"], color="red", alpha=0.12,
                           label="_nolegend_")
        if in_run:
            ax.axvspan(run_start, df["window_start_s"].max() + 1, color="red", alpha=0.12)

    # --- top: packet count ---
    ax = axes[0]
    shade_attacks(ax)
    ax.plot(df["window_start_s"], df["packet_count"], color="steelblue", lw=1, label="packet_count")
    flagged = df[df["flagged"]]
    ax.scatter(flagged["window_start_s"], flagged["packet_count"], color="darkred", s=18,
               zorder=5, label="flagged window")
    ax.set_ylabel("packets / 1s window")
    ax.set_title("Network Traffic Volume with Statistical Anomaly Flags")
    ax.legend(loc="upper right")

    # --- bottom: unique destination ports (port-scan signature) ---
    ax2 = axes[1]
    shade_attacks(ax2)
    ax2.plot(df["window_start_s"], df["unique_dst_ports"], color="seagreen", lw=1, label="unique_dst_ports")
    ax2.scatter(flagged["window_start_s"], flagged["unique_dst_ports"], color="darkred", s=18,
                zorder=5, label="flagged window")
    ax2.set_ylabel("unique dst ports / window")
    ax2.set_xlabel("time (s)")
    ax2.legend(loc="upper right")

    fig.suptitle("Red shading = ground-truth attack period  |  Red dots = flagged by z-score test (p<0.01)",
                 fontsize=9, y=0.995)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    print(f"Saved plot -> {out_path}")


if __name__ == "__main__":
    plot_detections()
