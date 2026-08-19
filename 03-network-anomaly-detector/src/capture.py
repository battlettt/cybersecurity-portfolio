"""
Traffic generation for the Network Traffic Anomaly Detector.

This environment cannot do live packet capture: a quick test confirmed
`scapy.all.sniff()` raises `Permission denied: could not open /dev/bpf0`
without sudo (macOS BPF devices require root). Rather than fake numbers
out of thin air, this module uses Scapy to *construct* real packet
objects (Ether/IP/TCP/UDP/ICMP layers) so that byte sizes, header
overhead, and flag fields are all genuine values taken from
`len(bytes(pkt))`, not hand-picked constants. The packets are never put
on the wire -- only their realistic metadata is kept.

Traffic model:
  - Baseline ("normal") traffic: packet arrivals follow a Poisson
    process (the standard assumption for aggregate, memoryless network
    arrivals), destinations drawn from a small set of "usual" servers,
    a few well-known destination ports, mostly TCP with some UDP/ICMP.
  - Attack 1 - port scan: one source hammers a single target with
    small SYN packets across many sequential destination ports in a
    short burst -- the classic TCP SYN scan signature.
  - Attack 2 - data exfiltration burst: one internal host pushes a
    sustained stream of unusually large outbound TCP payloads to a
    single external destination.

Every simulated packet is labeled with its ground-truth origin
(`normal` / `port_scan` / `exfiltration`). The label is carried through
to data/raw_traffic.csv for evaluation purposes only -- src/detect.py
never reads it when making a detection decision, only when scoring
itself against ground truth at the end.
"""
import random

import numpy as np
import pandas as pd
from scapy.all import ICMP, IP, TCP, UDP

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

INTERNAL_NET = "10.0.1."
NORMAL_SERVERS = [f"93.184.{i}.10" for i in range(1, 6)]  # a handful of "usual" remote hosts
NORMAL_PORTS = [443, 443, 443, 80, 22, 53, 123]  # weighted toward HTTPS, like real traffic
INTERNAL_HOSTS = [f"{INTERNAL_NET}{i}" for i in range(10, 30)]


def _pkt_size(layer) -> int:
    """Real wire size (bytes) of a constructed Scapy packet."""
    return len(bytes(layer))


def _make_normal_packet(t: float) -> dict:
    src = random.choice(INTERNAL_HOSTS)
    dst = random.choice(NORMAL_SERVERS)
    proto_roll = random.random()
    sport = random.randint(1024, 65535)

    if proto_roll < 0.85:  # TCP dominates, like real endpoint traffic
        dport = random.choice(NORMAL_PORTS)
        flags = random.choice(["S", "A", "PA", "FA"])
        payload = b"x" * random.randint(0, 1200)
        pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / payload
        proto = "TCP"
    elif proto_roll < 0.97:  # UDP: DNS-ish
        dport = 53
        payload = b"x" * random.randint(20, 120)
        pkt = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / payload
        proto = "UDP"
        flags = ""
    else:  # a little ICMP background noise
        pkt = IP(src=src, dst=dst) / ICMP()
        proto = "ICMP"
        flags = ""
        dport = 0

    return {
        "timestamp": t,
        "src_ip": src,
        "dst_ip": dst,
        "src_port": sport,
        "dst_port": dport,
        "proto": proto,
        "tcp_flags": flags,
        "size_bytes": _pkt_size(pkt),
        "label": "normal",
    }


def generate_baseline(duration_s: int, avg_pps: float, start_t: float = 0.0) -> list:
    """Poisson-process arrivals of normal traffic over `duration_s` seconds."""
    packets = []
    t = start_t
    end_t = start_t + duration_s
    while t < end_t:
        # Poisson process => exponential inter-arrival times
        t += np.random.exponential(1.0 / avg_pps)
        if t >= end_t:
            break
        packets.append(_make_normal_packet(t))
    return packets


def generate_port_scan(start_t: float, duration_s: float, attacker_ip: str, target_ip: str) -> list:
    """Sequential-port SYN scan: many small packets, one source -> one dest, ports climbing."""
    packets = []
    t = start_t
    port = 1
    n_ports = 400  # scan sweeps far more ports than fit in the window -> spikes unique-port count
    interval = duration_s / n_ports
    for _ in range(n_ports):
        t += interval
        sport = random.randint(40000, 60000)
        pkt = IP(src=attacker_ip, dst=target_ip) / TCP(sport=sport, dport=port, flags="S")
        packets.append({
            "timestamp": t,
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "src_port": sport,
            "dst_port": port,
            "proto": "TCP",
            "tcp_flags": "S",
            "size_bytes": _pkt_size(pkt),
            "label": "port_scan",
        })
        port += 1
    return packets


def generate_exfiltration(start_t: float, duration_s: float, insider_ip: str, exfil_dst: str) -> list:
    """Sustained burst of unusually large outbound payloads to one external destination."""
    packets = []
    t = start_t
    end_t = start_t + duration_s
    while t < end_t:
        t += np.random.exponential(1.0 / 40)  # much higher rate than baseline pps
        if t >= end_t:
            break
        sport = random.randint(1024, 65535)
        payload = b"x" * random.randint(1400, 1460)  # near-MTU jumbo payloads
        pkt = IP(src=insider_ip, dst=exfil_dst) / TCP(sport=sport, dport=443, flags="PA") / payload
        packets.append({
            "timestamp": t,
            "src_ip": insider_ip,
            "dst_ip": exfil_dst,
            "src_port": sport,
            "dst_port": 443,
            "proto": "TCP",
            "tcp_flags": "PA",
            "size_bytes": _pkt_size(pkt),
            "label": "exfiltration",
        })
    return packets


def build_dataset() -> pd.DataFrame:
    packets = []

    # 0-300s: pure baseline, used later to fit the "normal" distribution
    packets += generate_baseline(duration_s=300, avg_pps=8, start_t=0)

    # 300-305s: port scan attack (attacker not among usual internal hosts' traffic pattern)
    packets += generate_port_scan(start_t=300, duration_s=5, attacker_ip="10.0.1.66", target_ip="10.0.1.15")

    # 305-330s: back to normal
    packets += generate_baseline(duration_s=25, avg_pps=8, start_t=305)

    # 330-345s: exfiltration burst
    packets += generate_exfiltration(start_t=330, duration_s=15, insider_ip="10.0.1.21", exfil_dst="198.51.100.7")

    # 345-500s: normal tail, gives a clean post-attack baseline stretch too
    packets += generate_baseline(duration_s=155, avg_pps=8, start_t=345)

    packets.sort(key=lambda p: p["timestamp"])
    return pd.DataFrame(packets)


if __name__ == "__main__":
    df = build_dataset()
    out_path = "data/raw_traffic.csv"
    df.to_csv(out_path, index=False)
    print(f"Generated {len(df)} simulated packets over {df['timestamp'].max():.1f}s -> {out_path}")
    print(df["label"].value_counts())
