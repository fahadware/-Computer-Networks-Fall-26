#!/usr/bin/env python3
#23P-0569..........

#this is Task 4 which  run GBN and SR on scenarios A, B, C (200 packets, N=4, k=3, seed=569)
# and  it will  producee results_table.md, results.csv and gbn_vs_sr.png by using python libraries.

import csv     
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from rdt import simulate

SEED = 569          # last four digits of roll number 0569
PACKETS, N, K = 200, 4, 3
SCENARIOS = {
    "A: Reliable":    dict(loss=0.0,  corrupt=0.0,  delay=0.0),
    "B: Loss 0.10":   dict(loss=0.10, corrupt=0.0,  delay=0.0),
    "C: Mixed errors": dict(loss=0.05, corrupt=0.05, delay=0.10),
}

rows = []
for name, errs in SCENARIOS.items():
    for proto in ("gbn", "sr"):
        st = simulate(protocol=proto, packets=PACKETS, window=N, k=K, seed=SEED, quiet=True, **errs)
        secs = st["end_time"] / 1000
        rows.append({
            "Scenario": name,
            "Protocol": proto.upper(),
            "Transmitted": st["data_sent"],
            "Retransmissions": st["retransmissions"],
            "Delivered": f'{st["delivered_correct"]}/{PACKETS}',
            "Time (s)": round(secs, 2),
            "Throughput (kbps)": round(st["delivered_correct"] * 1000 * 8 / secs / 1000, 2),
        })

#table markdown + csv.......... 
cols = list(rows[0].keys())
md = "| " + " | ".join(cols) + " |\n|" + "---|" * len(cols) + "\n"
for r in rows:
    md += "| " + " | ".join(str(r[c]) for c in cols) + " |\n"
open("results_table.md", "w").write(md)
with open("results.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    w.writerows(rows)
print(md)

# graph:3 panels in one figure 
scen = list(SCENARIOS.keys())
def vals(proto, col):
    return [r[col] for r in rows if r["Protocol"] == proto]

panels = [("Packets transmitted", "Transmitted", "packets"),
          ("Retransmissions", "Retransmissions", "packets"),
          ("Execution time", "Time (s)", "seconds")]
fig, axes = plt.subplots(1, 3, figsize=(13, 4))
x = range(len(scen))
w = 0.38
for ax, (title, col, unit) in zip(axes, panels):
    g, s = vals("GBN", col), vals("SR", col)
    b1 = ax.bar([i - w / 2 for i in x], g, w, label="GBN", color="#d9534f")
    b2 = ax.bar([i + w / 2 for i in x], s, w, label="SR", color="#337ab7")
    for b in list(b1) + list(b2):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height(), f"{b.get_height():g}",
                ha="center", va="bottom", fontsize=8)
    ax.set_xticks(list(x))
    ax.set_xticklabels([s_.split(":")[0] + "\n" + s_.split(": ")[1] for s_ in scen], fontsize=8)
    ax.set_ylabel(unit)
    ax.set_title(title)
    ax.legend()
fig.suptitle(f"GBN vs SR  (200 packets, N={N}, k={K}, seed={SEED})")
fig.tight_layout()
fig.savefig("gbn_vs_sr.png", dpi=150)
print("saved results_table.md, results.csv, gbn_vs_sr.png in current directory.....")
