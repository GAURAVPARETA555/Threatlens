"""Generate a synthetic telemetry dataset for ThreatLens.

WHY SYNTHETIC: no public dataset has exactly the three features the backend
sends (request_rate, failed_logins, special_characters). This generator encodes
domain assumptions (brute force -> many failed logins, injection -> many special
chars, DoS -> huge request rate) PLUS deliberately hard benign cases and label
noise so classes overlap. Replace with real labelled logs when available; the
rest of the pipeline (train.py / serve.py) does not change.
"""
import numpy as np
import pandas as pd

RNG_SEED = 42
FEATURES = ["request_rate", "failed_logins", "special_characters"]


def generate(n=20_000, seed=RNG_SEED, malicious_frac=0.35, label_noise=0.03):
    rng = np.random.default_rng(seed)
    n_mal = int(n * malicious_frac)
    n_ben = n - n_mal

    # ---- benign: normal users + hard look-alikes -------------------------
    kind = rng.choice(["normal", "bursty", "typo_pw", "code_paste"],
                      size=n_ben, p=[0.70, 0.10, 0.10, 0.10])
    rate = rng.lognormal(2.4, 0.6, n_ben)                 # median ~11 req/s
    fails = rng.poisson(0.4, n_ben)
    spec = rng.poisson(1.5, n_ben)
    rate = np.where(kind == "bursty", rng.lognormal(4.0, 0.5, n_ben), rate)   # median ~55
    fails = np.where(kind == "typo_pw", rng.integers(2, 7, n_ben), fails)
    spec = np.where(kind == "code_paste", rng.poisson(8, n_ben), spec)
    benign = pd.DataFrame({"request_rate": rate, "failed_logins": fails,
                           "special_characters": spec, "attack_family": "benign",
                           "label": 0})

    # ---- malicious families ---------------------------------------------
    fam = rng.choice(["brute_force", "injection", "dos", "mixed_scan"],
                     size=n_mal, p=[0.30, 0.30, 0.20, 0.20])
    rate = rng.lognormal(3.0, 0.6, n_mal)
    fails = rng.poisson(1.0, n_mal)
    spec = rng.poisson(2.0, n_mal)
    rate = np.where(fam == "brute_force", rng.lognormal(3.6, 0.5, n_mal), rate)
    fails = np.where(fam == "brute_force", rng.poisson(13, n_mal), fails)
    spec = np.where(fam == "injection", rng.poisson(11, n_mal), spec)
    rate = np.where(fam == "injection", rng.lognormal(3.2, 0.5, n_mal), rate)
    rate = np.where(fam == "dos", rng.lognormal(5.2, 0.5, n_mal), rate)      # median ~180
    fails = np.where(fam == "mixed_scan", rng.poisson(4, n_mal), fails)
    spec = np.where(fam == "mixed_scan", rng.poisson(5, n_mal), spec)
    rate = np.where(fam == "mixed_scan", rng.lognormal(3.8, 0.5, n_mal), rate)
    mal = pd.DataFrame({"request_rate": rate, "failed_logins": fails,
                        "special_characters": spec, "attack_family": fam,
                        "label": 1})

    df = pd.concat([benign, mal], ignore_index=True).sample(frac=1, random_state=seed)
    df["request_rate"] = df["request_rate"].round(2)

    # label noise: analysts mislabel / unknown attacks slip through
    flip = rng.random(len(df)) < label_noise
    df.loc[flip, "label"] = 1 - df.loc[flip, "label"]
    return df.reset_index(drop=True)


if __name__ == "__main__":
    df = generate()
    df.to_csv("ml/data/telemetry.csv", index=False)
    print(df.label.value_counts(normalize=True).round(3).to_dict(), len(df))
