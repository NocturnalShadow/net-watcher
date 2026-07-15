import os
import sys

import numpy as np
import pandas as pd

src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src'))
if src_path not in sys.path:
    sys.path.append(src_path)

from flow_features import *


def prepare_data(flows_path):
    # Read data
    benign_df = pd.read_parquet(f'{flows_path}/benign')
    malicious_df = pd.read_parquet(f'{flows_path}/malicious')

    # Label the data
    benign_df['label'] = 0  # BENIGN
    malicious_df['label'] = 1  # MALICIOUS

    # Combine datasets
    combined_df = pd.concat([benign_df, malicious_df], ignore_index=True)

    # Filter out flows where packets_count is less than 3
    combined_df = combined_df[combined_df['packets_count'] >= 3]

    # Separate features and labels
    labels = combined_df['label'].values
    features_df = combined_df.drop(['label'], axis=1)

    # Convert DataFrame to numpy array using flows_df_to_np
    features, metas = flows_df_to_np(features_df)

    return features, labels, metas


def evaluate_at_fpr(models, scaler, eval_root, target_fpr=0.003):
    # Finds the minimum classification threshold where FPR <= target_fpr,
    # then reports per-class recall at that threshold for each (model, label).
    benign_df = pd.read_parquet(f'{eval_root}/benign')
    benign_df = benign_df[benign_df['packets_count'] >= 3]
    benign_features, _ = flows_df_to_np(benign_df)
    benign_scaled = scaler.transform(benign_features)

    mal_classes = sorted([
        d for d in os.listdir(f'{eval_root}/malicious')
        if os.path.isdir(os.path.join(eval_root, 'malicious', d))
    ])

    for model, label in models:
        benign_probs = model.predict(benign_scaled, verbose=0).flatten()

        # Minimum threshold where FPR <= target_fpr
        candidates = np.sort(np.unique(benign_probs))
        threshold = 1.0
        for t in candidates:
            if np.mean(benign_probs >= t) <= target_fpr:
                threshold = t
                break

        actual_fpr = np.mean(benign_probs >= threshold)

        total_alerts, total_flows = 0, 0
        rows = []
        for cls in mal_classes:
            cls_df = pd.read_parquet(f'{eval_root}/malicious/{cls}')
            cls_df = cls_df[cls_df['packets_count'] >= 3]
            cls_features, _ = flows_df_to_np(cls_df)
            cls_scaled = scaler.transform(cls_features)
            cls_probs = model.predict(cls_scaled, verbose=0).flatten()
            cls_alerts = int(np.sum(cls_probs >= threshold))
            cls_total = len(cls_probs)
            rows.append((cls, cls_alerts, cls_total))
            total_alerts += cls_alerts
            total_flows += cls_total

        print(f"\n{'='*56}")
        print(f"  {label}  threshold={threshold:.4f}  FPR={actual_fpr*100:.3f}%  (n_benign={len(benign_scaled)})")
        print(f"{'='*56}")
        for cls, alerts, total in rows:
            recall = alerts / total if total else 0.0
            print(f"  {cls:<22} {recall:.4f}  ({alerts}/{total})")
        overall = total_alerts / total_flows if total_flows else 0.0
        print(f"  {'─'*52}")
        print(f"  {'Overall':<22} {overall:.4f}  ({total_alerts}/{total_flows})")
        print(f"{'='*56}")
