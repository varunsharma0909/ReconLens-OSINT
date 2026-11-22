"""Offline evaluator for a manually labelled OSINT benchmark CSV.

CSV columns: scenario_id,expected_threat,predicted_threat,response_ms
expected_threat/predicted_threat must be 1 or 0. Include only cases where
expected labels were established independently and ethically. This script
reports measured metrics; it does not fabricate test outcomes.
"""
import argparse
import csv
import statistics


def evaluate(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise SystemExit("No benchmark rows found.")
    tp = fp = tn = fn = 0
    times = []
    for row in rows:
        expected = int(row["expected_threat"])
        predicted = int(row["predicted_threat"])
        if expected not in (0, 1) or predicted not in (0, 1):
            raise SystemExit("expected_threat and predicted_threat must be 0 or 1")
        tp += expected == 1 and predicted == 1
        fp += expected == 0 and predicted == 1
        tn += expected == 0 and predicted == 0
        fn += expected == 1 and predicted == 0
        times.append(float(row["response_ms"]))
    total = len(rows)
    accuracy = (tp + tn) / total if total else 0
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    print(f"Samples: {total}")
    print(f"TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"Accuracy: {accuracy:.3f}")
    print(f"Precision: {precision:.3f}")
    print(f"Recall: {recall:.3f}")
    print(f"False-positive rate: {fpr:.3f}")
    print(f"Response time ms: median={statistics.median(times):.1f}, max={max(times):.1f}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_path", help="CSV file with labelled benchmark cases")
    evaluate(parser.parse_args().csv_path)
