#!/usr/bin/env python3
"""eval.py —— 拿分析器输出和 labels.json 对比。用法：python eval.py findings.sarif"""
import json, sys

def load(path):
    with open(path, encoding="utf-8-sig") as fh:
        doc = json.load(fh)
    out = []
    if "findings" in doc:
        for f in doc["findings"]:
            out.append((f.get("file"), int(f.get("line", 0))))
    else:
        for run in doc.get("runs", []):
            for res in run.get("results", []):
                loc = res["locations"][0]["physicalLocation"]
                out.append((loc["artifactLocation"]["uri"], int(loc["region"]["startLine"])))
    return out

def main():
    labels = json.load(open("labels.json", encoding="utf-8"))["vulns"]
    truth = {(v["file"], v["line"]) for v in labels}
    got = set(load(sys.argv[1]))
    tp = len(truth & got); fp = len(got - truth); fn = len(truth - got)
    recall = tp/(tp+fn) if (tp+fn) else 0
    prec = tp/(tp+fp) if (tp+fp) else 0
    print(f"labels={len(truth)} findings={len(got)} TP={tp} FP={fp} FN={fn}")
    print(f"recall={recall:.1%} precision={prec:.1%} false_positive_rate={(1-prec):.1%}")

main()
