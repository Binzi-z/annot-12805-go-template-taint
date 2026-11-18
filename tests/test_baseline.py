"""骨架测试：baseline 召回要够，误报不用管（待改进点）。"""
import json, subprocess, sys

def test_labels_exist():
    assert json.load(open("labels.json", encoding="utf-8"))["total"] > 0

def test_baseline_recall_is_high():
    out = subprocess.run([sys.executable, "baseline/scan.py"], capture_output=True, text=True, check=True)
    got = {(f["file"], f["line"]) for f in json.loads(out.stdout)["findings"]}
    truth = {(v["file"], v["line"]) for v in json.load(open("labels.json", encoding="utf-8"))["vulns"]}
    assert len(truth & got) >= len(truth) * 0.9

def test_baseline_has_false_positives():
    out = subprocess.run([sys.executable, "baseline/scan.py"], capture_output=True, text=True, check=True)
    got = {(f["file"], f["line"]) for f in json.loads(out.stdout)["findings"]}
    truth = {(v["file"], v["line"]) for v in json.load(open("labels.json", encoding="utf-8"))["vulns"]}
    assert len(got - truth) > 0
