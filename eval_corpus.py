#!/usr/bin/env python3
"""eval_corpus.py —— 对 50 条样本语料评测自建污点分析器。

用法（在仓库根）：
    python -I eval_corpus.py

输出召回率、精确率、误报率，并按需求阈值（召回>=85%、误报<=15%）判定。
真值标签由 corpus/genlabels 基于 go/parser 生成，存于 corpus/corpus_labels.json。
"""
import json
import os
import subprocess
import sys
import tempfile

# 统一 UTF-8 输出，避免 Windows GBK 控制台无法编码中文/符号
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

ROOT = os.path.dirname(os.path.abspath(__file__))
ANALYZER = os.path.join(ROOT, "analyzer")
CORPUS = os.path.join(ROOT, "corpus")
LABELS = os.path.join(CORPUS, "corpus_labels.json")
RULES = os.path.join(ANALYZER, "rules", "rules.json")

RECALL_MIN = 0.85
FP_MAX = 0.15
N_DECOY = 15  # 非漏洞样本数（D01..D15）


def build():
    subprocess.run(["go", "build", "./..."], cwd=ANALYZER, check=True)


def run_analyzer(out_path):
    exe = os.path.join(ANALYZER, "taint-binary" + (".exe" if os.name == "nt" else ""))
    subprocess.run(
        ["go", "run", "./main", "-target", CORPUS, "-rules", RULES,
         "-out", out_path, "-json"],
        cwd=ANALYZER, check=True,
    )


def main():
    build()
    labels = json.load(open(LABELS, encoding="utf-8"))["vulns"]
    truth = {(v["file"], v["line"]) for v in labels}

    fd, tmp = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        run_analyzer(tmp)
        got = {(f["file"], f["line"]) for f in json.load(open(tmp, encoding="utf-8"))["findings"]}
    finally:
        os.remove(tmp)

    tp = len(truth & got)
    fp = len(got - truth)
    fn = len(truth - got)
    recall = tp / len(truth) if truth else 0.0
    precision = tp / len(got) if got else 1.0
    fp_rate = fp / N_DECOY if N_DECOY else 0.0

    print(f"样本总数={len(truth) + N_DECOY} 真漏洞={len(truth)} 非漏洞={N_DECOY}")
    print(f"TP={tp} FP={fp} FN={fn}")
    print(f"召回率 recall    = {recall:.1%}  (门槛 >= {RECALL_MIN:.0%})")
    print(f"精确率 precision = {precision:.1%}")
    print(f"误报率 FP/非漏洞 = {fp_rate:.1%}  (门槛 <= {FP_MAX:.0%})")

    ok = recall >= RECALL_MIN and fp_rate <= FP_MAX
    print("结果:", "[PASS] 达标" if ok else "[FAIL] 未达标")
    if fn:
        print("漏报:")
        for f, ln in sorted(truth - got):
            print(f"  {f}:{ln}")
    if fp:
        print("误报:")
        for f, ln in sorted(got - truth):
            print(f"  {f}:{ln}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
