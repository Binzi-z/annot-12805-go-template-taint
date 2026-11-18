#!/usr/bin/env python3
"""baseline：凡是出现 exec.Command / db.Query / os.Open / http.Get 就报。召回高、误报极高。"""
import json, os, re, sys

SINK_RE = re.compile(r"(runCmd\(|queryStr\(|readFile\(|fetch\()")

def main():
    findings = []
    for dirpath, _, names in os.walk("pkg/handlers"):
        for n in names:
            if not n.endswith(".go"):
                continue
            p = os.path.join(dirpath, n).replace("\\", "/")
            for i, line in enumerate(open(p, encoding="utf-8"), 1):
                if SINK_RE.search(line):
                    findings.append({"file": p, "line": i})
    json.dump({"findings": findings}, sys.stdout, indent=1)

main()
