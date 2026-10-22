#!/usr/bin/env python3
"""Fetch the latest ZYFXS daily node files from his GitHub repo and mirror
them to this repo root as zy-clash.yaml / zy-v2ray.txt (fixed URLs)."""
import json
import re
import sys
import urllib.parse
import urllib.request

SRC = "ZYFXS/ZYFXS001"
UA = {"User-Agent": "zy-mirror"}


def get_json(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode("utf-8"))


def get_bytes(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def last_commit_date(name):
    url = ("https://api.github.com/repos/" + SRC +
           "/commits?path=" + urllib.parse.quote(name) + "&per_page=1")
    commits = get_json(url)
    if not commits:
        return ""
    return commits[0]["commit"]["committer"]["date"]


def main():
    items = get_json("https://api.github.com/repos/" + SRC + "/contents/")
    names = [it["name"] for it in items if it.get("type") == "file"]
    clash_cands = [n for n in names
                   if "youtube@ZYFXS" in n and re.search(r"[Cc]", n)
                   and re.search(r"\d", n) and "V" not in n.replace("youtube", "")]
    # Clash files contain a C (upper or lower) and no standalone V marker;
    # V2Ray files contain a V. Classify by which letter appears in the name.
    def has_letter(n, letter):
        return letter in n or letter.lower() in n

    clash = []
    v2ray = []
    for n in names:
        if "youtube@ZYFXS" not in n:
            continue
        if has_letter(n, "C") and not has_letter(n, "V"):
            clash.append(n)
        elif has_letter(n, "V") and not has_letter(n, "C"):
            v2ray.append(n)
    print("clash candidates:", clash)
    print("v2ray candidates:", v2ray)

    def pick_newest(cands):
        best, best_date = None, ""
        for n in cands:
            d = last_commit_date(n)
            print("  ", n, "last commit:", d)
            if d > best_date:
                best, best_date = n, d
        return best

    jobs = []
    c = pick_newest(clash)
    if c:
        jobs.append((c, "zy-clash.yaml"))
    v = pick_newest(v2ray)
    if v:
        jobs.append((v, "zy-v2ray.txt"))
    if not jobs:
        print("ERROR: no source files found", file=sys.stderr)
        sys.exit(1)

    for src_name, out_name in jobs:
        url = ("https://raw.githubusercontent.com/" + SRC +
               "/refs/heads/main/" + urllib.parse.quote(src_name))
        data = get_bytes(url)
        if len(data) < 1000:
            print("ERROR: suspiciously small download for", src_name,
                  file=sys.stderr)
            sys.exit(1)
        with open(out_name, "wb") as f:
            f.write(data)
        print("wrote", out_name, len(data), "bytes from", src_name)


if __name__ == "__main__":
    main()
