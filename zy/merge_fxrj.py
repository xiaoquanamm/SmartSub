#!/usr/bin/env python3
"""Merge FXRJ (分享日记) nodes into the ZYFXS subscription files.

Reads zy-clash.yaml / zy-v2ray.txt (just produced by zy/update_zy.py),
fetches the latest FXRJ files from upstream (2OTT/Free-Nodes), and merges:
- Clash: FXRJ proxies appended to `proxies` (deduped by server+port),
  and their names appended to the 7 proxy-groups that list individual
  proxies (🚀 节点选择, ♻️ 自动选择, 🌍 国外媒体, 📲 电报信息,
  Ⓜ️ 微软服务, 🍎 苹果服务, 🐟 漏网之鱼). ZYFXS groups, rules,
  rule-providers and DNS stay untouched.
- V2Ray: FXRJ links appended to the base64 subscription (deduped).

If the FXRJ fetch fails, the ZYFXS-only files are left untouched and the
script exits 0, so the mirror still publishes the fresh ZYFXS batch.
"""
import base64
import sys
import urllib.request

import yaml

FXRJ_CLASH_URL = ("https://raw.githubusercontent.com/2OTT/Free-Nodes/"
                  "refs/heads/main/Nodes/fxrj.yaml")
FXRJ_V2RAY_URL = ("https://raw.githubusercontent.com/2OTT/Free-Nodes/"
                  "refs/heads/main/Nodes/fxrj.txt")
UA = {"User-Agent": "zy-fxrj-merge"}

# Groups that list individual proxy names; FXRJ names go in all of them.
MERGE_GROUPS = {"🚀 节点选择", "♻️ 自动选择", "🌍 国外媒体", "📲 电报信息",
                "Ⓜ️ 微软服务", "🍎 苹果服务", "🐟 漏网之鱼"}


def get_bytes(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def merge_clash():
    with open("zy-clash.yaml", encoding="utf-8") as f:
        zy = yaml.safe_load(f)
    fxrj = yaml.safe_load(get_bytes(FXRJ_CLASH_URL).decode("utf-8"))
    zy_proxies = zy.get("proxies", [])
    seen = {(p.get("server"), p.get("port"), p.get("type"))
            for p in zy_proxies}
    added = []
    for p in fxrj.get("proxies", []):
        key = (p.get("server"), p.get("port"), p.get("type"))
        if key in seen:
            continue
        seen.add(key)
        zy_proxies.append(p)
        added.append(p["name"])
    zy["proxies"] = zy_proxies
    for g in zy.get("proxy-groups", []):
        if g.get("name") in MERGE_GROUPS:
            g.setdefault("proxies", [])
            for name in added:
                if name not in g["proxies"]:
                    g["proxies"].append(name)
    with open("zy-clash.yaml", "w", encoding="utf-8") as f:
        yaml.safe_dump(zy, f, allow_unicode=True, sort_keys=False)
    print(f"clash: ZYFXS {len(zy_proxies) - len(added)} + FXRJ {len(added)} "
          f"= {len(zy_proxies)} proxies")


def merge_v2ray():
    with open("zy-v2ray.txt", encoding="utf-8") as f:
        raw = f.read().strip()
    zy_links = base64.b64decode(raw).decode("utf-8").splitlines()
    zy_links = [l.strip() for l in zy_links if l.strip()]
    fxrj_links = [l.strip() for l in
                  get_bytes(FXRJ_V2RAY_URL).decode("utf-8").splitlines()
                  if l.strip()]
    seen = set(zy_links)
    added = [l for l in fxrj_links if l not in seen]
    merged = zy_links + added
    with open("zy-v2ray.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(merged).encode("utf-8"))
                .decode("ascii"))
    print(f"v2ray: ZYFXS {len(zy_links)} + FXRJ {len(added)} "
          f"= {len(merged)} links")


def main():
    try:
        merge_clash()
    except Exception as e:
        print(f"WARNING: FXRJ clash merge failed ({e}); "
              "keeping ZYFXS-only zy-clash.yaml", file=sys.stderr)
    try:
        merge_v2ray()
    except Exception as e:
        print(f"WARNING: FXRJ v2ray merge failed ({e}); "
              "keeping ZYFXS-only zy-v2ray.txt", file=sys.stderr)


if __name__ == "__main__":
    main()
