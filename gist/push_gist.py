#!/usr/bin/env python3
"""Push local files into the mirror secret gist (content stays out of the repo)."""
import json
import os
import sys
import urllib.request


def main():
    token = os.environ["GIST_TOKEN"]
    gist_id = os.environ["MIRROR_GIST_ID"]
    files = {}
    for path in sys.argv[1:]:
        with open(path, "r", encoding="utf-8") as f:
            files[path] = {"content": f.read()}
    body = json.dumps({"files": files}).encode("utf-8")
    req = urllib.request.Request(
        "https://api.github.com/gists/" + gist_id,
        data=body,
        method="PATCH",
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "gist-mirror",
        },
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        print("gist update status:", r.status)
    print("pushed:", ", ".join(files))


if __name__ == "__main__":
    main()
