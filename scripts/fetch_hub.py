#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 hub.ccwork.nyc.mn 首页提取当日动态 token，拼出订阅链接并写入 config.yaml 的 subscribe 列表。

仅使用 Python 标准库（urllib），无第三方依赖。
由 GitHub Actions 工作流在运行 main.py 之前调用。
"""
import base64
import os
import re
import sys
import urllib.request

HUB_HOME = "https://hub.ccwork.nyc.mn/"
HUB_SUB_PREFIX = "https://hub.ccwork.nyc.mn/share_sub?token="
HUB_HOST_MARK = "hub.ccwork.nyc.mn/share_sub"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config.yaml")


def http_get_text(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


def extract_token(html):
    """token 由服务端按天轮换，随首页 HTML 下发，直接用正则提取。"""
    m = re.search(r"share_sub\?token=([0-9a-fA-F]+)", html)
    if m:
        return m.group(1)
    # 兜底：在 JS 变量中查找 token
    m = re.search(r"""["']token["']\s*[:=]\s*["']([0-9a-fA-F]{8,})["']""", html)
    if m:
        return m.group(1)
    return None


def validate_subscription(url, timeout=30):
    """校验拼出的订阅链接确实返回 base64 编码的节点内容。"""
    body = http_get_text(url, timeout=timeout)
    blob = "".join(body.split())
    if len(blob) < 128:
        raise ValueError("订阅内容过短（%d 字符），疑似无效" % len(blob))
    padded = blob + "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
    except Exception as exc:
        raise ValueError("订阅内容不是合法的 base64：%s" % exc)
    if b"://" not in raw:
        raise ValueError("解码后内容不包含节点链接")
    return raw


def update_config_subscribe(config_path, url):
    """在 config.yaml 的 subscribe 列表中删掉旧的 hub 行，追加新的 hub 订阅链接。"""
    with open(config_path, "r", encoding="utf-8") as f:
        text = f.read()

    lines = text.split("\n")
    out = []
    i = 0
    found = False
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^(\s*)subscribe:\s*(\[\s*\])?\s*(#.*)?$", line)
        if m and not found:
            found = True
            indent = m.group(1)
            comment = (" " + m.group(3)) if m.group(3) else ""
            out.append("%ssubscribe:%s" % (indent, comment))
            item_indent = indent + "  "
            i += 1
            # 消费旧的列表内容：删掉 hub 旧行，其它行原样保留
            while i < len(lines):
                nxt = lines[i]
                if re.match(r"^[A-Za-z_][\w\-]*\s*:", nxt):
                    break
                if HUB_HOST_MARK not in nxt:
                    out.append(nxt)
                i += 1
            out.append("%s- %s" % (item_indent, url))
            continue
        out.append(line)
        i += 1

    if not found:
        raise RuntimeError("config.yaml 中未找到顶层 subscribe: 键")

    with open(config_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out))


def main():
    try:
        html = http_get_text(HUB_HOME)
    except Exception as exc:
        print("错误：获取 hub 首页失败：%s" % exc, file=sys.stderr)
        return 1

    token = extract_token(html)
    if not token:
        print("错误：未能从 hub 首页提取到 share_sub token", file=sys.stderr)
        return 1

    url = HUB_SUB_PREFIX + token
    try:
        validate_subscription(url)
    except Exception as exc:
        print("错误：订阅链接校验失败（%s）：%s" % (url, exc), file=sys.stderr)
        return 1

    try:
        update_config_subscribe(CONFIG_PATH, url)
    except Exception as exc:
        print("错误：写入 config.yaml 失败：%s" % exc, file=sys.stderr)
        return 1

    print("hub 订阅链接：%s" % url)
    print("已写入 config.yaml 的 subscribe 列表")
    return 0


if __name__ == "__main__":
    sys.exit(main())
