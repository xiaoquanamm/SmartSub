#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 hub.ccwork.nyc.mn 获取当日动态 token，拼出订阅链接并写入 config.yaml 的 subscribe 列表。

仅使用 Python 标准库（urllib），无第三方依赖。
由 GitHub Actions 工作流在运行 main.py 之前调用。

token 获取策略：
  首页的静态 HTML 里通常只含过期/示例 token，真正有效的当日 token 由页面
  JS 在点击后填入（可能藏在 JS 变量里，变量名不一定叫 token）。因此脚本
  按优先级收集所有 hex 候选并逐个校验：
    1. share_sub?token=... 显式链接中的 token；
    2. JS 中形如 "token": "..."（大小写不敏感）的定义；
    3. 页面中所有裸露的 16 位 hex 字符串（当日有效 token 为 16 位）；
    4. 页面中所有裸露的 32 位 hex 字符串（兜底）。
  逐个用 share_sub 接口校验（有效 token 返回 Base64 节点内容，无效返回
  HTTP 403/过期提示），第一个校验通过的即写入 config。
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

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "config.yaml")


def http_get_text(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


def extract_candidates(html):
    """按优先级收集 token 候选（去重，保持优先级顺序）。"""
    candidates = []

    def add(tok):
        if tok and tok not in candidates:
            candidates.append(tok)

    # 1. 显式 share_sub?token= 链接
    for m in re.finditer(r"share_sub\?token=([0-9a-fA-F]{8,128})", html):
        add(m.group(1))
    # 2. JS 中 "token": "..." 定义（大小写不敏感）
    for m in re.finditer(
            r'["\']token["\']\s*[:=]\s*["\']([0-9a-fA-F]{8,128})["\']',
            html, re.IGNORECASE):
        add(m.group(1))
    # 3. 裸露的 16 位 hex（当日有效 token 格式）
    for m in re.finditer(r"\b[0-9a-fA-F]{16}\b", html):
        add(m.group(0))
    # 4. 裸露的 32 位 hex（兜底）
    for m in re.finditer(r"\b[0-9a-fA-F]{32}\b", html):
        add(m.group(0))
    return candidates


def validate_subscription(url, timeout=30):
    """校验订阅链接是否有效。

    有效的 share_sub 链接返回 Base64 编码的节点内容（去空白后长度 >= 128、
    可 Base64 解码、解码结果含 "://"）；过期的 token 则返回 HTTP 403
    （页面提示「链接已过期」）。
    """
    text = http_get_text(url, timeout=timeout)
    compact = re.sub(r"\s+", "", text)
    if len(compact) < 128:
        raise ValueError("订阅内容过短（%d 字符）" % len(compact))
    try:
        decoded = base64.b64decode(compact + "=" * (-len(compact) % 4))
    except Exception as e:
        raise ValueError("订阅内容不是有效的 Base64: %s" % e)
    if b"://" not in decoded:
        raise ValueError("订阅内容解码后不含节点链接")
    return True


def update_config_subscribe(new_url):
    """把新的 hub 订阅链接写入 config.yaml 的 subscribe 列表。

    先删除已有的 hub.ccwork.nyc.mn/share_sub 旧行（保留其他来源），
    再把新 URL 追加到列表末尾，保持两空格缩进。
    """
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()

    out = []
    in_subscribe = False
    subscribe_indent = None
    inserted = False

    for line in lines:
        stripped = line.strip()
        if re.match(r"^subscribe\s*:", line):
            in_subscribe = True
            subscribe_indent = line[:len(line) - len(line.lstrip())]
            if stripped in ("subscribe:", "subscribe: []"):
                out.append(subscribe_indent + "subscribe:\n")
            else:
                out.append(line)
            continue
        if in_subscribe:
            # 顶层段结束（遇到下一个无缩进的键）
            if line and not line[0].isspace() and stripped:
                if not inserted:
                    out.append("  - %s\n" % new_url)
                    inserted = True
                in_subscribe = False
                out.append(line)
                continue
            if HUB_HOST_MARK in line:
                # 删除旧的 hub 订阅行
                continue
            out.append(line)
            continue
        out.append(line)

    if in_subscribe and not inserted:
        out.append("  - %s\n" % new_url)
        inserted = True

    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        f.writelines(out)


def main():
    try:
        html = http_get_text(HUB_HOME)
    except Exception as e:
        print("错误：无法获取 hub 首页：%s" % e, file=sys.stderr)
        return 1

    candidates = extract_candidates(html)
    if not candidates:
        print("错误：未能从 hub 首页提取到任何 token 候选",
              file=sys.stderr)
        return 1

    print("找到 %d 个 token 候选，逐个校验..." % len(candidates))
    errors = []
    for token in candidates:
        url = HUB_SUB_PREFIX + token
        try:
            validate_subscription(url)
        except Exception as e:
            errors.append("token %s... 无效：%s" % (token[:8], e))
            continue
        # 校验通过，写入 config 并输出 URL
        try:
            update_config_subscribe(url)
        except Exception as e:
            print("错误：写入 config.yaml 失败：%s" % e, file=sys.stderr)
            return 1
        print("hub 订阅链接：%s" % url)
        print("已写入 config.yaml 的 subscribe 列表")
        return 0

    print("错误：所有 token 候选均校验失败：", file=sys.stderr)
    for err in errors:
        print("  - %s" % err, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
