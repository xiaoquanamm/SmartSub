#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 hub.ccwork.nyc.mn 获取当日动态 token，拼出订阅链接并写入 config.yaml 的 subscribe 列表。

仅使用 Python 标准库（urllib），无第三方依赖。
由 GitHub Actions 工作流在运行 main.py 之前调用。

token 获取策略（按顺序尝试）：
  A. 调用站点的 /api/token 接口（robots.txt 确认 /api/ 存在）。直接 GET
     返回 {"success":false,"msg":"Unauthorized"}，因此尝试带 AJAX 头
     （X-Requested-With / Referer / Accept: application/json）的 GET，以及
     POST（空 JSON / 空表单）。解析返回 JSON 中的 token 字段（或其中
     的 16/32 位 hex 字符串），再用 share_sub 校验。
  B. 首页 HTML 暴力枚举：按优先级收集所有 hex 候选并逐个校验：
     1. share_sub?token=... 显式链接中的 token；
     2. JS 中形如 "token": "..."（大小写不敏感）的定义；
     3. 页面中所有裸露的 16 位 hex 字符串（当日有效 token 为 16 位）；
     4. 页面中所有裸露的 32 位 hex 字符串（兜底）。
  逐个用 share_sub 接口校验（有效 token 返回 Base64 节点内容，无效返回
  HTTP 403/过期提示），第一个校验通过的即写入 config。
"""
import base64
import json
import os
import re
import sys
import urllib.request
import urllib.error

HUB_HOME = "https://hub.ccwork.nyc.mn/"
HUB_API_TOKEN = "https://hub.ccwork.nyc.mn/api/token"
HUB_SUB_PREFIX = "https://hub.ccwork.nyc.mn/share_sub?token="
HUB_HOST_MARK = "hub.ccwork.nyc.mn/share_sub"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "..", "config.yaml")


def http_get_text(url, timeout=30, headers=None):
    req_headers = {"User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


def http_post_json(url, payload, timeout=30, headers=None):
    req_headers = {"User-Agent": USER_AGENT,
                   "Content-Type": "application/json",
                   "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=req_headers,
                                 method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace")


def extract_token_from_api_text(text):
    """从 /api/token 的返回文本中提取 token。"""
    try:
        obj = json.loads(text)
    except Exception:
        return None
    # 常见字段名
    for key in ("token", "data"):
        val = obj.get(key)
        if isinstance(val, str) and re.fullmatch(r"[0-9a-fA-F]{8,128}",
                                                 val):
            return val
        if isinstance(val, dict):
            for v in val.values():
                if isinstance(v, str) and re.fullmatch(
                        r"[0-9a-fA-F]{8,128}", v):
                    return v
    # 兜底：在整个 JSON 文本里找 16/32 位 hex
    for pat in (r"\b[0-9a-fA-F]{16}\b", r"\b[0-9a-fA-F]{32}\b"):
        m = re.search(pat, text)
        if m:
            return m.group(0)
    return None


def fetch_token_via_api(timeout=30):
    """尝试通过 /api/token 获取 token，返回 token 或 None。"""
    ajax_headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json",
        "Referer": HUB_HOME,
    }
    attempts = []
    # 1. 带 AJAX 头的 GET
    try:
        text = http_get_text(HUB_API_TOKEN, timeout=timeout,
                             headers=ajax_headers)
        attempts.append(("GET+ajax", text))
    except Exception as e:
        print("  [api] GET+ajax 失败：%s" % e)
    # 2. POST 空 JSON
    try:
        text = http_post_json(HUB_API_TOKEN, {}, timeout=timeout,
                              headers={"Referer": HUB_HOME,
                                       "X-Requested-With": "XMLHttpRequest"})
        attempts.append(("POST+json", text))
    except Exception as e:
        print("  [api] POST+json 失败：%s" % e)
    for name, text in attempts:
        print("  [api] %s 返回：%s" % (name, text[:120]))
        tok = extract_token_from_api_text(text)
        if tok:
            print("  [api] %s 解析到 token 候选：%s..." % (name, tok[:8]))
            return tok
    return None


def extract_candidates(html):
    """从首页 HTML 按优先级收集 token 候选（去重，保持优先级顺序）。"""
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


def try_candidate(token, errors):
    """校验单个 token 候选，有效则写入 config 并返回 True。"""
    url = HUB_SUB_PREFIX + token
    try:
        validate_subscription(url)
    except Exception as e:
        errors.append("token %s... 无效：%s" % (token[:8], e))
        return False
    try:
        update_config_subscribe(url)
    except Exception as e:
        print("错误：写入 config.yaml 失败：%s" % e, file=sys.stderr)
        sys.exit(1)
    print("hub 订阅链接：%s" % url)
    print("已写入 config.yaml 的 subscribe 列表")
    return True


def main():
    errors = []

    # 策略 A：/api/token 接口
    print("尝试 /api/token 接口获取 token...")
    try:
        api_token = fetch_token_via_api()
    except Exception as e:
        print("  [api] 接口调用异常：%s" % e)
        api_token = None
    if api_token:
        print("接口返回 token 候选，开始校验...")
        if try_candidate(api_token, errors):
            return 0
        print("接口 token 校验未通过，转入 HTML 枚举")
    else:
        print("接口未返回可用 token，转入 HTML 枚举")

    # 策略 B：首页 HTML 暴力枚举
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
    for token in candidates:
        if try_candidate(token, errors):
            return 0

    print("错误：所有 token 候选均校验失败：", file=sys.stderr)
    for err in errors:
        print("  - %s" % err, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
