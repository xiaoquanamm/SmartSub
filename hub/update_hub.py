#!/usr/bin/env python3
"""Fetch today's hub share_sub (token from hub/token.txt), decode, convert to Clash YAML.
Runs inside GitHub Actions. Stdlib only. Writes hub-clash.yaml at repo root."""
import base64, os, sys, urllib.parse, urllib.request

TOKEN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "token.txt")
OUT_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hub-clash.yaml")
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

def fetch(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")

def q1(qs, key, default=""):
    v = qs.get(key, [default])
    return v[0] if v else default

def parse_vless(u):
    p = urllib.parse.urlparse(u)
    name = urllib.parse.unquote(p.fragment) or "%s:%s" % (p.hostname, p.port)
    qs = urllib.parse.parse_qs(p.query)
    proxy = {"name": name, "type": "vless", "server": p.hostname, "port": p.port,
             "uuid": p.username, "udp": True}
    net = q1(qs, "type", "tcp")
    if net and net != "tcp":
        proxy["network"] = net
    sec = q1(qs, "security")
    if sec in ("tls", "reality"):
        proxy["tls"] = True
    if sec == "reality":
        proxy["reality-opts"] = {"public-key": q1(qs, "pbk"), "short-id": q1(qs, "sid")}
    sni = q1(qs, "sni") or q1(qs, "host")
    if sni:
        proxy["servername"] = sni
    fp = q1(qs, "fp")
    if fp:
        proxy["client-fingerprint"] = fp
    flow = q1(qs, "flow")
    if flow:
        proxy["flow"] = flow
    if net == "ws":
        opts = {"path": urllib.parse.unquote(q1(qs, "path", "/"))}
        host = q1(qs, "host")
        if host:
            opts["headers"] = {"Host": host}
        proxy["ws-opts"] = opts
    elif net == "grpc":
        proxy["grpc-opts"] = {"grpc-service-name": q1(qs, "serviceName")}
    return proxy

def parse_trojan(u):
    p = urllib.parse.urlparse(u)
    name = urllib.parse.unquote(p.fragment) or "%s:%s" % (p.hostname, p.port)
    qs = urllib.parse.parse_qs(p.query)
    proxy = {"name": name, "type": "trojan", "server": p.hostname, "port": p.port,
             "password": urllib.parse.unquote(p.username or ""), "udp": True}
    sni = q1(qs, "sni") or q1(qs, "peer")
    if sni:
        proxy["sni"] = sni
    return proxy

def ys(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'

def emit(px, indent="  "):
    lines, first = [], True
    for k, v in px.items():
        prefix = indent + "- " if first else indent + "  "
        first = False
        if isinstance(v, dict):
            lines.append("%s%s:" % (prefix, k))
            for kk, vv in v.items():
                if isinstance(vv, dict):
                    lines.append("%s    %s:" % (indent, kk))
                    for kkk, vvv in vv.items():
                        lines.append("%s      %s: %s" % (indent, kkk, ys(vvv)))
                else:
                    lines.append("%s    %s: %s" % (indent, kk, ys(vv)))
        else:
            lines.append("%s%s: %s" % (prefix, k, ys(v)))
    return lines

def main():
    token = open(TOKEN_FILE, encoding="utf-8").read().strip()
    if not token:
        print("token.txt is empty"); sys.exit(1)
    raw = fetch("https://hub.ccwork.nyc.mn/share_sub?token=" + token)
    text = base64.b64decode(raw).decode("utf-8", "replace")
    proxies, seen = [], set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            if line.startswith("vless://"):
                px = parse_vless(line)
            elif line.startswith("trojan://"):
                px = parse_trojan(line)
            else:
                continue
        except Exception:
            continue
        if not px.get("server") or not px.get("port"):
            continue
        name, base, i = px["name"], px["name"], 2
        while name in seen:
            name = "%s #%d" % (base, i); i += 1
        px["name"] = name; seen.add(name); proxies.append(px)
    if len(proxies) < 10:
        print("too few proxies: %d" % len(proxies)); sys.exit(1)
    names = [p["name"] for p in proxies]
    out = ["port: 7890", "socks-port: 7891", "allow-lan: true", "mode: Rule",
           "log-level: info", "proxies:"]
    for px in proxies:
        out += emit(px)
    out.append("proxy-groups:")
    out.append('  - name: "PROXY"')
    out.append("    type: select")
    out.append("    proxies:")
    out.append('      - "AUTO"')
    for n in names:
        out.append("      - " + ys(n))
    out.append('  - name: "AUTO"')
    out.append("    type: url-test")
    out.append("    url: http://www.gstatic.com/generate_204")
    out.append("    interval: 300")
    out.append("    proxies:")
    for n in names:
        out.append("      - " + ys(n))
    out.append("rules:")
    out.append('  - "MATCH,PROXY"')
    open(OUT_FILE, "w", encoding="utf-8").write("\n".join(out) + "\n")
    print("wrote %s with %d proxies" % (OUT_FILE, len(proxies)))

if __name__ == "__main__":
    main()
