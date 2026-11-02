#!/usr/bin/env python3
"""Aggregate free node subscriptions from multiple active GitHub repos.

Follows ProxyNodeHub logic:
  discover active repos -> fetch subscription files -> parse -> dedupe by server:port -> export Clash YAML.

Sources (all verified active 2026-11-03):
  Pawdroid/Free-servers      sub                          (base64 URIs)
  kooker/FreeSubsCheck       all.yaml                     (Clash YAML)
  PuddinCat/BestClash        proxies.yaml                 (Clash YAML)
  snakem982/proxypool        source/clash-meta-2.yaml     (Clash YAML)

Output: agg-clash.yaml (Clash YAML, FlClash / Clash Meta compatible).
Only stdlib + PyYAML.
"""
import sys, urllib.request, urllib.parse, json, base64, re

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

SOURCES = [
    ("PW", "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub", "b64"),
    ("KK", "https://raw.githubusercontent.com/kooker/FreeSubsCheck/main/all.yaml", "yaml"),
    ("PC", "https://raw.githubusercontent.com/PuddinCat/BestClash/main/proxies.yaml", "yaml"),
    ("PP", "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta-2.yaml", "yaml"),
]

def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def q1(qs, key, default=""):
    v = qs.get(key, [default])
    return v[0] if v else default

def parse_vless(u):
    p = urllib.parse.urlparse(u)
    if not p.hostname or not p.port:
        return None
    name = urllib.parse.unquote(p.fragment) or f"{p.hostname}:{p.port}"
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
    if not p.hostname or not p.port:
        return None
    name = urllib.parse.unquote(p.fragment) or f"{p.hostname}:{p.port}"
    qs = urllib.parse.parse_qs(p.query)
    proxy = {"name": name, "type": "trojan", "server": p.hostname, "port": p.port,
             "password": urllib.parse.unquote(p.username or ""), "udp": True}
    sni = q1(qs, "sni") or q1(qs, "peer")
    if sni:
        proxy["sni"] = sni
    return proxy

def parse_vmess(u):
    try:
        body = u[8:]
        body += "=" * (-len(body) % 4)
        cfg = json.loads(base64.b64decode(body).decode("utf-8", "replace"))
    except Exception:
        return None
    if not cfg.get("add") or not cfg.get("port"):
        return None
    proxy = {"name": cfg.get("ps") or f"{cfg['add']}:{cfg['port']}",
             "type": "vmess", "server": cfg["add"], "port": int(cfg["port"]),
             "uuid": cfg.get("id", ""), "alterId": int(cfg.get("aid", 0)),
             "cipher": cfg.get("scy", "auto"), "udp": True}
    if cfg.get("tls") == "tls":
        proxy["tls"] = True
        if cfg.get("sni"):
            proxy["servername"] = cfg["sni"]
    net = cfg.get("net", "tcp")
    if net and net != "tcp":
        proxy["network"] = net
    if net == "ws":
        proxy["ws-opts"] = {"path": cfg.get("path", "/"),
                            "headers": {"Host": cfg.get("host", "")} if cfg.get("host") else {}}
    return proxy

def parse_ss(u):
    try:
        p = urllib.parse.urlparse(u)
        name = urllib.parse.unquote(p.fragment) or f"{p.hostname}:{p.port}"
        if "@" not in u:
            body = u[5:].split("#")[0].split("?")[0]
            body += "=" * (-len(body) % 4)
            decoded = base64.b64decode(body).decode("utf-8", "replace")
            m = re.match(r"(.+?):(.+)@(.+):(\d+)", decoded)
            if not m:
                return None
            method, password, host, port = m.groups()
        else:
            if not p.hostname or not p.port:
                return None
            userinfo = urllib.parse.unquote(p.username or "")
            if ":" in userinfo:
                method, password = userinfo.split(":", 1)
            else:
                userinfo += "=" * (-len(userinfo) % 4)
                decoded = base64.b64decode(userinfo).decode("utf-8", "replace")
                method, password = decoded.split(":", 1)
            host, port = p.hostname, p.port
        return {"name": name, "type": "ss", "server": host, "port": int(port),
                "cipher": method, "password": password, "udp": True}
    except Exception:
        return None

def parse_uri(u):
    u = u.strip()
    if u.startswith("vless://"):
        return parse_vless(u)
    if u.startswith("vmess://"):
        return parse_vmess(u)
    if u.startswith("trojan://"):
        return parse_trojan(u)
    if u.startswith("ss://"):
        return parse_ss(u)
    return None

def parse_b64_body(data, tag):
    """Decode a base64 subscription body into Clash proxies."""
    text = data.decode("utf-8", "replace").strip()
    compact = re.sub(r"\s+", "", text)
    try:
        padded = compact + "=" * (-len(compact) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", "replace")
    except Exception:
        decoded = text
    proxies = []
    for line in decoded.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        px = parse_uri(line)
        if px:
            px["name"] = f"[{tag}]{px['name']}"
            proxies.append(px)
    return proxies

def parse_yaml_body(data, tag):
    try:
        doc = yaml.safe_load(data.decode("utf-8", "replace"))
    except Exception as e:
        print(f"  [{tag}] yaml parse failed: {e}", file=sys.stderr)
        return []
    if not isinstance(doc, dict):
        return []
    out = []
    for px in doc.get("proxies") or []:
        if not isinstance(px, dict):
            continue
        server = px.get("server")
        port = px.get("port")
        if not server or not port:
            continue
        px = dict(px)
        px["name"] = f"[{tag}]{px.get('name', f'{server}:{port}')}"
        out.append(px)
    return out

def main():
    all_proxies = []
    seen = set()
    stats = {}
    for tag, url, kind in SOURCES:
        try:
            data = fetch(url)
        except Exception as e:
            print(f"[{tag}] fetch failed: {e}", file=sys.stderr)
            stats[tag] = 0
            continue
        if kind == "b64":
            proxies = parse_b64_body(data, tag)
        else:
            proxies = parse_yaml_body(data, tag)
        added = 0
        for px in proxies:
            key = (str(px["server"]).lower(), int(px["port"]))
            if key in seen:
                continue
            seen.add(key)
            base = px["name"]
            n = 2
            existing_names = {p["name"] for p in all_proxies}
            while px["name"] in existing_names:
                px["name"] = f"{base}#{n}"
                n += 1
            all_proxies.append(px)
            added += 1
        stats[tag] = added
        print(f"[{tag}] {len(proxies)} parsed, {added} new (total {len(all_proxies)})")
    header = ("port: 7890\nsocks-port: 7891\nallow-lan: true\nmode: Rule\n"
              "log-level: info\nproxies:\n")
    dumped = yaml.safe_dump(all_proxies, allow_unicode=True, default_flow_style=False)
    # indent every line by 2 spaces so list items sit under "proxies:"
    body = header + "\n".join(("  " + ln) if ln.strip() else ln
                              for ln in dumped.splitlines())
    # proxy groups: manual select + auto url-test
    names = [p["name"] for p in all_proxies]
    def qname(n):
        return yaml.safe_dump(n, allow_unicode=True,
                              default_flow_style=True).strip()
    body += "\nproxy-groups:\n"
    body += ('  - name: "PROXY"\n    type: select\n    proxies:\n'
             '      - "AUTO"\n      - "DIRECT"\n')
    for n in names:
        body += f"      - {qname(n)}\n"
    body += ('  - name: "AUTO"\n    type: url-test\n'
             '    url: http://www.gstatic.com/generate_204\n'
             '    interval: 300\n    proxies:\n')
    for n in names:
        body += f"      - {qname(n)}\n"
    # rules: domestic direct, everything else via proxy
    body += ("rules:\n"
             "  - DOMAIN-SUFFIX,cn,DIRECT\n"
             "  - GEOIP,CN,DIRECT\n"
             "  - MATCH,PROXY\n")
    with open("agg-clash.yaml", "w", encoding="utf-8") as f:
        f.write(body)
    print(f"WROTE agg-clash.yaml with {len(all_proxies)} proxies: {stats}")

if __name__ == "__main__":
    main()
