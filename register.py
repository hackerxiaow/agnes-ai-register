#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Agnes AI 批量注册机 (修复版)
原版: https://github.com/chentianxiong123/agnes-ai-register

原版存在的两个致命问题(2026-09 实测):
  1. Mail.tm 邮件详情的 html 字段是数组, 原版把列表直接传给正则,
     收验证码时必现 TypeError: expected string or bytes-like object
  2. Mail.tm 公共域名(uberip.com)已被 Agnes 按域名级频控封锁
     (400 "Too many registration attempts from this email domain"),
     且 Agnes 维护了一次性邮箱黑名单(mailsac/mailinator/tempmail.plus/
     guerrillamail/mail.gw 等常见临时邮箱全部被拒), 原版开箱即废

修复版方案(2026-09-25 全链路实测通过):
  - 默认渠道 catchmail: api.catchmail.io 免鉴权 REST API,
    域名 catchmail.io / mailistry.com / zeppost.com 均不在 Agnes 黑名单,
    三域名轮换分摊域名级频控, 已实测收到 Agnes 真实验证码
  - 备用渠道 tgmailer: tempgmailer.com 真实 Gmail 别名,
    gmail.com 永远不可能进一次性邮箱黑名单(其收件箱较慢, 作兜底)
  - 保留原 mail.tm 渠道(已修 html 数组 bug)作最后兜底
  - 发码失败(域名频控/进黑名单)自动切换渠道重试
  - Agnes 侧有 IP 级频控(约 5~10 次调用/小时/IP, 发码注册登录建Key都计数):
      * 根治: 自建 CF Worker 中继并设 AGNES_RELAY=https://你的worker域名
        (每次请求从不同 CF 出口 IP 发出, 实测彻底绕开 IP 频控)
      * 临时: AGNES_PROXY=http://127.0.0.1:10808 换本地代理出口 IP

输出: accounts.json (账号邮箱/密码, 每注册成功一个立即落盘)
      CREATE_KEY=1 时额外记录 token/key 到 accounts.json 并写 keys.txt
仅供学习使用。
"""

import requests
import json
import time
import re
import random
import string
import os
import threading
import itertools
from urllib.parse import urlencode, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

REGISTER_COUNT = int(os.environ.get("REGISTER_COUNT", 25))
THREAD_COUNT = int(os.environ.get("THREAD_COUNT", 1))
# Key 名称: 环境变量指定则固定, 否则每个账号随机
TOKEN_NAME = os.environ.get("TOKEN_NAME", "").strip()
# 是否登录并创建 API Key(1=注册+登录+建Key, 0=只注册账号)
CREATE_KEY = int(os.environ.get("CREATE_KEY", 1))

# 发码失败时最多换渠道重试次数(渠道池: catchmail 3域名 + tgmailer + mail.tm)
MAX_CHANNEL_RETRY = 5

MAIL_BASE_URL = "https://api.mail.tm"

AGNES_BASE_URL = "https://platform-backend.agnes-ai.com"
AGNES_HEADERS = {
    "accept": "*/*",
    "accept-encoding": "gzip, deflate, br, zstd",
    "accept-language": "zh-CN,zh;q=0.9,en-US;q=0.8",
    "cache-control": "no-cache",
    "content-type": "application/json",
    "origin": "https://platform.agnes-ai.com",
    "pragma": "no-cache",
    "referer": "https://platform.agnes-ai.com/",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-site",
}
AGNES_PROXY = os.environ.get("AGNES_PROXY", "").strip()
AGNES_PROXIES = {"http": AGNES_PROXY, "https": AGNES_PROXY} if AGNES_PROXY else None
# CF Worker 中继(绕过 Agnes IP 级频控的根治方案):
#   部署一个把请求转发到 platform-backend.agnes-ai.com 的 Worker,
#   例如 AGNES_RELAY=https://agnes-relay.cnz.indevs.in
AGNES_RELAY = os.environ.get("AGNES_RELAY", "").strip()
# 免费代理池文件(每行 ip:port): 每次 Agnes 请求随机换代理, 频控立即换下一个,
# 彻底稀释 Agnes 的 IP 级频控。文件由 validate_proxies 预先验证过可达 Agnes。
PROXY_POOL = []
_pf = os.environ.get("AGNES_PROXY_FILE", "").strip()
if _pf:
    try:
        PROXY_POOL = [l.strip() for l in open(_pf) if l.strip()]
    except Exception:
        PROXY_POOL = []

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36")

CSS_COLORS = frozenset({
    '000000', '111111', '222222', '333333', '444444', '555555',
    '666666', '777777', '888888', '999999', 'aaaaaa', 'bbbbbb',
    'cccccc', 'dddddd', 'eeeeee', 'ffffff',
})

lock = threading.Lock()


def rand_pwd(length=14):
    c = string.ascii_letters + string.digits
    while True:
        p = "".join(random.choices(c, k=length))
        if re.search(r"[A-Za-z]", p) and re.search(r"\d", p):
            return p + "Q"


def to_text(value):
    """邮件正文统一转成字符串(html 字段可能是列表——原版必崩 bug 的修复点)"""
    if value is None:
        return ""
    if isinstance(value, list):
        return "\n".join(str(x) for x in value)
    return str(value)


def extract_code(subject, body):
    """从邮件内容中提取6位验证码"""
    subject, body = to_text(subject), to_text(body)
    if not body:
        return None

    # 优先匹配 verification 相关 class
    m = re.search(r'class=["\'][^"\']*verification[^"\']*["\'][^>]*>([^<]{6})<', body)
    if m and m.group(1).isdigit():
        return m.group(1)

    # 从所有文本中找6位数字，排除 CSS 颜色值
    for m in re.finditer(r'\b(\d{6})\b', f"{subject} {body}"):
        if m.group(1) not in CSS_COLORS:
            return m.group(1)

    return None


# ======================================================================
# 渠道 0: 10minute-one (web.10minutemail.one, 6 域名轮换, 免鉴权仅Bearer)
# ======================================================================
TENMIN_DOMAINS = ["xghff.com", "oqqaj.com", "psovv.com", "dbwot.com", "ygwpr.com", "imxwe.com"]
_tenmin_cycle = itertools.cycle(TENMIN_DOMAINS)
_tenmin_lock = threading.Lock()
TENMIN_SITE = "https://10minutemail.one"
TENMIN_API = "https://web.10minutemail.one/api/v1"
JWT_RE = re.compile(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$')


def _tenmin_token():
    r = requests.get(f"{TENMIN_SITE}/zh", headers={"User-Agent": UA,
                     "Accept": "text/html,application/xhtml+xml,*/*"}, timeout=30)
    r.raise_for_status()
    m = re.search(r'<script[^>]*\bid="__NUXT_DATA__"[^>]*>([\s\S]*?)</script>', r.text)
    if not m:
        raise RuntimeError("tenmin: __NUXT_DATA__ 不存在")
    arr = json.loads(m.group(1).strip())

    def resolve(v, depth=0):
        if isinstance(v, int) and not isinstance(v, bool) and 0 <= v < len(arr) and depth < 64:
            return resolve(arr[v], depth + 1)
        return v

    for el in arr:
        if isinstance(el, dict) and "mailServiceToken" in el:
            t = resolve(el["mailServiceToken"])
            if isinstance(t, str) and JWT_RE.match(t):
                return t
    for el in arr:
        if isinstance(el, str) and JWT_RE.match(el):
            return el
    raise RuntimeError("tenmin: 未找到 mailServiceToken")


def tenmin_create():
    token = _tenmin_token()
    with _tenmin_lock:
        domain = next(_tenmin_cycle)
    local = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return {"email": f"{local}@{domain}", "token": token}


def _tenmin_headers(token):
    return {"Accept": "*/*", "Authorization": f"Bearer {token}",
            "Content-Type": "application/json", "Origin": TENMIN_SITE,
            "Referer": f"{TENMIN_SITE}/", "User-Agent": UA,
            "X-Request-ID": os.urandom(16).hex(),
            "X-Timestamp": str(int(time.time()))}


def tenmin_poll(sess, timeout=120, interval=4):
    email, token = sess["email"], sess["token"]
    start = time.time()
    fails = 0
    refreshed = False
    while time.time() - start < timeout:
        h = _tenmin_headers(token)
        try:
            r = requests.get(f"{TENMIN_API}/mailbox/{requests.utils.quote(email)}",
                             headers=h, timeout=30)
            if r.status_code == 401 and not refreshed:
                # token 偶发失效, 刷新一次再试
                refreshed = True
                token = _tenmin_token()
                time.sleep(interval)
                continue
            r.raise_for_status()
            data = r.json()
            rows = data if isinstance(data, list) else []
            for row in rows:
                body = ""
                b = row.get("body")
                if isinstance(b, dict):
                    body = b.get("html") or b.get("text") or ""
                elif row.get("html") or row.get("text") or row.get("mail_text"):
                    body = row.get("html") or row.get("text") or row.get("mail_text")
                elif row.get("id"):
                    dr = requests.get(f"{TENMIN_API}/mailbox/{requests.utils.quote(email)}/{row['id']}",
                                      headers=h, timeout=30)
                    if dr.ok:
                        body = str(dr.json())
                code = extract_code(row.get("subject", ""), body)
                if code:
                    return code
            fails = 0
        except Exception:
            fails += 1
            if fails >= 6:
                raise
        print(f"    [轮询] {int(time.time() - start)}s")
        time.sleep(interval)
    raise TimeoutError(f"验证码超时 ({timeout}s)")


# ======================================================================
# 渠道 1: tempmail365 (tempmail365.cn, 4 域名轮换, 两个 GET 搞定)
# ======================================================================
T365_DOMAINS = ["fengyou.cc", "shop345.com", "nutemail.com", "qvrf.cn"]
_t365_cycle = itertools.cycle(T365_DOMAINS)
_t365_lock = threading.Lock()
T365_BASE = "https://tempmail365.cn/tempemail.php"
T365_H = {"Accept": "application/json, text/plain, */*", "Referer": "https://tempmail365.cn/",
          "User-Agent": UA}


def t365_create():
    with _t365_lock:
        domain = next(_t365_cycle)
    user = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    email = f"{user}@{domain}"
    r = requests.get(T365_BASE, params={"action": "create_email", "email": email, "domain": domain},
                     headers=T365_H, timeout=30)
    r.raise_for_status()
    if not r.json().get("success"):
        raise RuntimeError(f"t365: 创建邮箱失败 {r.text[:80]}")
    return {"email": email}


def t365_poll(sess, timeout=120, interval=4):
    email = sess["email"]
    start = time.time()
    while time.time() - start < timeout:
        r = requests.get(T365_BASE, params={"action": "fetch_mail", "email": email},
                         headers=T365_H, timeout=30)
        r.raise_for_status()
        content = (r.json() or {}).get("content") or ""
        if content and content != "无邮件":
            code = extract_code("", content)
            if code:
                return code
        print(f"    [轮询] {int(time.time() - start)}s")
        time.sleep(interval)
    raise TimeoutError(f"验证码超时 ({timeout}s)")


# ======================================================================
# 渠道 2: catchmail (api.catchmail.io, 免鉴权, 三域名轮换)
# ======================================================================
CATCHMAIL_DOMAINS = ["catchmail.io", "mailistry.com", "zeppost.com"]
_cm_domain_cycle = itertools.cycle(CATCHMAIL_DOMAINS)
_cm_lock = threading.Lock()


def catchmail_create():
    local = "sdk" + "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
    with _cm_lock:
        domain = next(_cm_domain_cycle)
    email = f"{local}@{domain}"
    r = requests.get(
        "https://api.catchmail.io/api/v1/mailbox",
        params={"address": email},
        headers={"Accept": "application/json", "Referer": "https://catchmail.io/",
                 "Origin": "https://catchmail.io", "User-Agent": UA},
        timeout=30,
    )
    r.raise_for_status()
    return {"email": email}


def catchmail_poll(sess, timeout=120, interval=4):
    email = sess["email"]
    h = {"Accept": "application/json", "Referer": "https://catchmail.io/",
         "Origin": "https://catchmail.io", "User-Agent": UA}
    start = time.time()
    while time.time() - start < timeout:
        r = requests.get("https://api.catchmail.io/api/v1/mailbox",
                         params={"address": email}, headers=h, timeout=30)
        r.raise_for_status()
        for msg in r.json().get("messages") or []:
            d = requests.get(f"https://api.catchmail.io/api/v1/message/{msg['id']}",
                             params={"mailbox": email}, headers=h, timeout=30).json()
            body = (d.get("body") or {})
            code = extract_code(d.get("subject", ""), body.get("html") or body.get("text"))
            if code:
                return code
        print(f"    [轮询] {int(time.time() - start)}s")
        time.sleep(interval)
    raise TimeoutError(f"验证码超时 ({timeout}s)")


# ======================================================================
# 渠道 2: tempgmailer (tempgmailer.com, 真实 Gmail 别名, gmail.com 永不进黑名单)
# ======================================================================
def tgmailer_create():
    s = requests.Session()
    s.headers.update({"User-Agent": UA})
    r = s.get("https://tempgmailer.com/", timeout=30)
    r.raise_for_status()
    m = re.search(r'<meta\s+name="csrf-token"\s+content="([^"]+)"', r.text)
    if not m:
        raise RuntimeError("tgmailer: 获取 CSRF token 失败")
    h = {"X-Requested-With": "XMLHttpRequest", "X-TempGmailer-Auth": "frontend",
         "X-CSRF-TOKEN": m.group(1), "Origin": "https://tempgmailer.com",
         "Referer": "https://tempgmailer.com/", "Accept": "application/json, text/plain, */*",
         "Content-Type": "application/json"}
    r = s.post("https://tempgmailer.com/get-gmail", json={"refresh": True, "adblock": 0},
               headers=h, timeout=30)
    r.raise_for_status()
    email = r.json()["data"]["email"]
    return {"session": s, "email": email, "headers": h}


def tgmailer_poll(sess, timeout=150, interval=6):
    email, s, h = sess["email"], sess["session"], sess["headers"]
    start = time.time()
    while time.time() - start < timeout:
        r = s.post("https://tempgmailer.com/get-inbox", json={"email": email, "adblock": 0},
                   headers=h, timeout=30)
        r.raise_for_status()
        for msg in (r.json().get("data") or {}).get("messages") or []:
            code = extract_code(msg.get("subject", ""), msg.get("body") or msg.get("intro"))
            if code:
                return code
        print(f"    [轮询] {int(time.time() - start)}s")
        time.sleep(interval)
    raise TimeoutError(f"验证码超时 ({timeout}s)")


# ======================================================================
# 渠道 3: mail.tm (原版渠道, 已修 html 数组 bug, 域名大概率被 Agnes 频控, 仅兜底)
# ======================================================================
def mailtm_create():
    r = requests.get(f"{MAIL_BASE_URL}/domains", timeout=30)
    r.raise_for_status()
    domains = r.json()['hydra:member']
    domain = domains[0]['domain']

    username = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    email = f"{username}@{domain}"
    password = rand_pwd()

    r = requests.post(f"{MAIL_BASE_URL}/accounts", json={"address": email, "password": password}, timeout=30)
    r.raise_for_status()
    r = requests.post(f"{MAIL_BASE_URL}/token", json={"address": email, "password": password}, timeout=30)
    r.raise_for_status()
    return {"email": email, "mail_token": r.json()['token']}


def mailtm_poll(sess, timeout=120, interval=3):
    headers = {"Authorization": f"Bearer {sess['mail_token']}"}
    start = time.time()
    seen_ids = set()
    while time.time() - start < timeout:
        resp = requests.get(f"{MAIL_BASE_URL}/messages", headers=headers, timeout=30)
        resp.raise_for_status()
        for msg in resp.json().get("hydra:member", []):
            msg_id = msg.get("id")
            if not msg_id or msg_id in seen_ids:
                continue
            seen_ids.add(msg_id)
            email_data = requests.get(f"{MAIL_BASE_URL}/messages/{msg_id}",
                                      headers=headers, timeout=30).json()
            body = to_text(email_data.get("text") or email_data.get("html"))
            code = extract_code(email_data.get("subject", ""), body)
            if code:
                return code
        print(f"    [轮询] {int(time.time() - start)}s")
        time.sleep(interval)
    raise TimeoutError(f"验证码超时 ({timeout}s)")


CHANNELS = [
    {"name": "catchmail",  "create": catchmail_create, "poll": catchmail_poll},
    {"name": "mail.tm",    "create": mailtm_create,    "poll": mailtm_poll},
    {"name": "t365",       "create": t365_create,      "poll": t365_poll},
    {"name": "tenmin",     "create": tenmin_create,    "poll": tenmin_poll},
    {"name": "tgmailer",   "create": tgmailer_create,  "poll": tgmailer_poll},
]
_channel_cycle = itertools.cycle(range(len(CHANNELS)))
_channel_lock = threading.Lock()


def next_channel():
    with _channel_lock:
        return CHANNELS[next(_channel_cycle)]


# ======================================================================
# Agnes 平台接口
# ======================================================================
def agnes_request(method, path, params=None, json_body=None, headers=None):
    """Agnes 请求统一出口, 优先级: 代理池(每次随机换IP, 频控自动换) >
    CF Worker 中继 > 本地代理 > 直连。"""
    headers = headers or AGNES_HEADERS
    target = AGNES_BASE_URL + path + (("?" + urlencode(params)) if params else "")

    if AGNES_RELAY and not PROXY_POOL:
        url = f"{AGNES_RELAY}/?t={quote(target, safe='')}"
        return requests.request(method, url, headers=headers,
                                json=json_body, timeout=30)

    tries = 14 if PROXY_POOL else 1
    last = None
    for i in range(tries):
        px = None
        if PROXY_POOL:
            p = random.choice(PROXY_POOL)
            px = {"http": f"http://{p}", "https": f"http://{p}"}
        elif AGNES_PROXIES:
            px = AGNES_PROXIES
        try:
            resp = requests.request(method, target, headers=headers,
                                    json=json_body, timeout=30, proxies=px)
        except requests.RequestException:
            last = None
            time.sleep(0.4)
            continue
        if (resp.status_code == 400 and PROXY_POOL
                and ("from this IP" in resp.text or "Sending too frequently" in resp.text)):
            last = resp
            time.sleep(0.6)
            continue
        return resp
    if last is not None:
        return last
    raise RuntimeError("Agnes 请求全部失败(代理池均不可用)")


def send_code(email):
    resp = agnes_request("GET", "/api/verification",
                         params={"email": email, "purpose": "register"},
                         headers={**AGNES_HEADERS, "x-user-language": "zh-CN"})
    print(f"    [发送验证码] {resp.status_code} {resp.text[:80] if resp.status_code != 200 else ''}")
    return resp


def do_register(email, password, code):
    resp = agnes_request("POST", "/api/user/register",
                         headers={**AGNES_HEADERS, "x-user-language": "zh"},
                         json_body={"email": email, "password": password,
                                    "password_confirm": password, "code": code})
    print(f"    [注册] {resp.status_code}")
    resp.raise_for_status()


def do_login(email, password):
    resp = agnes_request("POST", "/api/user/login",
                         headers={**AGNES_HEADERS, "x-user-language": "zh"},
                         json_body={"username": email, "password": password})
    print(f"    [登录] {resp.status_code}")
    resp.raise_for_status()
    data = resp.json()
    d = data.get("data", {})
    token = d.get("access_token") or d.get("token") or data.get("access_token") or data.get("token")
    if not token and isinstance(d, dict):
        for k, v in d.items():
            if isinstance(v, str) and len(v) > 15:
                token = v
                break
    return token


def create_key(auth_token, name=None):
    resp = agnes_request("POST", "/api/token",
                         headers={**AGNES_HEADERS, "x-user-language": "zh-CN",
                                  "Authorization": f"Bearer {auth_token}"},
                         json_body={"name": name or TOKEN_NAME or "auto"})
    print(f"    [创建Key] {resp.status_code}")
    resp.raise_for_status()
    data = resp.json()
    d = data.get("data", {})
    key = d.get("key") or data.get("key")
    return key


def rand_key_name():
    if TOKEN_NAME:
        return TOKEN_NAME
    return "k" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def save(accounts):
    jp = "accounts.json"
    tp = "keys.txt"
    old = []
    if os.path.exists(jp):
        try:
            with open(jp, "r", encoding="utf-8") as f:
                old = json.load(f)
        except Exception:
            old = []
    old.extend(accounts)
    with open(jp, "w", encoding="utf-8") as f:
        json.dump(old, f, ensure_ascii=False, indent=2)

    # keys.txt: 一行一个 API Key
    keys = []
    if os.path.exists(tp):
        with open(tp, "r", encoding="utf-8") as f:
            keys = [l.strip() for l in f if l.strip()]
    keys.extend(a["key"] for a in accounts if a.get("key"))
    with open(tp, "w", encoding="utf-8") as f:
        f.write("\n".join(keys) + "\n" if keys else "")

    # accounts.txt: 一行一个 账号----密码
    ap = "accounts.txt"
    lines = []
    if os.path.exists(ap):
        with open(ap, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
    lines.extend(f"{a['email']}----{a['password']}" for a in accounts)
    with open(ap, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n" if lines else "")

    print(f"[保存] {jp} {tp} {ap}")


def register_one(idx, total):
    tag = f"[{idx}/{total}]"
    print(f"{tag} 开始")
    try:
        # 创建邮箱 + 发码。失败策略: 同渠道重试1次(域名自动轮换) → 换渠道;
        # IP 级频控 → 等待窗口后用同一邮箱重试(邮箱不换, 不浪费)
        ch = sess = None
        ip_waits = 0
        attempt = 0
        same_retry = False
        while True:
            if sess is None:
                ch = next_channel()
                sess = ch["create"]()
                print(f"{tag} 渠道={ch['name']} 邮箱={sess['email']}")
            resp = send_code(sess["email"])
            if resp.status_code == 200:
                break
            msg = ""
            try:
                msg = resp.json().get("message", "")
            except Exception:
                msg = resp.text[:100]
            if (("from this IP" in msg) or ("Sending too frequently" in msg)) and ip_waits < 8:
                # 阶梯式等待: 75s → 180s → 5min → 10min → 15min → 20min → 30min → 40min
                waits = [75, 180, 300, 600, 900, 1200, 1800, 2400]
                d = waits[min(ip_waits, len(waits) - 1)]
                ip_waits += 1
                print(f"{tag} IP级频控, 等{d}s后同一邮箱重试 ({ip_waits}/8)")
                time.sleep(d)
                continue
            attempt += 1
            if attempt >= MAX_CHANNEL_RETRY:
                print(f"{tag} 所有渠道均发码失败, 跳过")
                return None
            if not same_retry and "email domain" in msg:
                # 域名级频控: 同渠道换下一个域名再试一次
                same_retry = True
                sess = None
                print(f"{tag} 域名频控, 同渠道换域名重试 ({attempt}/{MAX_CHANNEL_RETRY})")
                time.sleep(2)
                continue
            same_retry = False
            sess = None
            print(f"{tag} 发码失败({msg[:50]}), 换渠道重试 ({attempt}/{MAX_CHANNEL_RETRY})")
            time.sleep(2)

        code = ch["poll"](sess)
        print(f"{tag} 验证码={code}")

        password = rand_pwd()
        # 注册接口同样可能撞 IP 级频控, 阶梯等待重试
        reg_waits = [75, 180, 300, 600, 900]
        for reg_attempt in range(len(reg_waits) + 1):
            try:
                do_register(sess["email"], password, code)
                break
            except requests.HTTPError as e:
                body = e.response.text if e.response is not None else ""
                if (e.response is not None and e.response.status_code == 400
                        and "from this IP" in body and reg_attempt < len(reg_waits)):
                    d = reg_waits[reg_attempt]
                    print(f"{tag} 注册撞IP频控, 等{d}s重试 ({reg_attempt + 1}/{len(reg_waits)})")
                    time.sleep(d)
                    continue
                raise

        account = {"email": sess["email"], "password": password, "channel": ch["name"],
                   "created_at": time.strftime("%Y-%m-%d %H:%M:%S")}

        if CREATE_KEY:
            token = do_login(sess["email"], password)
            if not token:
                print(f"{tag} 登录Token为空，跳过")
                return None
            print(f"{tag} token={token[:40]}...")
            key = create_key(token, rand_key_name())
            print(f"{tag} key={key}")
            account["token"] = token
            account["key"] = key or ""

        print(f"{tag} 完成")
        with lock:
            save([account])
        return account
    except Exception as e:
        print(f"{tag} 失败: {e}")
        return None


def run():
    accounts = []
    proxy_note = f", Agnes走中继 {AGNES_RELAY}" if AGNES_RELAY else (
        f", Agnes走代理 {AGNES_PROXY}" if AGNES_PROXY else "")
    print(f"目标成功注册 {REGISTER_COUNT} 个账号, 线程 {THREAD_COUNT}{proxy_note}")
    if THREAD_COUNT <= 1 or REGISTER_COUNT <= 1:
        successes = 0
        attempts = 0
        # 以成功数为准, 失败不占名额; 总尝试次数封顶防止死循环
        while successes < REGISTER_COUNT and attempts < REGISTER_COUNT * 5:
            attempts += 1
            r = register_one(successes + 1, REGISTER_COUNT)
            if r:
                successes += 1
                accounts.append(r)
                if successes < REGISTER_COUNT:
                    time.sleep(random.randint(5, 12))
    else:
        with ThreadPoolExecutor(max_workers=THREAD_COUNT) as ex:
            fts = {ex.submit(register_one, i + 1, REGISTER_COUNT): i + 1 for i in range(REGISTER_COUNT * 2)}
            done = 0
            for ft in as_completed(fts):
                idx = fts[ft]
                try:
                    r = ft.result()
                    if r:
                        with lock:
                            accounts.append(r)
                        print(f"[结果] #{idx} 成功")
                    else:
                        print(f"[结果] #{idx} 失败")
                except Exception as e:
                    print(f"[结果] #{idx} 异常: {e}")
    print(f"完成 {len(accounts)}/{REGISTER_COUNT}")


if __name__ == "__main__":
    run()
