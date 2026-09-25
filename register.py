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
  - Agnes 侧有 IP 级频控, 如遇 "Too many registration attempts from this IP"
    可设 AGNES_PROXY 环境变量让 Agnes 请求走本地代理换出口 IP:
      AGNES_PROXY=http://127.0.0.1:10808 python register.py

输出: accounts.json (完整账号) + keys.txt (仅 API Key)
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
from concurrent.futures import ThreadPoolExecutor, as_completed

REGISTER_COUNT = int(os.environ.get("REGISTER_COUNT", 10))
THREAD_COUNT = int(os.environ.get("THREAD_COUNT", 1))
TOKEN_NAME = os.environ.get("TOKEN_NAME", "auto")

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
# 渠道 1: catchmail (api.catchmail.io, 免鉴权, 三域名轮换) —— 默认主力
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
    {"name": "tgmailer",   "create": tgmailer_create,  "poll": tgmailer_poll},
    {"name": "mail.tm",    "create": mailtm_create,    "poll": mailtm_poll},
]
_channel_cycle = itertools.cycle(range(len(CHANNELS)))
_channel_lock = threading.Lock()


def next_channel():
    with _channel_lock:
        return CHANNELS[next(_channel_cycle)]


# ======================================================================
# Agnes 平台接口
# ======================================================================
def send_code(email):
    resp = requests.get(
        f"{AGNES_BASE_URL}/api/verification",
        headers={**AGNES_HEADERS, "x-user-language": "zh-CN"},
        params={"email": email, "purpose": "register"},
        timeout=30, proxies=AGNES_PROXIES,
    )
    print(f"    [发送验证码] {resp.status_code} {resp.text[:80] if resp.status_code != 200 else ''}")
    return resp


def do_register(email, password, code):
    resp = requests.post(
        f"{AGNES_BASE_URL}/api/user/register",
        headers={**AGNES_HEADERS, "x-user-language": "zh"},
        json={"email": email, "password": password, "password_confirm": password, "code": code},
        timeout=30, proxies=AGNES_PROXIES,
    )
    print(f"    [注册] {resp.status_code}")
    resp.raise_for_status()


def do_login(email, password):
    resp = requests.post(
        f"{AGNES_BASE_URL}/api/user/login",
        headers={**AGNES_HEADERS, "x-user-language": "zh"},
        json={"username": email, "password": password},
        timeout=30, proxies=AGNES_PROXIES,
    )
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


def create_key(auth_token):
    resp = requests.post(
        f"{AGNES_BASE_URL}/api/token",
        headers={**AGNES_HEADERS, "x-user-language": "zh-CN", "Authorization": f"Bearer {auth_token}"},
        json={"name": TOKEN_NAME},
        timeout=30, proxies=AGNES_PROXIES,
    )
    print(f"    [创建Key] {resp.status_code}")
    resp.raise_for_status()
    data = resp.json()
    d = data.get("data", {})
    key = d.get("key") or data.get("key")
    return key


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

    keys = []
    if os.path.exists(tp):
        with open(tp, "r", encoding="utf-8") as f:
            keys = [l.strip() for l in f if l.strip()]
    keys.extend(a["key"] for a in accounts if a.get("key"))
    with open(tp, "w", encoding="utf-8") as f:
        f.write("\n".join(keys) + "\n" if keys else "")

    print(f"[保存] {jp}  {tp}")


def register_one(idx, total):
    tag = f"[{idx}/{total}]"
    print(f"{tag} 开始")
    try:
        # 创建邮箱 + 发码, 失败自动换渠道(域名频控/黑名单时触发)
        ch = sess = None
        for attempt in range(MAX_CHANNEL_RETRY):
            ch = next_channel()
            sess = ch["create"]()
            print(f"{tag} 渠道={ch['name']} 邮箱={sess['email']}")

            resp = send_code(sess["email"])
            if resp.status_code == 200:
                break
            print(f"{tag} 发码失败, 换渠道重试 ({attempt + 1}/{MAX_CHANNEL_RETRY})")
            time.sleep(2)
        else:
            print(f"{tag} 所有渠道均发码失败, 跳过")
            return None

        code = ch["poll"](sess)
        print(f"{tag} 验证码={code}")

        password = rand_pwd()
        do_register(sess["email"], password, code)
        token = do_login(sess["email"], password)
        if not token:
            print(f"{tag} 登录Token为空，跳过")
            return None
        print(f"{tag} token={token[:40]}...")
        key = create_key(token)
        print(f"{tag} key={key}")
        print(f"{tag} 完成")
        return {"email": sess["email"], "password": password, "channel": ch["name"],
                "token": token, "key": key or "",
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    except Exception as e:
        print(f"{tag} 失败: {e}")
        return None


def run():
    accounts = []
    proxy_note = f", Agnes走代理 {AGNES_PROXY}" if AGNES_PROXY else ""
    print(f"注册 {REGISTER_COUNT} 个账号, 线程 {THREAD_COUNT}{proxy_note}")
    if THREAD_COUNT <= 1 or REGISTER_COUNT <= 1:
        for i in range(REGISTER_COUNT):
            r = register_one(i + 1, REGISTER_COUNT)
            if r:
                accounts.append(r)
            if i < REGISTER_COUNT - 1:
                time.sleep(random.randint(2, 5))
    else:
        with ThreadPoolExecutor(max_workers=THREAD_COUNT) as ex:
            fts = {ex.submit(register_one, i + 1, REGISTER_COUNT): i + 1 for i in range(REGISTER_COUNT)}
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
    if accounts:
        save(accounts)
    print(f"完成 {len(accounts)}/{REGISTER_COUNT}")


if __name__ == "__main__":
    run()
