# Agnes AI 批量注册机 (修复版)

自动注册 Agnes AI 平台账号，批量获取 API Key。
基于 [chentianxiong123/agnes-ai-register](https://github.com/chentianxiong123/agnes-ai-register) 修复，**2026-09-25 全链路实测通过**（注册 → 收码 → 创建 Key → Key 实际可调 `apihub.agnes-ai.com/v1`）。

## 原版为什么不能用了

| 问题 | 现象 |
|------|------|
| 脚本 bug | Mail.tm 邮件详情 `html` 字段是**数组**，原版把列表直接传正则，收码必崩 `TypeError: expected string or bytes-like object` |
| 域名级频控 | Agnes 对邮箱域名计数，Mail.tm 公共域名 `uberip.com` 已被全球用户刷爆，返回 `400 "Too many registration attempts from this email domain"` |
| 一次性邮箱黑名单 | Agnes 拒收常见临时邮箱域名：mailsac / mailinator / tempmail.plus 全家族 / guerrillamail / mail.gw / getnada / yopmail / dropmail / 1secmail / inboxkitten / cybertemp / best-tempmail 等约 70 个域名全部实测被拒 |

## 修复版方案

| 渠道 | 说明 | 状态 |
|------|------|------|
| **catchmail**（默认） | `api.catchmail.io` 免鉴权 REST API；域名 `catchmail.io` / `mailistry.com` / `zeppost.com` 均不在黑名单，三域名轮换分摊频控 | ✅ 实测收码成功 |
| **tgmailer**（备用） | `tempgmailer.com` 真实 Gmail 别名，`gmail.com` 永不进黑名单；收件较慢 | ⚠️ 发码成功、收件慢 |
| **mail.tm**（兜底） | 原版渠道，已修 html 数组 bug | ❌ 域名被频控 |

发码失败会**自动换渠道/换域名重试**（最多 5 次）。

## 使用

```bash
pip install requests

# 直接跑(默认 10 个账号)
python register.py

# 常用环境变量
REGISTER_COUNT=5 THREAD_COUNT=2 TOKEN_NAME=auto python register.py

# 遇到 "Too many registration attempts from this IP" 时, 让 Agnes 请求走本地代理换出口 IP
AGNES_PROXY=http://127.0.0.1:10808 python register.py
```

输出文件：

- `accounts.json` — 完整账号信息（邮箱、密码、渠道、Token、Key）
- `keys.txt` — 仅 API Key 列表

## 注意事项

- Agnes 有 **IP 级频控**，同一 IP 短时间高频调用 verification 接口会被限流几分钟，建议 `REGISTER_COUNT` 别太大、开 `AGNES_PROXY`
- catchmail 邮箱无需注册，地址随机生成即收信，但邮件不保证长期保留，跑完及时取 key
- 仅供学习使用
