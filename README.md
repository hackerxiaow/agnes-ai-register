# Agnes AI 批量注册机 (修复版)

自动注册 Agnes AI 平台账号并批量获取 API Key。
基于 [chentianxiong123/agnes-ai-register](https://github.com/chentianxiong123/agnes-ai-register) 深度修复，2026-09-25 实测全链路可用。

## 原版为什么不能用了

| 问题 | 现象 |
|------|------|
| 脚本 bug | Mail.tm 邮件详情 `html` 字段是**数组**，原版把列表直接传正则，收码必崩 |
| 域名级频控 | Agnes 对邮箱域名计数，Mail.tm 公共域名 `uberip.com` 周期性被封 `400 "Too many registration attempts from this email domain"` |
| 一次性邮箱黑名单 | 约 70 个常见临时邮箱域名被拒（mailinator/tempmail.plus 全家/guerrillamail/mail.gw/getnada/yopmail/1secmail/mailsac 等），且**动态更新** |
| IP 级频控 | 每出口 IP 约 5~10 次调用/窗口（发码/注册/登录/建Key 都计数），触发后 `400 "Too many registration attempts from this IP"` |

## 修复版架构

**多渠道轮换**（发码失败自动 换域名→换渠道）：

| 渠道 | 域名数 | 状态 |
|------|--------|------|
| catchmail（api.catchmail.io，免鉴权） | 3（io/com/zeppost 轮换） | ✅ 主力，投递快 |
| mail.tm（原版渠道，已修 html bug） | 1 | ⚠️ 周期性域名频控，窗口期可用 |
| tempmail365 | 4 | ⚠️ 站点不稳 |
| 10minute-one | 6 | ⚠️ 实测收不到 Agnes 邮件，兜底 |
| tempgmailer（真实 Gmail 别名） | gmail.com 永不进黑名单 | ⚠️ 收件接口不稳 |

**IP 级频控对策**（选其一，可叠加多机并行）：
- `AGNES_RELAY`：自建 CF Worker 中继，请求从 CF 出口 IP 发出（见下）
- `AGNES_PROXY`：走本地代理换出口 IP
- 多台 VPS 各自带独立出口 IP 并行跑，配额池互不影响
- 遇频控阶梯等待（75s→40min，8 档）自动恢复，**按成功数计数**，失败不占名额

**CF Worker 中继**（几行代码，绑定任意 CF 域名即可）：

```js
addEventListener("fetch", (e) => { e.respondWith(handleRequest(e.request)); });
async function handleRequest(req) {
  const t = new URL(req.url).searchParams.get("t");
  if (!t || !t.startsWith("https://platform-backend.agnes-ai.com/")) return new Response("bad", { status: 400 });
  const h = new Headers(req.headers); h.delete("host"); h.delete("cf-connecting-ip"); h.delete("x-real-ip");
  const init = { method: req.method, headers: h, redirect: "follow" };
  if (req.method !== "GET" && req.method !== "HEAD") init.body = await req.arrayBuffer();
  return fetch(t, init);
}
```

## 使用

```bash
pip install requests

# 单机直跑(默认目标 25 个成功)
python register.py

# 常用环境变量
REGISTER_COUNT=20          # 目标成功注册数(失败自动补)
CREATE_KEY=1               # 1=注册+登录+随机名Key(默认); 0=只注册
THREAD_COUNT=1             # 并发线程
AGNES_RELAY=https://xxx    # CF Worker 中继(推荐)
AGNES_PROXY=http://...     # 或本地代理
```

## 输出文件

- `accounts.txt` — 一行一个：`邮箱----密码`
- `keys.txt` — 一行一个 API Key
- `accounts.json` — 完整记录（邮箱、密码、渠道、token、key、时间）

邮箱前缀、密码、Key 名称均随机生成。

## 多机并行方案（实测）

6 个独立配额池并行：本地(中继池) + 2×IPv4 VPS(直连) + 3×IPv6 VPS(直连)。
每台 `nohup env CREATE_KEY=1 REGISTER_COUNT=17 python3 -u register.py > batch.log 2>&1 &`，跑完后汇总各机 `accounts.txt`/`keys.txt` 去重合并。

## 注意事项

- catchmail 邮箱无需注册、即取即用，但邮件不长期保留，跑完及时取 key
- 频控窗口小时级，100 个账号的量级需要多池并行跑数小时，脚本无人值守自动重试
- 仅供学习使用
