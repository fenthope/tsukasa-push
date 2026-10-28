# tsukasa-push

Go 实现的 Web Push SDK：把浏览器/原生端的推送能力拆成四个可组合的包，覆盖 **RFC 8030（Web Push 协议）**、**RFC 8188（aes128gcm 内容编码）**、**RFC 8291（推送消息加密）**、**RFC 8292（VAPID）**。

- 模块：`github.com/fenthope/tsukasa-push`，Go 1.27
- 密码学：纯标准库（`crypto/ecdh`、`crypto/hkdf`、`crypto/aes`+GCM、`crypto/ecdsa`），无第三方密码学依赖
- HTTP：`github.com/WJQSERVER-STUDIO/httpc`；服务端框架：`github.com/infinite-iroha/touka`；限流：`github.com/fenthope/ikumi`
- 定位：SDK 而非独立程序，可嵌入自有基础设施；存储通过 `Store` 接口注入

## 规范映射

| 规范 | 条款 | 实现位置 |
| --- | --- | --- |
| RFC 8030 §4 | 订阅创建（201 + Location + `Link rel="urn:ietf:params:push"`） | `service.handleSubscribe` / `receiver.Subscribe` |
| RFC 8030 §5 | 推送投递（TTL 必填、201 + Location） | `sender.Send` / `service.handlePush` |
| RFC 8030 §5.2 | TTL 语义（含 0 TTL 仅在 UA 在线时投递） | `pushmsg.ParseTTL` / `service.MemoryStore.Enqueue` |
| RFC 8030 §5.3 | Urgency / Topic | `pushmsg.Urgency` / `pushmsg.ValidTopic` |
| RFC 8030 §6 | UA 接收消息 | `receiver.Poll` / `service.handlePoll` |
| RFC 8030 §6.2 | 消息确认（DELETE 消息资源） | `receiver.Ack` / `service.handleAck` |
| RFC 8030 §7.3 | 订阅过期（404 + `TTL-Expired`） | `service.handlePoll` / `service.handlePush` |
| RFC 8188 | aes128gcm 记录格式（86 字节头、AAD 为空） | `pushmsg.Encrypt` / `pushmsg.Decrypt` |
| RFC 8291 | ECDH P-256 + HKDF 派生、单记录、pad 分隔符 0x02 | `pushmsg.deriveKeys` |
| RFC 8292 | VAPID：ES256 JWT、`aud`/`exp`/`sub`、受限订阅 | `vapid.Signer` / `vapid.Verify` / `service.checkVAPID` |

未实现（明确不在范围内）：legacy `aesgcm` 编码、receipt subscription、§5.4 消息替换、batch、subscription set。

## 包结构

```
pushmsg/   共享内核：aes128gcm 加解密、订阅 JSON、TTL/Urgency/Topic 校验、链接关系常量
vapid/     ES256 JWT 签发与验证、受限订阅公钥
sender/    应用服务器侧：加密投递、VAPID、错误分类
service/   push service 侧：touka 路由、Store 接口 + 内存实现、长轮询
receiver/  用户代理侧：订阅、长轮询接收、解密、确认
```

## 用法

### 用户代理（接收端）

```go
ua, err := receiver.New("https://push.example.com")
sub, err := ua.Subscribe(ctx)                    // 订阅，返回 URI 与密钥
appSub, err := sub.AppSubscription()             // 交给应用服务器的形态

for {
    msg, err := ua.Poll(ctx, sub)                // 长轮询 + 解密
    if err != nil {
        return err
    }
    handle(msg.Payload)
    ua.Ack(ctx, msg)                            // 确认投递
}
```

`Subscription` 可直接 JSON 序列化保存（内含私钥，务必加密存储）。

### 应用服务器（发送端）

```go
app := sender.New(sender.WithVAPID(signer, "mailto:ops@example.com"))
err := app.Send(ctx, appSub, sender.Message{
    Payload: []byte(`{"title":"hi"}`),
    TTL:     3600,
    Urgency: pushmsg.UrgencyHigh,
    Topic:   "inbox",
})
```

错误通过 `errors.Is` 判别：`ErrSubscriptionNotFound`(404)、`ErrSubscriptionGone`(410)、`ErrVAPIDRequired`(401)、`ErrVAPIDRejected`(403)、`ErrTooManyRequests`(429)、`ErrBadRequest`(400)、`pushmsg.ErrPayloadTooLarge`(413)；其余非 2xx 返回 `*sender.HTTPError`（含 `RetryAfter`）。

### 自建 push service

```go
engine := touka.Default()
svc := service.New(
    service.WithBaseURL("https://push.example.com"),
    // 应用服务器是系统里不受信任的一环（RFC 8030 §8.4），按 IP 限流
    service.WithRateLimit(ikumi.TokenRateLimiterOptions{
        Limit: rate.Limit(20),
        Burst: 40,
    }),
)
svc.Register(engine)          // 挂载 /subscribe /push/:id /subscription/:id /message/:id
```

限流由 [fenthope/ikumi](https://github.com/fenthope/ikumi)（Touka 速率限制中间件）实现，**只作用于 `/push/:id`**：用户代理的订阅轮询是长连接，不能消耗令牌。默认使用内存令牌桶，可通过 `Store` 换成共享存储实现集群限流。

限流桶默认按**应用服务器的 VAPID 身份**划分，不同的应用服务器互不影响；缺少或伪造 VAPID 凭据的请求回落到客户端 IP，避免用随机 `k` 参数无限开桶。VAPID 验签结果在请求上下文里缓存，限流与 handler 不会重复验签。需要按其他维度限流时设置 `opts.KeyFunc`。

默认使用内存存储；需要持久化时实现 `service.Store` 接口并用 `service.WithStore` 注入。

路由语义：

| 方法与路径 | 说明 | 成功响应 | 失败响应 |
| --- | --- | --- | --- |
| `POST /subscribe` | 创建订阅，可选 body `{"vapid":"..."}` | 201 + `Location` + `Link rel=push` | 400 参数非法 |
| `POST /push/:id` | 应用服务器投递消息 | 201 + `Location`(消息资源) + `TTL` | 400 TTL/紧急度/Topic 非法，401/403 VAPID，404 订阅不存在，413 载荷过大 |
| `GET /subscription/:id` | UA 长轮询（`Prefer: wait=0` 立即返回） | 200 + `Location` + 消息体；无消息 204 | 404 订阅过期/不存在 |
| `DELETE /subscription/:id` | 退订 | 204 | 410 |
| `DELETE /message/:id` | 确认投递 | 204 | 410 |

## 与 RFC 的差异

1. **长轮询替代 HTTP/2 server push**：RFC 8030 §6 规定用 H2 push 下发消息；本实现以长轮询响应承载消息体，消息资源 URI 通过 `Location` 头传递（RFC §9.2 未注册 message 链接关系类型）。
2. **Topic 只透传不实现替换**：校验语法并记录，不实现 §5.4 的同 Topic 覆盖语义，且不向 UA 转发（符合 §5.4 要求）。
3. **Urgency 过滤按 §5.3 语义**：UA 未带 `Urgency` 头时接收任意紧急度；带该头时低于下限的消息不投递；该头不下发给 UA。
4. **零 TTL 消息**：仅在有 UA 正在等待时投递，否则立即过期（§5.2）。
5. **默认不重试**：`httpc` 默认对 429/5xx 自动重试并遵守 `Retry-After`，会静默重发推送，因此 SDK 默认关闭重试，由宿主通过 `httpc.WithRetryOptions` 自行开启。

## 生产注意事项

- **明文上限 3993 字节**（4096 − 86 头 − 1 pad − 16 tag），超出时 sender 直接报错，service 返回 413。
- **公钥点校验**：所有 ECDSA/ECDH 公钥经 `crypto/ecdh` 校验在曲线上，避免无效曲线攻击。
- **VAPID 与 ECDH 密钥必须不同**（RFC 8292 §3.2）；SDK 生成的两类密钥相互独立。
- **订阅 URI 与密钥属于机密**（RFC 8030 §8.3）：传输通道必须加密认证。
- **长轮询会占用连接**：按并发量规划连接数；客户端应设置超时并循环重连。
- **存储抽象**：`service.Store` 是唯一的持久化切入点，内存实现不保证重启后保留订阅。

## UnifiedPush

UnifiedPush（unifiedpush.org）在应用服务器与推送服务器之间使用 **Web Push**（RFC 8030/8188/8291/8292）：推送消息是 RFC 8291 加密的单记录（1–4096 字节），鉴权用 VAPID（RFC 8292）。因此 `tsukasapush` 的 `sender` 包可以直接向 UnifiedPush 端点发送消息，无需新协议。

### 应用服务器（发送）

`upush/` 包是一层薄封装，把 UnifiedPush 注册信息（端点、P-256 公钥、auth secret）转换为 `pushmsg.Subscription`，并通过 `sender.Send` 投递：

```go
sub := &upush.Subscription{
    Endpoint:  endpoint,        // 来自分发器的 Web Push capability URL
    P256DHB64: p256dhB64,       // 客户端加密公钥，base64url
    AuthB64:   authB64,         // 16 字节认证密钥，base64url
}
if err := sub.Validate(); err != nil {
    log.Fatalf("invalid subscription: %v", err)
}

snd := sender.New(sender.WithVAPID(signer, "mailto:ops@example.com"))
if err := upush.Push(ctx, snd, sub, sender.Message{
    Payload: payload,
    TTL:     60,
    Urgency: pushmsg.UrgencyHigh,
}); err != nil {
    log.Fatalf("push: %v", err)
}
```

### 端设备（接收）

`upush/device/` 包提供端设备侧的接收能力：订阅管理与消息解密。分发器通过 Android 广播意图或 Linux D-Bus 将加密字节送到设备，本 SDK 负责解密（RFC 8291），传输层由嵌入方自行处理：

```go
// 设备生成订阅（端点和连接令牌来自分发器）
sub, err := device.GenerateSubscription(endpoint, connectionToken, distributor)
if err := sub.Validate(); err != nil {
    log.Fatalf("validate: %v", err)
}

// 私钥留在设备上，公钥和端点对外发给应用服务器
recv := device.NewReceiver(sub)

// 收到分发器下发的加密字节后解密
plain, err := recv.Decrypt(encryptedBytes)
```

完整演示见 `go run ./example/upush`（发送端）与 `go run ./example/device`（接收端）。

## 开发

```bash
go test ./...                        # 单元测试 + 端到端测试
go test -race ./...                  # 并发检查
go test -fuzz=FuzzDecrypt -fuzztime=30s ./pushmsg/
go run ./example                     # Web Push 完整闭环演示
go run ./example/upush               # UnifiedPush 发送端演示
go run ./example/device              # UnifiedPush 接收端演示
```

密码学实现以 RFC 8291 §5 与附录 A、RFC 8292 §2.4 的官方测试向量逐字节比对，另有随机往返、篡改、错误密钥与模糊测试。

### 性能基准

基准覆盖加密、验签与端到端推送，用 `benchstat`（`golang.org/x/perf/cmd/benchstat`）做改动前后的对比：

```bash
# 改动前先采集基线
go test -run XXX -bench . -benchmem -count 10 ./... > plan/bench/baseline.txt

# 改动后采集并对比
go test -run XXX -bench . -benchmem -count 10 ./... > plan/bench/current.txt
benchstat plan/bench/baseline.txt plan/bench/current.txt
```

| 基准 | 覆盖路径 |
| --- | --- |
| `pushmsg`: `GenerateUAKeys` / `Encrypt` / `Decrypt` / `DeriveKeys` | RFC 8291 加解密与密钥派生 |
| `vapid`: `Token` / `Authorization` / `VerifyToken` / `ParseAuthorization` | RFC 8292 签发与校验 |
| `sender`: `Send` / `SendWithVAPID` / `SendLargePayload` | 加密 + 签名 + HTTP 往返 |
| `service`: `HandlePush` / `HandlePoll` | push service 请求与消息投递 |
| `receiver`: `Poll` / `DecryptOnly` | 用户代理收取与解密 |
| `upush`: `Push` / `Subscription.Validate` | UnifiedPush 端点投递（Web Push 上层） |

耗时指标受机器负载影响较大（本机为共享 CPU，噪声约 ±10%），判断回归以确定性的 `allocs/op` 与 `B/op` 为准，耗时只在同机同负载下对比。
