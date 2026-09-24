# YQ 手机端绑定包

此包供 `gomobile bind` 调用，不是可执行程序。使用一条主动连接到 GOST 的
QUIC 会话，接受服务端发起的双向流，通过现有 HTTP/SOCKS5 Handler 转发请求。
转发目标由手机端网络访问，不会自动接管手机其他 App 的流量。

## 接口

- `Start(serverAddr string) error`：校验地址并启动后台任务；返回成功不代表已连接。
- `Stop()`：取消重连、关闭 QUIC 连接并等待流处理结束；应从 App 后台线程调用。
- `LastError() string`：异步错误信息。
- `ConfigureTLS(caPEM, serverName string, insecure bool) error`：启动前配置服务端证书验证。
  默认启用验证。caPEM 为空则使用系统信任库；自签名服务器可传入公开证书 PEM。
  insecure=true 仅用于开发测试。
- `SetClientCertificate(certPEM, keyPEM string) error`：可选客户端证书；空字符串清除。

同一进程只启动一个手机客户端。重复 Start 返回错误；需要切换服务器或 TLS 配置时，先 Stop。
网络中断后自动重连，失败退避从 1 秒增长至最多 30 秒。
已中断的代理连接不会迁移到新的 QUIC 会话，调用方需重新请求。
Stop 不能强制中断 Handler 中所有第三方阻塞操作，目标 TCP 拨号配置了 5 秒超时。

## Android 绑定

在项目根目录，配置 Go、JDK、Android SDK / NDK 和 gomobile 后：

```bash
gomobile bind -target=android/arm64 -o yqmobile.aar ./mobile/yqmobile
```

将 AAR 加入 Android 工程，声明 `android.permission.INTERNET`。生成的 Java
类通常为 `yqmobile.Yqmobile`，Kotlin 调用示意：

```kotlin
// 开发测试：服务器使用自动生成的自签名证书。
Yqmobile.configureTLS("", "", true)
Yqmobile.start("192.168.1.10:8081")
// 在后台线程停止。
Yqmobile.stop()
```

实际部署应配置可信证书并将 insecure 设为 false。Go 返回的 error 会通过绑定映射
为 Java 异常，App 应捕获。后台运行策略、网络切换和前台服务由 Android App 管理；
本包不会自动创建 Android Service。移动端需允许 QUIC/UDP 通信。

服务端示例：

```bash
go run ./cmd/gost -L=:8080 -F='yq://:8081' -D
```

## 验证

```bash
go test -race -v -run '^TestYQPCClientLifecycle$' .
CGO_ENABLED=0 GOOS=android GOARCH=arm64 go build ./mobile/yqmobile
```

集成测试覆盖真实 QUIC 转发、同会话多流、断线重连、停止、再次启动。
交叉编译检查不等同于 AAR 打包或真机验证。

根目录 `yq_pc_client_test.go` 中的 `TestYQPCClient` 是上述公开 API 的手动测试入口，不再单独实现 QUIC 转发。
保留原环境变量：YQ_ADDR、YQ_DURATION、YQ_INSECURE、YQ_CA、YQ_SERVER_NAME、YQ_CERT、YQ_KEY。

```bash
YQ_ADDR=127.0.0.1:8081 YQ_INSECURE=1 YQ_DURATION=5m \
  go test -v -run '^TestYQPCClient$' -count=1 -timeout=6m .
```

未设置 YQ_ADDR 时自动跳过。测试期间会输出状态变化，并使用库的自动重连逻辑；
整个测试期间从未观察到 connected 则失败。此手动测试不自行生成代理请求，
需要另一个终端通过 GOST 的 -L 入口发送请求。

## Java/Kotlin 连接状态回调

`SetConnectionListener` 可在启动前或运行中调用；传 nil 可解除注册，无须 Stop。
更换后，后续通知使用新 listener；已经取出的旧回调仍可能完成一次调用。
回调接口为 `ConnectionListener.OnStateChanged(status, errorMessage)`，Java 方法名
为 `onStateChanged`。状态变化时由连接任务直接调用，不经过事件队列。回调应尽快返回。
可以在回调中查询 LastError，但不能同步调用 Stop；请将停止操作提交到其他后台线程。
UI 更新需转到 Android 主线程。

```java
Yqmobile.setConnectionListener(new ConnectionListener() {
    @Override
    public void onStateChanged(String status, String errorMessage) {
        runOnUiThread(() -> {
            // connected: QUIC 连接成功；reconnecting: 失败或断线，查看 errorMessage。
            // connecting: 开始一次拨号。主动 Stop 不发回调。
        });
    }
});
Yqmobile.start("192.168.1.10:8081");
```

Start 参数错误等同步错误仍通过返回的 error / Java Exception 报告。
connected 不保证后续每一个目标地址都能连接成功，只代表 QUIC 会话已建立。
Stop 会等待网络任务和正在执行的回调返回。回调不可等待正在调用 Stop 的线程，
也不要在回调中做耗时操作。

状态仅通过 connecting / connected / connect_failed / reconnecting 四种回调通知，不保存状态字符串，
也不再提供 Status() 接口。Java 主动调用 Stop，返回即表示清理完成，不发送 stopped 回调。

connect_failed 表示 quic.DialAddr 失败，包含错误字符串；随后 reconnecting 表示准备重试。
主动 Stop 取消拨号不会被当作连接失败通知。
