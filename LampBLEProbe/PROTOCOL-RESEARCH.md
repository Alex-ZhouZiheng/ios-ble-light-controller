# 协议研究记录：2026-10-29

## 本灯的直接证据

用户在 0.3 导出的报告中确认：广播名 `shhf.light.slcwb8`；FE95 广播头的产品 ID 字节为 `38 37`，按小端解释是 14136；只有 FE95 服务，包含 0004、0005、0010、0016、0017、0018、0019、001A、001B、001C。0004 读取到 20 字节数据，去掉尾部 0 后为 `2.1.2_0004`。连接时 RSSI 为 -64 dBm。

这些是识别协议的线索，不是认证成功证据。不能用固件字符串里的 2 直接确定认证类型，也不能把 CoreBluetooth UUID 当作 MAC。

## 资料与选择

### 0.4 真机验证进展

用户于 2026-10-29 19:05:46 UTC 导出的“验证认证通道”报告确认：连接成功，0004 版本仍为 `2.1.2_0004`；0010、0016 通知订阅成功；发送 A4 后收到符合预期的 MNG0，协商 payload 为 111 字节；收到 113 字节 MNG1 并通过长度及内容校验，提交了 113 字节最终 echo。整个诊断约 1.45 秒。

这为本灯支持候选协议的 A4/MNG 阶段提供了真机证据。最终 echo 由 CoreBluetooth 提交，未单独验证对端接收结果；没有发送 50 登录请求、凭证证明或开灯指令。下一关是自有 gatt_ltmk 的取得和登录验收，无需再重复只读扫描。

1. 小米官方[直连控制说明](https://iot.mi.com/v2/new/doc/plugin/other/connection-ble) 将 authType=4（Standard Auth）和 authType=5（Mesh）区分。不能因为二者都有 FE95 就使用同一套登录协议。
2. 小米官方[Mesh 接入文档](https://github.com/MiEcosystem/miio_open/blob/master/ble/04-%E8%93%9D%E7%89%99Mesh%E6%8E%A5%E5%85%A5%E5%BC%80%E5%8F%91.md) 说明加密直连通道需要先登录；文档中的 stdio UUID 没有出现在本灯报告里。该文档不足以提供本灯的完整客户端握手。
3. [XiaomiGateway3 支持列表](https://github.com/AlexxIT/XiaomiGateway3/blob/master/DEVICES.md) 将该型号列为 Mesh Light。它证明有网关适配实例，不证明手机直连协议已经可用。
4. kabbi 的 [Yeelight 原始抓包记录](https://gist.github.com/kabbi/32658d7d3a086cd47d877882933a9908) 和[登录 PoC](https://gist.github.com/kabbi/242a48dde4d3ae548f6d54cf1f987776) 针对 `yeelink.light.mbulb3`，记录了 FE95/0010 控制、0016 认证、A4/MNG 协商和 50/51 登录序列。
5. [xiaomi-diffuser-ble 协议记录](https://github.com/clairefiorettiythzr6802-eng/xiaomi-diffuser-ble/blob/main/docs/protocol-xw002-zh.md) 针对 `xiaomi.diffuser.xw002`，独立记录了同类登录及 001A/B/C 数据接口，与本灯服务结构相近。它仍是其他设备上的作者实测，不能直接当成本灯实现规范。

0.4 依据后两项做**可失败的兼容性实验**。没有复制参考仓库代码，也没有添加外部依赖。加密计算使用 Apple CryptoKit、Security、CommonCrypto；AES-CCM 所需的封装独立实现，并用 Python cryptography 输出交叉测试。

## 候选登录与实现边界

- 先订阅 0010、0016，确认订阅成功，才写入 A4。
- 只接受符合预期的 MNG0/MNG1 格式；协商上限结合 iOS maximumWriteValueLength，不硬编码 247 字节 MTU。
- 通道模式到 MNG 为止，不发 50，也不需要凭证。
- 登录模式需要同一设备的 32 字节 gatt_ltmk。每次生成新的 P-256 密钥对，先等待 Ready ACK，再发送分包。
- 按候选协议计算 `HKDF-SHA256(ECDH_shared || gatt_ltmk, salt="miot-mesh-login-salt", info="miot-mesh-login-info", length=64)`；使用第 16..<32 字节作为 AES-128 key，以固定 nonce `10..1b` 对设备公钥的 CRC32 小端值作 CCM 证明（4 字节 tag）。这个固定 nonce 来自参考协议，每次登录的加密 key 由新生成的 ECDH 密钥对导出。
- 仅当证明提交后，0010 返回完整 `51 00 00 00` 才记录登录被设备接受；52、未知响应、坏公钥、重复/过大的分包和阶段超时都会停止。不会将连接、订阅、ACK 或仅收到公钥误认为登录成功。
- 这不是完整的设备证书验证或双向身份验证实现；51 仅表示观察到的协议结果。
- 登录结果后断开。不执行 F0、状态读取、属性写入或自动化。参考设备可能要求登录后立刻 F0 才能控制，本轮不声称控制通道可用。
- 无自动重试、注册、重置、删除绑定、通用任意写入或 OTA 功能。

## 凭证与剩余工作

gatt_ltmk 在此协议里与设备列表 token、广播 bindkey、旧认证 key 含义不同。参考作者通过用户自己的已认证小米云会话调用 `/v2/blemesh/query_dev` 取得。本灯/账号是否能取得、具体合法登录会话的获取流程尚待验证，0.5 已提供本机扫码查询工具（Tools/cloud_key_helper.py），仅查中国大陆自有家庭并精确匹配目标型号与 MAC；该账号是否取得字段仍待扫码后验证。

手机输入的凭证只按 CoreBluetooth UUID 存入本机 Keychain，使用 WhenUnlockedThisDeviceOnly，不写进报告、UserDefaults 或源码；切换设备不共用密钥。实验日志只记录认证帧的方向、特征和字节数，不记录证明、派生密钥和凭证。最终后台读取凭证的策略尚未选择。

接下来的验收顺序是：本灯 MNG 响应 → 自有凭证取得 → 设备接受登录证明 → 重新登录并验证加密状态读取 → 前台开关灯及状态回读 → App Intents / 锁屏测试 → 回家自动化、短时重试和去重。任何一个阶段失败都保留真实结果，不返回开灯成功。

## 0.5 登录超时与 0.6 时序假设

用户提供的 2026-10-29 19:22:42 UTC 报告：App 取得本机 32 字节凭证并进入实验性登录，A4/MNG 通过，echo 在 0.744 秒提交，50 在 0.754 秒提交，公钥传输头在 0.763 秒提交，随后没有通知并在 publicReady 超时。未收到 Ready ACK，未发送公钥及证明，不能判断密钥有效性。

原 [Yeelight PoC](https://gist.github.com/kabbi/242a48dde4d3ae548f6d54cf1f987776) 在最终 MNG echo 后明确等待 200 毫秒；[香氛机实现](https://github.com/clairefiorettiythzr6802-eng/xiaomi-diffuser-ble/blob/main/python/miot_ble_specv2.py) 在 50 与传输头之间等待 200 毫秒。0.6 引入 250/200 毫秒的串行提交间隔以验证设备准备时间这一假设，没有更换凭证算法、认证通道、控制 opcode 或添加重试。新增报告头部日志帮助区分下一次是否收到 Ready ACK、错误状态或仍无通知。不能在真机结果返回前断言该时序就是唯一原因。

## 0.6 登录成功的真机证据

用户提供的 2026-10-29 19:29:57 UTC 报告确认：协商 payload 111；MNG echo 在 5.004 秒提交，50 在 5.258 秒提交，公钥传输头在 5.459 秒提交；随后收到 Ready ACK、设备 P-256 公钥，提交证明后于 6.263 秒收到完整 51。报告中没有状态读取或开关指令。时序修订已使该次真实会话成功，但单次成功不证明长期可靠性。

## 0.7 同版状态、控制和快捷指令

数据通道依据先前引用的原作者实测格式开发，并非已经在本灯验证。先订阅 001A/001B，在 51 回调同步交接派生密钥并发起 F0，避免新增登录后等待。仅在完成 CCM 校验后解析 MIoT v2；接收计数器必须递增，拒绝重放；本轮不支持计数器 rollover，达到界限时断开重连，不重复 nonce。支持单帧及有界多帧接收，立即回通道 ACK；登录前早到的数据暂存于有界缓冲，登录明确成功后再处理。

开关属性采用灯具规格中的 siid=2/piid=1，BOOL（type=0）。参考小米官方 Mesh 色温灯模板与该型号 [MIoT 规格页](https://home.miot-spec.com/spec/shhf.light.slcwb8)。本轮访问 miot-spec.org 原始实例接口未成功，因此不能声称重新取得了原始官方 JSON。只构造 F0、GetProperty 和明确 BOOL SetProperty，不使用 DoAction 或 toggle。设备返回码必须为 0，并由匹配请求 TID 的 GetPropertyResp 回读确认目标值，属性通知本身不作为成功证据。

同版 App Intents 默认不打开 UI，采用 alwaysAllowed 认证策略并声明 bluetooth-central。依据 Apple 的 [Intent 认证策略说明](https://developer.apple.com/documentation/appintents/appintent/authenticationpolicy-1r9kh)，该策略允许锁屏调用；它并不保证蓝牙操作一定得到后台运行时间。点击保存目标按钮时，才将本灯 Keychain 条目改为 AfterFirstUnlockThisDeviceOnly。仅在操作已回读确认时返回成功；25 秒整体超时、取消、版本不符、缺密钥、无法连接或设备错误均失败。无定时常驻、自动重新绑定或隐式切换其他设备。

最终仍需真机验收：前台状态读回、实体灯开关与读回一致、手动快捷指令、锁屏且 App 不在前台、家庭 Wi-Fi/地点自动化立即运行。当前只确认 0.6 登录真实成功，不能在 0.7 报告前将这些后续步骤标为完成。

## 0.7 真实关灯与回读中断

用户 2026-10-29 19:49:26 UTC 报告：F0 成功，4.363 秒回读 `on=true`；11.276 秒点击 OFF，11.834 秒收到 SetPropertyResp code=0，11.923 秒收到 22 字节数据帧，严格递增计数器检查触发，导致最终读回未完成。用户直接确认实体灯关闭。因此前台关闭真实生效，但不能把这次记录为完整读回验证成功。

0.7.1 将接收器改为 64 计数器滑动窗口，思路参考 [RFC 4303 接收窗口](https://www.rfc-editor.org/rfc/rfc4303#section-3.4.3)（仅借用通用防重放窗口设计，不声称实现 IPsec）。完整性验证成功后才更新位图；窗口内未见帧允许乱序一次，重复/过旧帧丢弃；仍只由匹配 GetPropertyResp 认定控制成功。原日志没有具体接收计数器，无法确认是迟到、重复还是 rollover；原 Xcode 调试进程已结束。因此保留 rollover 限制并新增非敏感计数器日志，以真机结果继续核对，而不假称已解密识别这次 22 字节帧。

## 0.7.1 前台开关及回读验收

用户提供的 2026-10-29 19:57:24 UTC 报告与实体观察确认：初始 on=false；4.428 秒开灯读回 true，7.278 秒关灯读回 false，8.628 秒再次开灯读回 true；三次均 SetPropertyResp code=0。9.687 秒保存快捷指令目标。乱序假设在这份报告中得到直接证据：wireCounter 5 的写入响应后到达 counter 4 的 PropertyChanged，随后 counter 6 的 GetPropertyResp；后续也有 9→8→11→10，窗口正常接受并保持匹配请求回读。

最后 15.645 秒的另一次 OFF 在 16.908 秒收到 `00000105`、总长 6 的缺帧请求，当前软件中止，不能将这次操作标为已回读成功。0.7.2 增加单帧流的显式 RCV_LOST 序号 1 补发，遵循先前参考实现记录中的 `00000105 <seq>` 格式。只重发缓存的完全相同加密帧，最多两次，不重新加密或改变 nonce/TID；不能据此省略状态回读。若实际请求序号不同，会记录并停止，不猜测任意帧。补发软件测试通过，真实分支仍待验证。
