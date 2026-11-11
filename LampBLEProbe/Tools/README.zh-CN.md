# 中国大陆自有灯具的本地凭证获取

用于已经绑定在用户本人米家账号下的 `shhf.light.slcwb8`。不读取密码，不保存小米登录会话，不输出账号 token、其他设备的密钥或 gatt_ltmk 原文。仅查询自有家庭并按型号与 MAC 精确匹配灯具，再查询 `/v2/blemesh/query_dev`。接口由参考实现提供，并非小米承诺稳定的第三方个人 API。

## 本次使用

本机已配置目标灯的 MAC（来自用户提供的 MiBeacon 报告），配置位于被 Git 忽略的 `.private/target.json`。工具需要 Python 3 和 cryptography；当前 Mac 已有这些依赖。

1. 运行 `获取灯具密钥.command`；若 Finder 无法直接运行，可在终端执行 `sh` 后拖入该文件。
2. 打开终端显示的 `OPEN http://127.0.0.1:端口/…` 本机网址。
3. 用米家 App 的扫一扫扫描二维码，在手机上确认登录。二维码约数分钟后过期；过期时停止工具并重新运行。
4. 查询成功后，页面出现“下载本灯密钥文件”。下载 `LampBLEProbe-key.json`，通过隔空投送传到自己的 iPhone，并保存至“文件”App。
5. 在 iPhone 的蓝牙灯诊断 0.5 中，先扫描并选择灯（只读诊断即可）。结束后进入“配置所选灯的认证密钥”→“导入本灯密钥文件”，选择 JSON。
6. App 会核对文件格式、版本、地区、型号、MAC 和密钥长度，再保存到这台手机的 Keychain。确认已导入后，返回选择“实验性登录”，再次点击灯具并分享**诊断报告**。

无需将密钥文件、密码、二维码登录链接或账号凭证发到聊天。初始扫码确认与每日回家免操作的目标分开：正式自动化不应要求每天扫码。

## 范围与生命周期

- 页面只监听 `127.0.0.1` 随机端口，不能从局域网访问。校验 Host/Origin 和随机访问令牌；页面和接口禁用缓存、外部嵌入和跨站读取。
- 账号登录仅连接明确列出的 Xiaomi 官方 HTTPS 主机。此 Mac 的官方登录接口返回欧洲账号轮询域名，已按实际响应加入精确列表；米家设备查询依然固定中国大陆 `api.io.mi.com`。
- 登录会话只存在内存，在取得结果或失败后清除。密钥下载内容在内存保留最多 10 分钟，之后服务退出；Control-C 可立即停止整个进程。浏览器下载的文件由用户保管，App 导入后可自行删除。
- 文件不含全量设备列表、设备列表 token、广播 bindkey 或云端会话。`gatt_ltmk` 必须恰为 32 字节十六进制值；接口缺失或返回其他 key 类型时停止，不做替代或重试绑定。
- 仅支持已核对的自有目标灯。登录确认、目标匹配或接口返回失败会显示脱敏错误，不改灯的米家绑定，不控制或重置设备。

## 验证和引用

运行 `python3 -m unittest discover -s ../Tests -p 'test_cloud_key_helper.py'` 执行离线测试；使用测试数据验证 RC4 RFC 6229 向量、签名、设备匹配、仅查自有家庭、拒绝错误 key 类型、只读接口白名单，以及本机下载和跨来源拦截。

工具的扫码和加密请求部分改编自 [Xiaomi-cloud-tokens-extractor](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor/blob/master/token_extractor.py)，保留 [MIT 许可](THIRD_PARTY_LICENSES.md)。Mesh 密钥接口依据 [xiaomi-diffuser-ble 的原作者实测记录](https://github.com/clairefiorettiythzr6802-eng/xiaomi-diffuser-ble/blob/main/docs/protocol-xw002-zh.md)。扫码页面初始化已在本机验证；本账号是否取得 gatt_ltmk 仍需用户完成扫码后验证。
