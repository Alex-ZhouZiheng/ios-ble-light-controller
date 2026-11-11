# 直接导入随身 iPhone

将本目录的 **回家开灯.shortcut** 和 **离家关灯.shortcut** 隔空投送到随身 iPhone，或通过“文件”App 打开，选择添加快捷指令。

两个文件已使用 Apple 自带 `shortcuts sign --mode anyone` 签名，不包含真实控制凭证，也不包含联系人信息。Mac 导入检查已确认设置问题正常显示、锁定时可运行，POST 的文件请求体正确引用文本输出。

导入时分别回答两个问题：

1. 请求地址：旧手机蓝牙灯 App → 配置随身 iPhone 的自动化 → 复制请求地址。
2. 文本内容：回家开灯使用“开灯内容”，离家关灯使用“关灯内容”。

填写后操作已经搭好，无需添加操作；日后运行不再弹出配置问题。先各手动运行一次并完成首次联网授权，以旧手机回读和实体灯亮灭确认结果。

最后在随身 iPhone 给“回家开灯”添加到达家的自动触发，给“离家关灯”添加离开家的自动触发，设为无需确认运行。家庭地址和位置触发由你在随身手机上选择，文件没有预填位置，也不会在导入后自动启用位置自动化。

`source/` 是未签名源模板，不要导入这个子目录的文件。重新生成：

```sh
python3 LampBLEProbe/Tools/generate_presence_shortcuts.py
shortcuts sign --mode anyone --input LampBLEProbe/Shortcuts/source/回家开灯.shortcut --output LampBLEProbe/Shortcuts/回家开灯.shortcut
shortcuts sign --mode anyone --input LampBLEProbe/Shortcuts/source/离家关灯.shortcut --output LampBLEProbe/Shortcuts/离家关灯.shortcut
```

签名时 Apple 会接收模板副本进行验证；这些模板为空白，不含真实配对地址和控制口令。不要将填入真实凭证后的快捷指令公开分享。
