#!/bin/sh
set -eu
task_tool_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
printf '%s\n' '请打开下方 OPEN 后面的本机网址，用米家扫一扫完成一次登录。' '不要将下载的密钥文件发到聊天中。按 Control-C 可结束本地会话。'
exec python3 -u "$task_tool_dir/cloud_key_helper.py" --target-file "$task_tool_dir/../.private/target.json"
