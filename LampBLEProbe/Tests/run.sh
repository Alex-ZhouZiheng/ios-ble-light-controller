#!/bin/sh
set -eu
task_test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
task_build_dir=$(mktemp -d "${TMPDIR:-/tmp}/LampBLEProbe-tests.XXXXXX")
trap 'rm -rf "$task_build_dir"' EXIT
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
xcrun --sdk macosx swiftc -target "$(uname -m)-apple-macosx15.0" \
    -sdk "$(xcrun --sdk macosx --show-sdk-path)" \
    -module-cache-path "$task_build_dir/modules" \
    "$task_test_dir/../LampBLEProbe/MeshAuth.swift" "$task_test_dir/../LampBLEProbe/LampControl.swift" "$task_test_dir/MeshAuthTests.swift" "$task_test_dir/ControlTests.swift" \
    -o "$task_build_dir/MeshAuthTests"
"$task_build_dir/MeshAuthTests"
xcrun --sdk macosx swiftc -target "$(uname -m)-apple-macosx15.0" \
    -sdk "$(xcrun --sdk macosx --show-sdk-path)" \
    -module-cache-path "$task_build_dir/modules" \
    "$task_test_dir/../LampBLEProbe/RelayPolicy.swift" "$task_test_dir/RelayTests.swift" \
    -o "$task_build_dir/RelayTests"
"$task_build_dir/RelayTests"
xcrun --sdk macosx swiftc -target "$(uname -m)-apple-macosx15.0" \
    -sdk "$(xcrun --sdk macosx --show-sdk-path)" \
    -module-cache-path "$task_build_dir/modules" \
    "$task_test_dir/../LampBLEProbe/SnapDetector.swift" "$task_test_dir/SnapTests.swift" \
    -o "$task_build_dir/SnapTests"
"$task_build_dir/SnapTests"
xcrun --sdk macosx swiftc -target "$(uname -m)-apple-macosx15.0" \
    -sdk "$(xcrun --sdk macosx --show-sdk-path)" \
    -module-cache-path "$task_build_dir/modules" \
    "$task_test_dir/../LampBLEProbe/DiagnosticLog.swift" "$task_test_dir/DiagnosticTests.swift" \
    -o "$task_build_dir/DiagnosticTests"
"$task_build_dir/DiagnosticTests"
