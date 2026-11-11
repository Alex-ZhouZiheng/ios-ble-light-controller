# BLE Light Controller for iOS

A Swift iOS app for Xiaomi BLE light control, with encrypted communication, an iPhone hub, and Apple Shortcuts automation.

- Native SwiftUI interface and CoreBluetooth connectivity.
- Device authentication, encrypted commands, and state readback verification.
- An old iPhone as a BLE hub, with HTTPS relay for arrival and departure automation.
- Experimental on-device finger-snap detection using Apple SoundAnalysis; hardware validation is pending.
- Local diagnostic logs and hardware-independent regression tests.

The current device integration targets `shhf.light.slcwb8`; compatibility with other lights has not been verified.

## Getting started

Open `LampBLEProbe/LampBLEProbe.xcodeproj` in Xcode, select your own signing team, and run on a physical iPhone. Device credentials are configured locally and stored in Keychain.

See the [Chinese project documentation](LampBLEProbe/README.zh-CN.md) for setup and validation details, the [automation guide](LampBLEProbe/AUTOMATION.zh-CN.md), and the [protocol research notes](LampBLEProbe/PROTOCOL-RESEARCH.md).

## Tests

On macOS with Xcode installed:

```sh
sh LampBLEProbe/Tests/run.sh
python3 -m unittest discover -s LampBLEProbe/Tests -p 'test_*.py'
```

The tests use synthetic credentials and responses. Real device behavior and iOS background execution require separate hardware validation.

## Third-party notices

See [third-party licenses](LampBLEProbe/Tools/THIRD_PARTY_LICENSES.md) for the credential helper's attribution and license.
