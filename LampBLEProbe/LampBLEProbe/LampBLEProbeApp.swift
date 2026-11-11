import SwiftUI
import Combine
import CoreBluetooth
import UIKit
import UniformTypeIdentifiers
import OSLog

@main
struct LampBLEProbeApp: App {
    var body: some Scene {
        WindowGroup { ProbeView() }
    }
}

struct NearbyDevice: Identifiable {
    let peripheral: CBPeripheral
    let name: String
    let rssi: Int
    let services: [CBUUID]
    let serviceData: [CBUUID: Data]
    let manufacturerData: Data?
    let connectable: Bool?
    var id: UUID { peripheral.identifier }
    var advertisesXiaomiService: Bool { services.contains(CBUUID(string: "FE95")) || serviceData[CBUUID(string: "FE95")] != nil }
}

// Default: read-only discovery. Explicit experimental modes can subscribe and
// negotiate/login; control mode adds explicit on/off with verified readback.
final class BluetoothProbe: NSObject, ObservableObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    static let shared = BluetoothProbe()
    @Published private(set) var devices: [NearbyDevice] = []
    @Published private(set) var status = "正在检查蓝牙状态"
    @Published private(set) var scanning = false
    @Published private(set) var inspecting = false
    private var diagnosticOperation: (id: String, source: String, started: TimeInterval)?

    private var diagnosticContext: String {
        let bundle = Bundle.main
        return "appVersion=\(bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") ?? "unknown") build=\(bundle.object(forInfoDictionaryKey: "CFBundleVersion") ?? "unknown") iOS=\(UIDevice.current.systemVersion) model=\(UIDevice.current.model)\nhubRunning=\(hubRunning) controlReady=\(controlReady) power=\(lastConfirmedPower.map(String.init) ?? "unknown")\n\(SnapControl.shared.diagnosticState)"
    }

    func exportDiagnostics(completion: @escaping (String) -> Void) {
        DiagnosticLog.shared.record("app", "diagnostics_exported")
        DiagnosticLog.shared.export(context: diagnosticContext, completion: completion)
    }

    @Published private(set) var selectedDeviceID: UUID?
    @Published private(set) var selectedDeviceMAC: String?
    @Published private(set) var lampIsOn: Bool?
    @Published private(set) var lastConfirmedPower: Bool?
    @Published private(set) var lastConfirmedAt: Date?
    @Published private(set) var controlReady = false
    @Published private(set) var savedForShortcuts = SavedLamp.load() != nil
    @Published private(set) var hubEnabled = UserDefaults.standard.bool(forKey: "LampBLEProbe.hubEnabled")
    @Published private(set) var hubRunning = false
    private var hubReconnect: DispatchWorkItem?
    private var hubRetryDelay: TimeInterval = 2
    private var controlSession: LampControlSession?
    private var earlyDataFrames: [(String, Data)] = []
    private(set) var backgroundOperation = false
    private var automationGoal: Bool?
    private var operationID: UUID?
    private var operationCompletion: ((Result<Bool, Error>) -> Void)?
    var canAcceptRelayOperation: Bool {
        !scanning && operationCompletion == nil && (!inspecting ||
            (controlReady && controlSession?.isReady == true && target?.state == .connected
             && target?.identifier == SavedLamp.load()?.id))
    }
    var hasControlConnection: Bool { controlSession != nil && target?.state == .connected }
    private var operationDeadline: DispatchWorkItem?
    private var pendingSavedStart = false
    private var mode: ProbeMode = .discovery
    private var versionText: String?
    private var matchedTarget = false
    private var authSession: MeshAuthSession?
    private var authCharacteristics: [String: CBCharacteristic] = [:]
    private var pendingNotifications: Set<String> = []
    private var authWriter: PacedAuthWriter?
    private var pendingAuthResult: String?
    private var central: CBCentralManager!
    private var target: CBPeripheral?
    private var pendingServices = 0
    private var usesShortcutDiscovery: Bool { backgroundOperation && mode == .control }
    private let shortcutServiceUUID = CBUUID(string: "FE95")
    private let shortcutCharacteristicUUIDs = ["0004", "0010", "0016", "001A", "001B"].map { CBUUID(string: $0) }
    private var readVersions = false
    private var readQueue: [CBCharacteristic] = []
    private var activeRead: CBCharacteristic?
    private var deadline: DispatchWorkItem?

    override init() {
        super.init()
        DiagnosticLog.shared.record("app", "launch")
        central = CBCentralManager(delegate: self, queue: .main)
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        DiagnosticLog.shared.record("bluetooth", "state", detail: "value=\(central.state.rawValue)")
        switch central.state {
        case .poweredOn: status = "蓝牙已就绪，点击扫描"
        case .poweredOff: status = "请在设置中打开蓝牙"
        case .unauthorized: status = "请在设置 → 隐私与安全性 → 蓝牙中允许此 App"
        case .unsupported: status = "此设备不支持蓝牙低功耗，请使用真实 iPhone"
        case .resetting: status = "蓝牙正在重置，请稍后再试"
        case .unknown: status = "正在检查蓝牙状态"
        @unknown default: status = "未知蓝牙状态"
        }
        if central.state == .poweredOn, pendingSavedStart { startSavedConnection(); return }
        if backgroundOperation, pendingSavedStart, central.state == .unknown || central.state == .resetting { return }
        if central.state == .poweredOn, hubRunning, !inspecting { scheduleHubReconnect() }
        if central.state != .poweredOn {
            if hubRunning { finish(error: "蓝牙未就绪") } else { stop() }
        }
    }

    func scan() {
        guard central.state == .poweredOn, !inspecting else { return }
        stop()
        devices = []
        scanning = true
        status = "扫描中，请根据名称和米家设备信息核对目标灯"
        central.scanForPeripherals(withServices: nil, options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
        let work = DispatchWorkItem { [weak self] in
            guard let self = self, self.scanning else { return }
            self.central.stopScan()
            self.scanning = false
            self.status = "扫描结束，共发现 \(self.devices.count) 个设备"
        }
        deadline = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 12, execute: work)
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard scanning else { return }
        let device = NearbyDevice(
            peripheral: peripheral,
            name: advertisementData[CBAdvertisementDataLocalNameKey] as? String ?? peripheral.name ?? "未命名设备",
            rssi: RSSI.intValue,
            services: advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID] ?? [],
            serviceData: advertisementData[CBAdvertisementDataServiceDataKey] as? [CBUUID: Data] ?? [:],
            manufacturerData: advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data,
            connectable: (advertisementData[CBAdvertisementDataIsConnectable] as? NSNumber)?.boolValue
        )
        if let index = devices.firstIndex(where: { $0.id == device.id }) { devices[index] = device }
        else { devices.append(device) }
        devices.sort {
            if $0.advertisesXiaomiService != $1.advertisesXiaomiService { return $0.advertisesXiaomiService }
            return $0.rssi > $1.rssi
        }
    }

    func inspect(_ device: NearbyDevice, readVersions: Bool, mode: ProbeMode = .discovery) {
        guard central.state == .poweredOn, !inspecting else { return }
        if !backgroundOperation { stop(); automationGoal = nil }
        else { central.stopScan(); deadline?.cancel() }
        controlReady = false
        lampIsOn = nil
        inspecting = true
        selectedDeviceID = device.id
        self.mode = mode
        versionText = nil
        let beacon = Array(device.serviceData[CBUUID(string: "FE95")] ?? Data())
        selectedDeviceMAC = beacon.count >= 11 && beacon[0] & 0x10 != 0
            ? beacon[5...10].reversed().map { String(format: "%02X", $0) }.joined() : nil
        var pid = beacon.count >= 4 ? Int(beacon[2]) | Int(beacon[3]) << 8 : -1
        matchedTarget = device.name == "shhf.light.slcwb8" && pid == 14136
        if backgroundOperation, let saved = SavedLamp.load(), saved.id == device.id {
            pid = 14136
            matchedTarget = true
            selectedDeviceMAC = saved.mac
        }
        target = device.peripheral
        target?.delegate = self
        pendingServices = 0
        self.readVersions = readVersions || mode != .discovery
        readQueue = []
        activeRead = nil
        append("Mode: \(mode.rawValue)")
        append("Product ID: \(pid)")
        append(backgroundOperation ? "Identity source: saved verified UUID; fresh advertisement unavailable" : "Identity source: selected advertisement")
        append("Mesh login previously verified on target firmware; current session must authenticate again.")
        append("Version reads enabled: \(self.readVersions)")
        append("iOS: \(UIDevice.current.systemVersion)")
        append("Time: \(ISO8601DateFormatter().string(from: Date()))")
        append("Expected model supplied by user: shhf.light.slcwb8 (NOT verified by this tool)")
        append("Name: \(device.name)")
        append("CoreBluetooth UUID (not MAC): \(device.id.uuidString)")
        append(backgroundOperation ? "RSSI: unavailable (saved UUID reconnect)" : "RSSI: \(device.rssi)")
        append("Connectable: \(device.connectable.map { String($0) } ?? "unknown")")
        append("Advertised services: \(device.services.map { $0.uuidString }.joined(separator: ", "))")
        if let data = device.manufacturerData { append("Manufacturer data: \(hex(data))") }
        for uuid in device.serviceData.keys.sorted(by: { $0.uuidString < $1.uuidString }) {
            if let data = device.serviceData[uuid] { append("Service data \(uuid.uuidString): \(hex(data))") }
        }
        status = backgroundOperation ? "正在连接已保存的灯" : "正在连接设备"
        central.connect(device.peripheral, options: nil)
        armDiscoveryDeadline(stage: "connection", peripheral: device.peripheral)
    }

    private func armDiscoveryDeadline(stage: String, peripheral: CBPeripheral) {
        deadline?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self = self, self.inspecting, self.target === peripheral else { return }
            self.append("TIMEOUT: \(stage) did not finish within 20 seconds")
            self.finish()
        }
        deadline = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 20, execute: work)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard inspecting, peripheral === target else { return }
        append("Connected. This does NOT prove Xiaomi application authentication.")
        status = "已连接，正在发现 GATT 服务"
        armDiscoveryDeadline(stage: "GATT discovery", peripheral: peripheral)
        append(usesShortcutDiscovery ? "Shortcut discovery: FE95 only; firmware check retained" : "Full diagnostic discovery")
        peripheral.discoverServices(usesShortcutDiscovery ? [shortcutServiceUUID] : nil)
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard inspecting, peripheral === target else { return }
        if let error = error { append("Service discovery error: \(error.localizedDescription)"); finish(); return }
        // CoreBluetooth may retain services from an earlier full diagnosis.
        // Filter the returned cache as well as the discovery request.
        let services = (peripheral.services ?? []).filter { !usesShortcutDiscovery || $0.uuid == shortcutServiceUUID }
        pendingServices = services.count
        append("GATT services: \(services.count)")
        guard !services.isEmpty else { finish(); return }
        for service in services {
            append("SERVICE \(service.uuid.uuidString)")
            peripheral.discoverCharacteristics(usesShortcutDiscovery ? shortcutCharacteristicUUIDs : nil, for: service)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard inspecting, peripheral === target else { return }
        guard !usesShortcutDiscovery || service.uuid == shortcutServiceUUID else { return }
        if let error = error { append("Characteristics \(service.uuid.uuidString): ERROR \(error.localizedDescription)") }
        else {
            for characteristic in service.characteristics ?? [] {
                // Cached characteristics can also include unrelated values.
                if usesShortcutDiscovery && !shortcutCharacteristicUUIDs.contains(characteristic.uuid) { continue }
                append("  \(service.uuid.uuidString) / \(characteristic.uuid.uuidString) [\(propertyNames(characteristic.properties))]")
                if service.uuid == CBUUID(string: "FE95"), ["0010", "0016", "001A", "001B"].contains(characteristic.uuid.uuidString) {
                    authCharacteristics[characteristic.uuid.uuidString] = characteristic
                }
                if self.readVersions, characteristic.properties.contains(.read), isVersionCharacteristic(characteristic) {
                    readQueue.append(characteristic)
                }
            }
        }
        pendingServices -= 1
        if pendingServices == 0 {
            append("Discovery finished. No login or light control attempted.")
            if self.readVersions { readNextVersion() }
            else { append("No values read or written."); finish() }
        }
    }

    // UUID meanings vary between Xiaomi generations. Keep FE95/0004 raw;
    // a returned value alone does not identify the authentication protocol.
    private func isVersionCharacteristic(_ characteristic: CBCharacteristic) -> Bool {
        guard let service = characteristic.service else { return false }
        if service.uuid == CBUUID(string: "FE95") {
            return characteristic.uuid == CBUUID(string: "0004")
        }
        let deviceInfo = ["2A24", "2A26", "2A27", "2A28", "2A29"].map { CBUUID(string: $0) }
        return service.uuid == CBUUID(string: "180A") && deviceInfo.contains(characteristic.uuid)
    }

    private func readNextVersion() {
        deadline?.cancel()
        deadline = nil
        activeRead = nil
        guard inspecting, let target = target else { return }
        guard !readQueue.isEmpty else {
            append("Version reads finished.")
            if mode == .discovery {
                append("No characteristic writes, subscriptions, login or light control attempted.")
                finish()
                } else { beginAuthExperiment() }
            return
        }
        let characteristic = readQueue.removeFirst()
        activeRead = characteristic
        let path = "\(characteristic.service?.uuid.uuidString ?? "?") / \(characteristic.uuid.uuidString)"
        status = "正在只读采集版本信息：\(path)"
        append("READ requested: \(path)")
        let work = DispatchWorkItem { [weak self] in
            guard let self = self, self.inspecting, self.activeRead === characteristic else { return }
            self.append("READ timeout: \(path). Ending diagnosis to avoid overlapping requests.")
            self.finish()
        }
        deadline = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 8, execute: work)
        target.readValue(for: characteristic)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard inspecting, peripheral === target else { return }
        if let session = authSession {
            guard authCharacteristics[characteristic.uuid.uuidString] === characteristic else { return }
            if let error = error { append("AUTH notify failed: \(error.localizedDescription)"); finish(); return }
            guard let data = characteristic.value else { return }
            append("AUTH RX \(characteristic.uuid.uuidString): \(AuthFrameLog.summary(channel: characteristic.uuid.uuidString, data: data))")
            if let control = controlSession {
                if ["001A", "001B"].contains(characteristic.uuid.uuidString) {
                    control.receive(channel: characteristic.uuid.uuidString, data: data)
                } else if characteristic.uuid == CBUUID(string: "0010"), data == Data([0x52,0,0,0]) {
                    append("Device revoked login during control"); finish(error: "设备拒绝了当前会话")
                }
            } else if ["0010", "0016"].contains(characteristic.uuid.uuidString) {
                session.receive(channel: characteristic.uuid.uuidString, data: data)
            } else if mode == .control {
                guard earlyDataFrames.count < 64,
                      earlyDataFrames.reduce(data.count, { $0 + $1.1.count }) <= 16384 else {
                    finish(error: "登录前收到的数据过多，已停止")
                    return
                }
                earlyDataFrames.append((characteristic.uuid.uuidString, data))
                append("Data notification buffered until login is explicitly accepted")
            }
            return
        }
        guard characteristic === activeRead else { return }
        let path = "\(characteristic.service?.uuid.uuidString ?? "?") / \(characteristic.uuid.uuidString)"
        if let error = error as NSError? {
            append("READ error \(path): domain=\(error.domain) code=\(error.code) \(error.localizedDescription)")
        } else if let data = characteristic.value {
            append("READ value \(path): \(hex(data)) (\(data.count) bytes)")
            let unpadded = Data(data.prefix { $0 != 0 })
            if let value = String(data: unpadded, encoding: .utf8), !value.isEmpty,
               value.unicodeScalars.allSatisfy({ $0.value >= 32 && $0.value < 127 }) {
                append("  ASCII: \(value)")
                if characteristic.service?.uuid == CBUUID(string: "FE95"), characteristic.uuid == CBUUID(string: "0004") {
                    versionText = value
                }
            }
        } else {
            append("READ value \(path): nil")
        }
        readNextVersion()
    }

    private func beginAuthExperiment() {
        guard matchedTarget, versionText == "2.1.2_0004", let target = target else {
            append("AUTH BLOCKED: requires target name, PID 14136 and verified version 2.1.2_0004. No auth writes sent.")
            finish(); return
        }
        let channels = mode == .control ? ["0010", "0016", "001A", "001B"] : ["0010", "0016"]
        for id in channels {
            guard let c = authCharacteristics[id], c.properties.contains(.notify), c.properties.contains(.writeWithoutResponse) else {
                append("AUTH BLOCKED: required characteristic/properties missing: \(id)"); finish(); return
            }
        }
        let key: Data?
        do { key = mode.requiresCredential ? try MeshKeyStore.load(target.identifier) : nil }
        catch { append("AUTH BLOCKED: local Keychain credential unavailable"); finish(); return }
        if mode.requiresCredential && key == nil {
            append("AUTH BLOCKED: import this device's 32-byte gatt_ltmk locally first. No credential requested over chat.")
            finish(); return
        }
        let session = MeshAuthSession(maximumWriteLength: target.maximumWriteValueLength(for: .withoutResponse),
                                      login: mode.requiresCredential, ltmk: key)
        authSession = session
        let writer = PacedAuthWriter()
        authWriter = writer
        writer.canSend = { [weak self] in
            guard let self = self else { return false }
            return self.inspecting && self.target?.canSendWriteWithoutResponse == true
        }
        writer.submit = { [weak self] id, data in
            guard let self = self, self.inspecting, let target = self.target, let c = self.authCharacteristics[id] else { return }
            self.append("AUTH TX \(id): \(AuthFrameLog.summary(channel: id, data: data))")
            target.writeValue(data, for: c, type: .withoutResponse)
            if id != "001B" { self.armAuthDeadline() }
        }
        writer.drained = { [weak self] in self?.completeAuthAfterDraining() }
        append("iOS write limit: \(target.maximumWriteValueLength(for: .withoutResponse)) bytes; paced authentication writes enabled")
        session.write = { [weak self] id, data, gap in self?.enqueueAuthWrite(id: id, data: data, minimumGap: gap) }
        session.progress = { [weak self] message in
            guard let self = self, self.inspecting else { return }
            self.status = "认证实验进行中，请保持前台"
            self.append("AUTH: " + message)
            self.armAuthDeadline()
        }
        session.completion = { [weak self] result in
            guard let self = self else { return }
            if self.authSession?.observedExpectedResponse == true {
                if self.mode == .control, let key = self.authSession?.derivedSessionKey {
                    self.append(result)
                    self.beginLampControl(key: key)
                    return
                }
                self.pendingAuthResult = result
                self.completeAuthAfterDraining()
                return
            }
            self.append(result)
            self.append("No registration, reset, light control or property reads attempted. Disconnecting after experiment.")
            self.finish()
        }
        pendingNotifications = Set(channels)
        status = "正在订阅认证通道通知"
        armAuthDeadline()
        for id in channels { target.setNotifyValue(true, for: authCharacteristics[id]!) }
    }

    private func beginLampControl(key: Data) {
        guard let target = target else { finish(error: "蓝牙连接已断开"); return }
        do {
            let control = try LampControlSession(key: key, writeLimit: target.maximumWriteValueLength(for: .withoutResponse), desired: automationGoal)
            controlSession = control
            control.write = { [weak self] id, data in self?.enqueueAuthWrite(id: id, data: data, minimumGap: 0) }
            control.progress = { [weak self] message in
                guard let self = self else { return }
                self.append(message)
                self.status = "正在验证灯具状态，请保持连接"
                self.armAuthDeadline()
            }
            control.metadata = { [weak self] in self?.append($0) }
            control.failure = { [weak self] message in
                guard let self = self else { return }
                self.append("CONTROL STOP: " + message)
                self.finish(error: "操作未确认：" + message)
                self.status = "操作未确认，请查看报告"
            }
            control.verified = { [weak self, weak control] value, requested, wrote in
                guard let self = self, let control = control else { return }
                self.completeDiagnosticOperation(power: value, error: nil)
                self.lampIsOn = value
                self.lastConfirmedPower = value
                self.lastConfirmedAt = Date()
                self.controlReady = true
                self.status = requested == nil ? "开关状态已读回" : "指令已确认，回读为" + (value ? "开启" : "关闭")
                self.append("STATE VERIFIED: siid=2 piid=1 on=\(value); requested=\(requested.map(String.init) ?? "none"); propertyWriteSent=\(wrote)")
                self.deadline?.cancel()
                if self.hubRunning {
                    self.hubRetryDelay = 2
                    self.operationDeadline?.cancel(); self.operationDeadline = nil
                    self.operationID = nil
                    self.automationGoal = nil
                    self.backgroundOperation = false
                    let completion = self.operationCompletion
                    self.operationCompletion = nil
                    self.append("HUB session retained; ready for next operation")
                    completion?(.success(value))
                } else if self.backgroundOperation {
                    let completion = self.operationCompletion
                    self.operationCompletion = nil
                    self.finish()
                    completion?(.success(value))
                } else {
                    let work = DispatchWorkItem { [weak self, weak control] in
                        guard let self = self, let control = control, self.controlSession === control, control.isReady else { return }
                        self.append("Idle connection closed after 120 seconds; last verified state retained")
                        self.finish()
                    }
                    self.deadline = work
                    DispatchQueue.main.asyncAfter(deadline: .now() + 120, execute: work)
                }
            }
            // All data notifications were subscribed before login. Start F0
            // synchronously in the 0x51 callback, with no post-login sleep.
            append("Login accepted; starting encrypted F0 immediately")
            control.start()
            let buffered = earlyDataFrames
            earlyDataFrames = []
            for (id, data) in buffered { control.receive(channel: id, data: data) }
        } catch { append("CONTROL STOP: session initialization failed"); finish(error: "加密会话初始化失败") }
    }

    @discardableResult
    func setLampOn(_ value: Bool, source: String = "manual", diagnosticID: String = UUID().uuidString) -> Bool {
        guard controlReady, let control = controlSession, control.isReady else {
            DiagnosticLog.shared.record("control", "ignored", level: .warning, detail: "id=\(diagnosticID) source=\(source) reason=not_ready")
            return false
        }
        beginDiagnosticOperation(id: diagnosticID, source: source, desired: value)
        controlReady = false
        status = value ? "正在开灯并验证状态" : "正在关灯并验证状态"
        append(value ? "USER requested explicit ON" : "USER requested explicit OFF")
        control.setOn(value)
        return true
    }

    func refreshLamp() {
        guard controlReady, let control = controlSession, control.isReady else { return }
        controlReady = false
        control.refresh()
    }

    func saveShortcutTarget() {
        guard controlReady, let id = selectedDeviceID, let mac = selectedDeviceMAC else { return }
        do {
            try MeshKeyStore.allowBackgroundAccess(id)
            let saved = SavedLamp(id: id, mac: mac, model: "shhf.light.slcwb8", firmware: "2.1.2_0004")
            try saved.save()
            savedForShortcuts = true
            append("Shortcut target saved. Device key remains in this iPhone's Keychain; lock-screen execution pending real-device verification.")
            status = "快捷指令目标灯已保存"
        } catch { status = "保存失败，请保持手机解锁后重试" }
    }

    @MainActor
    func performSavedOperation(desired: Bool, source: String = "shortcut") async throws -> Bool {
        guard let saved = SavedLamp.load() else { throw LampOperationError(message: "请先在 App 中连接灯并点击“设为快捷指令控制的灯”") }
        let reuse = hubRunning && inspecting && target?.state == .connected
            && target?.identifier == saved.id && controlSession?.isReady == true && controlReady
        guard (!inspecting || reuse), !scanning, operationCompletion == nil else { throw LampOperationError(message: "灯具正忙，请稍后重试") }
        try Task.checkCancellation()
        hubReconnect?.cancel(); hubReconnect = nil
        if hubEnabled { hubRunning = true }
        let callID = UUID()
        operationID = callID
        beginDiagnosticOperation(id: callID.uuidString, source: source, desired: desired)
        return try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Bool, Error>) in
                operationCompletion = { continuation.resume(with: $0) }
                append(reuse ? "SHORTCUT reusing authenticated HUB session" : "Waiting for Bluetooth to reconnect the user-saved target")
                backgroundOperation = true
                automationGoal = desired
                pendingSavedStart = !reuse
                let timeout = DispatchWorkItem { [weak self] in
                    guard let self = self, self.operationID == callID else { return }
                    self.append("SHORTCUT timeout after 25 seconds; no confirmed result")
                    self.finish(error: "25 秒内未完成操作。请确认手机已在灯的蓝牙范围内；指令未确认")
                }
                operationDeadline = timeout
                DispatchQueue.main.asyncAfter(deadline: .now() + 25, execute: timeout)
                if Task.isCancelled { finish(error: "快捷指令已取消") }
                else if reuse {
                    deadline?.cancel(); deadline = nil
                    setLampOn(desired, source: source, diagnosticID: callID.uuidString)
                }
                else if central.state == .poweredOn { startSavedConnection() }
                else if central.state != .unknown && central.state != .resetting { finish(error: "蓝牙未就绪或尚未授权") }
            }
        }, onCancel: { [weak self] in
            Task { @MainActor in
                guard let self = self, self.operationID == callID else { return }
                self.finish(error: "快捷指令已取消；未确认操作结果")
            }
        })
    }

    private func startSavedConnection() {
        guard pendingSavedStart, let saved = SavedLamp.load() else { return }
        pendingSavedStart = false
        guard let peripheral = central.retrievePeripherals(withIdentifiers: [saved.id]).first else {
            finish(error: "系统未找到已保存的灯，请先打开 App 重新扫描并保存目标")
            return
        }
        let device = NearbyDevice(peripheral: peripheral, name: saved.model, rssi: 127,
                                  services: [], serviceData: [:], manufacturerData: nil, connectable: nil)
        inspect(device, readVersions: true, mode: .control)
        append("Saved UUID connection; goal=\(automationGoal.map { $0 ? "ON" : "OFF" } ?? "read only")")
    }

    func setHubEnabled(_ enabled: Bool) {
        guard !enabled || SavedLamp.load() != nil else {
            status = "请先保存快捷指令目标灯"; return
        }
        guard !enabled || !inspecting || (controlReady && target?.identifier == SavedLamp.load()?.id) else {
            status = "请先停止当前诊断再启用中枢"; return
        }
        hubEnabled = enabled
        UserDefaults.standard.set(enabled, forKey: "LampBLEProbe.hubEnabled")
        if enabled { startHub() } else { stop() }
    }

    func startHub() {
        guard hubEnabled, !scanning, operationCompletion == nil else { return }
        hubRunning = true
        if inspecting {
            if controlSession?.isReady == true {
                deadline?.cancel(); deadline = nil
                status = "中枢已连接，保留认证会话"
            }
            return
        }
        hubReconnect?.cancel(); hubReconnect = nil
        backgroundOperation = true
        automationGoal = nil
        pendingSavedStart = true
        if central.state == .poweredOn { startSavedConnection() }
        else { status = "中枢等待蓝牙就绪" }
    }

    private func scheduleHubReconnect() {
        guard hubRunning, !inspecting, central.state == .poweredOn, SavedLamp.load() != nil else { return }
        hubReconnect?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self = self, self.hubRunning else { return }
            self.startHub()
        }
        hubReconnect = work
        status = "中枢连接中断，将自动重连"
        DispatchQueue.main.asyncAfter(deadline: .now() + hubRetryDelay, execute: work)
        hubRetryDelay = min(30, hubRetryDelay * 2)
    }

    func enteredBackground() {
        if !backgroundOperation && !hubRunning { stop() }
    }

    private func armAuthDeadline() {
        deadline?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self = self, self.inspecting, let session = self.authSession else { return }
            if let control = self.controlSession {
                control.timeout()
            } else if self.pendingAuthResult != nil {
                self.append("AUTH STOP: outgoing queue did not drain; final echo delivery not established")
                self.finish()
            } else if !self.pendingNotifications.isEmpty {
                self.append("AUTH STOP: notification subscription timeout")
                self.finish()
            } else { session.timeout() }
        }
        deadline = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 8, execute: work)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        guard inspecting, peripheral === target, authSession != nil,
              authCharacteristics[characteristic.uuid.uuidString] === characteristic,
              pendingNotifications.contains(characteristic.uuid.uuidString) else { return }
        guard error == nil, characteristic.isNotifying else {
            append("AUTH STOP: notification subscription failed for \(characteristic.uuid.uuidString)")
            finish(); return
        }
        pendingNotifications.remove(characteristic.uuid.uuidString)
        append("AUTH notify enabled: \(characteristic.uuid.uuidString)")
        if pendingNotifications.isEmpty { authSession?.start() }
    }

    private func enqueueAuthWrite(id: String, data: Data, minimumGap: TimeInterval) {
        guard inspecting, let target = target, authCharacteristics[id] != nil, authSession != nil else { return }
        guard data.count <= target.maximumWriteValueLength(for: .withoutResponse) else {
            append("AUTH STOP: frame exceeds negotiated iOS write limit"); finish(); return
        }
        authWriter?.enqueue(channel: id, data: data, minimumGap: minimumGap)
    }

    private func completeAuthAfterDraining() {
        guard let result = pendingAuthResult, authWriter?.isEmpty == true, let session = authSession else { return }
        pendingAuthResult = nil
        // Give CoreBluetooth the final no-response echo before disconnecting.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
            guard let self = self, self.authSession === session, self.inspecting else { return }
            self.append(result)
            self.append("No registration, reset, light control or property reads attempted. Disconnecting after experiment.")
            self.finish()
        }
    }

    func peripheralIsReady(toSendWriteWithoutResponse peripheral: CBPeripheral) {
        guard peripheral === target else { return }
        authWriter?.drain()
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        guard peripheral === target else { return }
        append("Connection failed: \(error?.localizedDescription ?? "unknown error")")
        finish()
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        guard peripheral === target else { return }
        append("Disconnected: \(error?.localizedDescription ?? "no error")")
        finish()
    }

    func stop() {
        hubRunning = false
        hubReconnect?.cancel(); hubReconnect = nil
        deadline?.cancel()
        deadline = nil
        central.stopScan()
        scanning = false
        if inspecting { append("Stopped by user or app leaving foreground") }
        finish()
    }

    private func finish(error: String? = nil) {
        completeDiagnosticOperation(power: nil, error: error ?? "操作结束但未确认")
        let completion = operationCompletion
        operationCompletion = nil
        operationDeadline?.cancel(); operationDeadline = nil
        pendingSavedStart = false
        backgroundOperation = false
        automationGoal = nil
        operationID = nil
        controlSession?.cancel(); controlSession = nil
        earlyDataFrames = []
        controlReady = false
        authSession?.cancel()
        authSession = nil
        pendingNotifications = []
        authCharacteristics = [:]
        authWriter?.cancel()
        authWriter = nil
        pendingAuthResult = nil
        readQueue = []
        activeRead = nil
        deadline?.cancel()
        deadline = nil
        if let target = target {
            target.delegate = nil
            self.target = nil
            central.cancelPeripheralConnection(target)
        }
        if inspecting { status = "诊断已结束，请查看并分享报告" }
        inspecting = false
        completion?(.failure(LampOperationError(message: error ?? "操作未完成，未确认灯具状态；请查看诊断报告")))
        scheduleHubReconnect()
    }

    private func beginDiagnosticOperation(id: String, source: String, desired: Bool) {
        guard diagnosticOperation?.id != id else { return }
        diagnosticOperation = (id, source, ProcessInfo.processInfo.systemUptime)
        DiagnosticLog.shared.record("control", "operation_started", detail: "id=\(id) source=\(source) target=\(desired)")
    }

    private func completeDiagnosticOperation(power: Bool?, error: String?) {
        guard let operation = diagnosticOperation else { return }
        diagnosticOperation = nil
        let elapsed = ProcessInfo.processInfo.systemUptime - operation.started
        DiagnosticLog.shared.record("control", error == nil ? "operation_verified" : "operation_failed",
                                    level: error == nil ? .info : .error,
                                    detail: "id=\(operation.id) source=\(operation.source) duration=\(elapsed) power=\(power.map(String.init) ?? "unknown") reason=\(error ?? "none")")
        if operation.source == "snap" {
            SnapControl.shared.operationCompleted(id: operation.id, power: power, error: error)
        }
    }

    private func append(_ line: String) {
        DiagnosticLog.shared.record("bluetooth", "protocol", level: line.contains("STOP") || line.contains("timeout") ? .error : .debug, detail: line)
    }

    private func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    private func propertyNames(_ properties: CBCharacteristicProperties) -> String {
        let names: [(CBCharacteristicProperties, String)] = [
            (.read, "read"), (.write, "write"), (.writeWithoutResponse, "writeWithoutResponse"),
            (.notify, "notify"), (.indicate, "indicate"), (.authenticatedSignedWrites, "signedWrites"),
            (.extendedProperties, "extended"), (.broadcast, "broadcast"),
            (.notifyEncryptionRequired, "notifyEncryptionRequired"), (.indicateEncryptionRequired, "indicateEncryptionRequired")
        ]
        return names.filter { properties.contains($0.0) }.map { $0.1 }.joined(separator: ", ")
    }
}

struct ReportDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.plainText] }
    let text: String

    init(text: String) { self.text = text }

    init(configuration: ReadConfiguration) throws {
        guard let data = configuration.file.regularFileContents,
              let text = String(data: data, encoding: .utf8) else {
            throw CocoaError(.fileReadCorruptFile)
        }
        self.text = text
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: Data(text.utf8))
    }
}

struct SharedReport: Identifiable {
    let id = UUID()
    let url: URL
}

struct ReportShareSheet: UIViewControllerRepresentable {
    let url: URL

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: [url], applicationActivities: nil)
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}

// Frontmost, fully opaque curtain covers settings sheets too. It never becomes
// key, and its touch-up action consumes the wake gesture before it disappears.
@MainActor
private final class HubStandbyController: UIViewController {
    var wake: (() -> Void)?
    override var prefersStatusBarHidden: Bool { true }
    override var prefersHomeIndicatorAutoHidden: Bool { true }

    override func loadView() {
        let surface = UIControl()
        surface.backgroundColor = .black
        surface.isOpaque = true
        surface.isAccessibilityElement = true
        surface.accessibilityLabel = "中枢省电待机，轻点唤醒"
        surface.accessibilityTraits = .button
        surface.addTarget(self, action: #selector(wakeFromTouch), for: .touchUpInside)
        view = surface
    }

    @objc private func wakeFromTouch() { wake?() }
}

// Own brightness and automatic sleep only while this app scene is active.
@MainActor
final class HubIdleBrightness: ObservableObject {
    @Published private(set) var isStandby = false
    private weak var appWindow: UIWindow?
    private var curtain: UIWindow?
    private var screen: UIScreen?
    private var normalBrightness: CGFloat?
    private var previousIdleTimerDisabled: Bool?
    private var dimTimer: DispatchSourceTimer?
    private var activityGeneration: UInt64 = 0
    private let displayLog = Logger(subsystem: Bundle.main.bundleIdentifier ?? "LampBLEProbe", category: "HubDisplay")

    func activate(window: UIWindow) {
        guard screen == nil, let scene = window.windowScene else { return }
        appWindow = window
        screen = scene.screen
        normalBrightness = scene.screen.brightness
        previousIdleTimerDisabled = UIApplication.shared.isIdleTimerDisabled
        UIApplication.shared.isIdleTimerDisabled = true
        touched()
    }

    func touched() {
        guard let screen else { return }
        dimTimer?.cancel()
        activityGeneration &+= 1
        let generation = activityGeneration
        let activityTime = DispatchTime.now()
        if isStandby {
            removeCurtain()
            screen.brightness = normalBrightness ?? screen.brightness
            isStandby = false
            displayLog.info("Standby ended by wake touch")
        } else {
            normalBrightness = screen.brightness
        }
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: activityTime + .seconds(60), leeway: .milliseconds(50))
        timer.setEventHandler { [weak self] in
            MainActor.assumeIsolated {
                guard let self, self.activityGeneration == generation,
                      let screen = self.screen, let window = self.appWindow,
                      let scene = window.windowScene else { return }
                let elapsed = Double(DispatchTime.now().uptimeNanoseconds - activityTime.uptimeNanoseconds) / 1_000_000_000
                // End editing before covering the window so the keyboard cannot
                // remain above the curtain. Text entered in fields is preserved.
                window.endEditing(true)
                let controller = HubStandbyController()
                controller.wake = { [weak self] in self?.touched() }
                let curtain = UIWindow(windowScene: scene)
                curtain.frame = scene.coordinateSpace.bounds
                curtain.windowLevel = .alert + 1
                curtain.backgroundColor = .black
                curtain.isOpaque = true
                curtain.rootViewController = controller
                self.curtain = curtain
                curtain.isHidden = false
                self.normalBrightness = screen.brightness
                screen.brightness = 0
                self.isStandby = true
                self.dimTimer?.cancel()
                self.dimTimer = nil
                self.displayLog.info("Black standby entered; idle seconds: \(elapsed, privacy: .public)")
            }
        }
        dimTimer = timer
        displayLog.debug("Black standby deadline armed: 60 seconds")
        timer.resume()
    }

    func deactivate() {
        activityGeneration &+= 1
        dimTimer?.cancel()
        dimTimer = nil
        removeCurtain()
        if isStandby, let normalBrightness { screen?.brightness = normalBrightness }
        if isStandby { isStandby = false }
        if let previousIdleTimerDisabled {
            UIApplication.shared.isIdleTimerDisabled = previousIdleTimerDisabled
        }
        previousIdleTimerDisabled = nil
        appWindow = nil
        screen = nil
        normalBrightness = nil
    }

    private func removeCurtain() {
        curtain?.isHidden = true
        curtain?.rootViewController = nil
        curtain = nil
    }
}

// Bluetooth/cloud still process every event; hidden dashboard redraws are skipped.
@MainActor
private final class HubDashboardUpdates: ObservableObject {
    @Published private(set) var revision: UInt64 = 0
    var paused = false
    private var subscription: AnyCancellable?

    func observe(probe: BluetoothProbe, relay: LampRelay) {
        guard subscription == nil else { return }
        subscription = probe.objectWillChange.merge(with: relay.objectWillChange)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                guard let self, !self.paused else { return }
                self.revision &+= 1
            }
    }
}

// Observe touch-down at the window so buttons, scrolling and presented sheets
// all count as activity. Fail immediately so ordinary controls keep the touch.
private final class HubTouchRecognizer: UIGestureRecognizer {
    var activity: (() -> Void)?
    override func canPrevent(_ preventedGestureRecognizer: UIGestureRecognizer) -> Bool { false }
    override func canBePrevented(by preventingGestureRecognizer: UIGestureRecognizer) -> Bool { false }
    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent) {
        activity?()
        state = .failed
    }
}

private struct HubTouchObserver: UIViewRepresentable {
    let brightness: HubIdleBrightness
    let active: Bool
    final class ObserverView: UIView {
        let touch = HubTouchRecognizer()
        weak var observedWindow: UIWindow?
        var brightness: HubIdleBrightness?
        var active = false
        private var activityRevision: UInt64 = 0
        private var needsDeactivate = false
        private var dismantled = false
        override func didMoveToWindow() {
            super.didMoveToWindow()
            if observedWindow !== window {
                observedWindow?.removeGestureRecognizer(touch)
                needsDeactivate = true
                observedWindow = window
                touch.cancelsTouchesInView = false
                touch.delaysTouchesBegan = false
                touch.delaysTouchesEnded = false
                window?.addGestureRecognizer(touch)
            }
            updateActivity()
        }
        func updateActivity() {
            // UIKit invokes this during SwiftUI reconciliation. Publish only
            // after that pass, coalescing rapid window/scene changes.
            activityRevision &+= 1
            let revision = activityRevision
            DispatchQueue.main.async { [weak self] in
                guard let self, !self.dismantled, self.activityRevision == revision else { return }
                if self.needsDeactivate {
                    self.brightness?.deactivate()
                    self.needsDeactivate = false
                }
                if self.active, let window = self.window {
                    self.brightness?.activate(window: window)
                } else { self.brightness?.deactivate() }
            }
        }
        func dismantle() {
            dismantled = true
            activityRevision &+= 1
            observedWindow?.removeGestureRecognizer(touch)
            let controller = brightness
            DispatchQueue.main.async { controller?.deactivate() }
        }
    }
    func makeUIView(context: Context) -> ObserverView {
        let view = ObserverView()
        view.isUserInteractionEnabled = false
        view.brightness = brightness
        view.touch.activity = { [weak brightness] in brightness?.touched() }
        return view
    }
    func updateUIView(_ view: ObserverView, context: Context) {
        view.active = active
        view.updateActivity()
    }
    static func dismantleUIView(_ view: ObserverView, coordinator: ()) {
        view.dismantle()
    }
}

private enum HubPalette {
    static let accent = Color(red: 0.88, green: 0.73, blue: 0.49)
    static let card = Color(white: 0.065)
    static let muted = Color(white: 0.64)
}

struct ProbeView: View {
    private let probe = BluetoothProbe.shared
    private let relay = LampRelay.shared
    @StateObject private var brightness = HubIdleBrightness()
    @StateObject private var updates = HubDashboardUpdates()
    @Environment(\.scenePhase) private var phase
    @Environment(\.dynamicTypeSize) private var typeSize
    @State private var showingSettings = false

    private var busy: Bool { probe.hasControlConnection && !probe.controlReady }
    private var fullyReady: Bool { probe.controlReady && relay.connected && probe.hubRunning }
    private var summary: String {
        if busy { return "正在执行，请等待回读" }
        if fullyReady { return "中枢就绪" }
        if !probe.hubRunning { return "中枢已暂停" }
        if !relay.enabled { return "云端接收已关闭" }
        return "正在恢复连接"
    }
    private var bluetoothLabel: String {
        if busy { return "正在执行" }
        if probe.controlReady { return "已连接" }
        return probe.hubRunning ? "连接中" : "未连接"
    }

    var body: some View {
        NavigationStack {
            GeometryReader { geometry in
                let landscape = geometry.size.width > geometry.size.height && !typeSize.isAccessibilitySize
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        HStack(spacing: 8) {
                            Circle().fill(fullyReady ? HubPalette.accent : HubPalette.muted).frame(width: 6, height: 6)
                            Text(summary).font(.subheadline)
                            Spacer(minLength: 0)
                            Text("家庭中枢").font(.caption).foregroundStyle(HubPalette.muted)
                        }.padding(.horizontal, 2)
                        if landscape {
                            HStack(alignment: .top, spacing: 16) {
                                lampCard(compact: true).frame(maxWidth: .infinity)
                                statusPanel.frame(maxWidth: .infinity)
                            }
                        } else {
                            lampCard(compact: false)
                            statusPanel
                        }
                        HStack(spacing: 6) {
                            Image(systemName: "moon.zzz")
                            Text("闲置 1 分钟纯黑待机 · 轻触唤醒")
                        }.font(.caption).foregroundStyle(HubPalette.muted)
                            .frame(maxWidth: .infinity).padding(.vertical, 4)
                    }.padding(.horizontal, 18).padding(.vertical, 12)
                        .frame(maxWidth: landscape ? 1100 : 560).frame(maxWidth: .infinity)
                }
            }
            .background(Color.black)
            .navigationTitle("灯光中枢")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                Button { showingSettings = true } label: {
                    Image(systemName: "gearshape").frame(minWidth: 44, minHeight: 44)
                }.accessibilityLabel("中枢设置")
            }
        }
        .opacity(brightness.isStandby ? 0 : 1)
        .allowsHitTesting(!brightness.isStandby)
        .accessibilityHidden(brightness.isStandby)
        .statusBarHidden(brightness.isStandby)
        .tint(HubPalette.accent)
        .preferredColorScheme(.dark)
        .background(HubTouchObserver(brightness: brightness, active: phase == .active))
        .sheet(isPresented: $showingSettings) { HubSettingsView() }
        .onChange(of: brightness.isStandby) { _, standby in
            updates.paused = standby
        }
        .onChange(of: phase) { _, newPhase in
            DiagnosticLog.shared.record("app", "scene_changed", detail: "phase=\(String(describing: newPhase))")
            SnapControl.shared.setActive(newPhase == .active)
            if newPhase != .active {
                brightness.deactivate()
                probe.enteredBackground()
            }
        }
        .onAppear {
            SnapControl.shared.setActive(phase == .active)
            updates.observe(probe: probe, relay: relay)
            if probe.hubEnabled { probe.startHub() }
            relay.start()
        }
        .onDisappear { brightness.deactivate(); SnapControl.shared.setActive(false) }
    }

    private var statusPanel: some View {
        VStack(spacing: 14) {
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 12) { connectionCards }
                VStack(spacing: 12) { connectionCards }
            }
            automationCard
            if !probe.hubRunning || !relay.enabled { recoveryCard }
        }
    }

    private func lampCard(compact: Bool) -> some View {
        VStack(spacing: compact ? 12 : 20) {
            HStack {
                Text("家里的灯").font(.headline)
                Spacer()
                Button { probe.refreshLamp() } label: {
                    Image(systemName: "arrow.clockwise").frame(width: 44, height: 44)
                }.disabled(!probe.controlReady).accessibilityLabel("刷新灯具状态")
            }
            if compact {
                HStack(spacing: 20) {
                    lampButton
                    lampState
                }.frame(maxWidth: .infinity)
            } else {
                VStack(spacing: 16) {
                    lampButton
                    lampState
                }.frame(maxWidth: .infinity)
            }
            if !probe.controlReady {
                HStack(alignment: .top, spacing: 8) {
                    if probe.hubRunning && !brightness.isStandby { ProgressView().controlSize(.small) }
                    else { Image(systemName: "pause.circle") }
                    Text(busy ? "指令正在执行，完成回读后更新状态。" : probe.lastConfirmedAt == nil ? "等待蓝牙连接与验证。" : "连接尚未就绪，保留最近确认状态。")
                        .font(.footnote)
                }.foregroundStyle(HubPalette.muted).frame(maxWidth: .infinity, alignment: .leading)
            } else {
                Text(probe.lastConfirmedPower == true ? "轻触灯泡关灯" : "轻触灯泡开灯")
                    .font(.caption).foregroundStyle(HubPalette.muted)
            }
        }.padding(compact ? 16 : 24)
            .background(HubPalette.card, in: RoundedRectangle(cornerRadius: 26))
    }

    private var lampButton: some View {
        Button {
            guard probe.controlReady, let current = probe.lastConfirmedPower else { return }
            probe.setLampOn(!current)
        } label: {
            Image(systemName: probe.lastConfirmedPower == true ? "lightbulb.fill" : "lightbulb")
                .font(.system(size: 58, weight: .light))
                .foregroundStyle(probe.lastConfirmedPower == true ? HubPalette.accent : HubPalette.muted)
                .frame(width: 120, height: 120)
                .background(Circle().fill(HubPalette.accent.opacity(probe.lastConfirmedPower == true ? 0.13 : 0.035)))
                .overlay(Circle().strokeBorder(HubPalette.accent.opacity(probe.controlReady ? 0.3 : 0.08)))
                .contentShape(Circle())
        }.buttonStyle(.plain)
            .disabled(!probe.controlReady || probe.lastConfirmedPower == nil)
            .accessibilityLabel(probe.lastConfirmedPower == true ? "关灯" : "开灯")
            .accessibilityValue(probe.lastConfirmedPower.map { $0 ? "灯已开启" : "灯已关闭" } ?? "状态未确认")
            .accessibilityHint("切换灯具开关，完成回读后更新状态")
    }

    private var lampState: some View {
        VStack(spacing: 10) {
            Text(probe.lastConfirmedPower.map { $0 ? "已开启" : "已关闭" } ?? "等待确认")
                .font(.system(size: 36, weight: .medium, design: .rounded))
                .minimumScaleFactor(0.75).lineLimit(1)
            if let date = probe.lastConfirmedAt {
                VStack(spacing: 3) {
                    Text("最近回读确认")
                    Text(date, format: .dateTime.hour().minute().second())
                }.font(.caption).foregroundStyle(HubPalette.muted)
            } else {
                Text("连接后读取真实状态").font(.caption).foregroundStyle(HubPalette.muted)
            }
        }
    }

    @ViewBuilder private var connectionCards: some View {
        connection("蓝牙灯具", symbol: "antenna.radiowaves.left.and.right", value: bluetoothLabel,
                   detail: probe.controlReady ? "可直接控制" : busy ? "等待状态回读" : "等待认证会话", ready: probe.controlReady)
        connection("云端接收", symbol: "cloud", value: relay.connectionLabel,
                   detail: relay.connected ? "等待自动化请求" : relay.enabled ? "连接后自动接收" : "接收已关闭", ready: relay.connected)
    }

    private var automationCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label("最近自动化", systemImage: "bolt.horizontal.circle").font(.subheadline)
                Spacer()
                if let date = relay.lastResultAt {
                    Text(date, format: .dateTime.hour().minute()).font(.caption).foregroundStyle(HubPalette.muted)
                }
            }
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: relay.resultPhase.symbol)
                    .foregroundStyle(relay.resultPhase == .failed ? Color.orange : HubPalette.accent)
                Text(relay.lastResult).font(.subheadline.weight(.medium)).fixedSize(horizontal: false, vertical: true)
            }.accessibilityElement(children: .combine)
            Divider().overlay(Color.white.opacity(0.04))
            Text("连接家庭 Wi-Fi 开灯，断开后关灯。")
                .font(.caption).foregroundStyle(HubPalette.muted)
        }.padding(18).background(HubPalette.card, in: RoundedRectangle(cornerRadius: 22))
    }

    private var recoveryCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(!probe.savedForShortcuts ? "尚未保存目标灯" : !probe.hubRunning ? "中枢连接已暂停" : "云端接收已关闭")
                .font(.subheadline.weight(.medium))
            Text(!probe.savedForShortcuts ? "在设置的高级诊断中管理目标灯。" : "可在这里恢复日常运行。")
                .font(.footnote).foregroundStyle(HubPalette.muted)
            Button(!probe.savedForShortcuts ? "打开设置" : !probe.hubRunning ? "启动中枢" : "开启云端接收") {
                if !probe.savedForShortcuts { showingSettings = true }
                else if !probe.hubRunning {
                    if probe.hubEnabled { probe.startHub() } else { probe.setHubEnabled(true) }
                } else { relay.setEnabled(true) }
            }.buttonStyle(.bordered).disabled(probe.scanning || (probe.inspecting && !probe.controlReady && !probe.hubRunning))
        }.frame(maxWidth: .infinity, alignment: .leading).padding(18)
            .background(HubPalette.card, in: RoundedRectangle(cornerRadius: 22))
    }

    private func connection(_ title: String, symbol: String, value: String, detail: String, ready: Bool) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            Label(title, systemImage: symbol).font(.caption).foregroundStyle(HubPalette.muted)
            Label(value, systemImage: ready ? "checkmark.circle.fill" : "circle.dotted")
                .font(.subheadline.weight(.medium)).foregroundStyle(ready ? HubPalette.accent : HubPalette.muted)
                .fixedSize(horizontal: true, vertical: false)
            Text(detail).font(.caption2).foregroundStyle(HubPalette.muted).fixedSize(horizontal: true, vertical: false)
        }.frame(maxWidth: .infinity, alignment: .leading).padding(16)
            .background(HubPalette.card, in: RoundedRectangle(cornerRadius: 20))
            .accessibilityElement(children: .combine)
    }

}

struct HubSettingsView: View {
    @ObservedObject private var snap = SnapControl.shared
    @ObservedObject private var probe = BluetoothProbe.shared
    @ObservedObject private var relay = LampRelay.shared
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Toggle("常驻中枢", isOn: Binding(get: { probe.hubEnabled }, set: { probe.setHubEnabled($0) }))
                        .disabled(probe.scanning || (probe.inspecting && !probe.controlReady))
                    Toggle("接收云端请求", isOn: Binding(get: { relay.enabled }, set: { relay.setEnabled($0) }))
                        .disabled(!probe.hubEnabled)
                } header: { Text("日常运行") } footer: {
                    Text("中枢保留蓝牙认证会话，接收随身 iPhone 的家庭 Wi-Fi 自动化请求。")
                }
                Section {
                    Toggle("响指控制", isOn: Binding(get: { snap.enabled }, set: { snap.setEnabled($0) }))
                    LabeledContent("识别器", value: "Apple SoundAnalysis")
                    LabeledContent("触发方式", value: "单响指切换开关")
                    Text(snap.status).font(.footnote)
                    Text(snap.lastResult).font(.footnote).foregroundStyle(.secondary)
                } header: { Text("响指控制 · 实验功能") } footer: {
                    Text("使用 Apple 内置模型识别单响指，需中枢已连接。忙碌时忽略，触发后冷却 1.2 秒。仅前台监听，纯黑待机继续有效；不保存或上传声音。模型可能漏检或误识别，持续监听会增加耗电。灯具结果以主屏回读为准。")
                }
                Section("连接详情") {
                    Label(probe.status, systemImage: "antenna.radiowaves.left.and.right")
                    Label(relay.status, systemImage: "cloud")
                }.font(.footnote)
                Section {
                    LabeledContent("纯黑待机", value: "闲置 1 分钟")
                    LabeledContent("唤醒界面", value: "轻触屏幕")
                    Text("待机时全黑、最低亮度，保持 App 前台；首次轻触只唤醒。App 前台暂停自动锁屏，离开时恢复原亮度与自动锁屏行为。")
                        .font(.footnote).foregroundStyle(.secondary)
                } header: { Text("屏幕") }
                Section {
                    NavigationLink {
                        ProbeDiagnosticsView()
                    } label: {
                        Label("高级配置与诊断", systemImage: "wrench.and.screwdriver")
                    }
                } footer: {
                    Text("自动化凭据、目标灯管理和完整日志位于此处。已配置好的中枢无需重新配对。")
                }
                Section {
                    LabeledContent("版本", value: "0.7.2")
                    Text("锁屏与长期运行稳定性尚未单独验收。")
                        .font(.footnote).foregroundStyle(.secondary)
                }
            }
            .navigationTitle("中枢设置").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("完成") { dismiss() } } }
        }.tint(HubPalette.accent)
    }
}

struct ProbeDiagnosticsView: View {
    @StateObject private var probe = BluetoothProbe.shared
    @StateObject private var relay = LampRelay.shared
    @State private var showingRelaySetup = false
    @State private var readVersions = true
    @State private var mode: ProbeMode = .discovery
    @State private var editingKey = false
    @State private var sharedReport: SharedReport?
    @State private var temporaryReportURL: URL?
    @State private var exporting = false
    @State private var exportText = ""
    @State private var copied = false
    @State private var exportError: String?
    var body: some View {
        List {
                Section("到家开灯 · 离家关灯") {
                    Toggle("接收云端开关请求", isOn: Binding(get: { relay.enabled }, set: { relay.setEnabled($0) }))
                    Text(relay.status).font(.footnote)
                    Text(relay.lastResult).font(.footnote)
                    Button("配置随身 iPhone 的自动化") {
                        relay.prepareSetup()
                        showingRelaySetup = true
                    }
                    Text("通过 ntfy.sh 传递请求，不上传位置和蓝牙密钥。家庭 Wi-Fi 触发的两机联动已验收；此处用于管理现有配置。")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Section("常驻中枢") {
                    Toggle("常驻中枢模式", isOn: Binding(get: { probe.hubEnabled }, set: { probe.setHubEnabled($0) }))
                        .disabled(probe.scanning || (probe.inspecting && !probe.controlReady))
                    Text("供留在家中的手机使用：保留连接和认证会话，快捷指令复用连接。后台运行和长期稳定性仍需真机验证。")
                        .font(.footnote).foregroundStyle(.secondary)
                    if probe.hubEnabled {
                        Button(probe.hubRunning ? "中枢运行中" : "启动中枢连接") { probe.startHub() }
                            .disabled(probe.hubRunning || probe.inspecting || probe.scanning)
                    }
                }
                Section {
                    Text(probe.status)
                    Text("选择“连接并控制灯”读取状态、开灯或关灯。操作需要灯在蓝牙范围内；请退出其他米家灯具页面。")
                        .font(.footnote).foregroundStyle(.secondary)
                    NavigationLink {
                        DiagnosticModePicker(selection: $mode)
                    } label: {
                        LabeledContent("诊断模式", value: mode.rawValue)
                    }.disabled(probe.inspecting)
                    if mode != .discovery {
                        Text(mode == .channel ? "验证 A4 协商，不登录。" : mode == .control ? "登录后验证加密通道并读取开关状态，再启用控制按钮。" : "只验证登录后断开，不控制灯。")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                    if mode == .control || probe.lampIsOn != nil {
                        Text(probe.lampIsOn.map { "最近回读：" + ($0 ? "开启" : "关闭") } ?? "尚未读到灯具开关状态")
                        HStack {
                            Button("开灯") { probe.setLampOn(true) }
                            Spacer()
                            Button("关灯") { probe.setLampOn(false) }
                            Spacer()
                            Button("读状态") { probe.refreshLamp() }
                        }
                        .buttonStyle(.borderless)
                        .disabled(!probe.controlReady)
                        Button(probe.savedForShortcuts ? "更新快捷指令目标灯" : "设为快捷指令控制的灯") { probe.saveShortcutTarget() }
                            .disabled(!probe.controlReady)
                        if probe.savedForShortcuts {
                            Text("已保存目标灯。在快捷指令中添加“打开家里的灯”或“关闭家里的灯”。锁屏执行仍需实测。")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                    if let id = probe.selectedDeviceID {
                        Button("配置所选灯的认证密钥") { editingKey = true }
                            .disabled(probe.inspecting)
                            .sheet(isPresented: $editingKey) { MeshKeyEditor(deviceID: id, expectedMAC: probe.selectedDeviceMAC) }
                    }
                    Toggle("读取版本信息（只读）", isOn: $readVersions)
                        .disabled(probe.inspecting || mode != .discovery)
                    HStack {
                        Button("扫描 12 秒") { probe.scan() }.disabled(probe.scanning || probe.inspecting)
                        Spacer()
                        Button("停止") { probe.stop() }.disabled(!probe.scanning && !probe.inspecting)
                    }
                    .buttonStyle(.borderless)
                }
                Section("附近设备 · 请核对后仅连接自己的灯") {
                    ForEach(probe.devices) { device in
                        Button { probe.inspect(device, readVersions: readVersions, mode: mode) } label: {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(device.name).foregroundStyle(.primary)
                                Text("\(device.rssi) dBm · \(device.id.uuidString)")
                                    .font(.caption).foregroundStyle(.secondary)
                                if device.advertisesXiaomiService {
                                    Text("广播含 FE95，仅是候选线索").font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }.disabled(probe.inspecting)
                    }
                }
                Group {
                    Section("完整诊断日志") {
                        Button {
                            probe.exportDiagnostics { text in
                                UIPasteboard.general.string = text
                                copied = true
                            }
                        } label: {
                            Label(copied ? "已复制完整报告" : "复制完整报告", systemImage: "doc.on.doc")
                        }
                        .buttonStyle(.borderless)
                        Button(action: shareReport) {
                            Label("分享报告文件", systemImage: "square.and.arrow.up")
                        }
                        .buttonStyle(.borderless)
                        Button {
                            probe.exportDiagnostics { text in
                                exportText = text
                                exporting = true
                            }
                        } label: {
                            Label("保存为文本文件", systemImage: "folder")
                        }
                        .buttonStyle(.borderless)
                        NavigationLink {
                            ReportSnapshotView(probe: probe)
                        } label: {
                            Label("查看完整报告", systemImage: "doc.text.magnifyingglass")
                        }
                        Text("包含声音识别、蓝牙和应用状态，保留最近 7 天，最多 10 MB。日志仅保存在本机；查看时使用快照，点刷新获取最新内容。")
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }
            }
        .navigationTitle("高级配置与诊断")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(item: $sharedReport, onDismiss: removeTemporaryReport) { report in
            ReportShareSheet(url: report.url)
        }
        .fileExporter(isPresented: $exporting, document: ReportDocument(text: exportText),
                      contentType: .plainText, defaultFilename: "LampBLEProbe-report.txt") { result in
            if case .failure(let error) = result { exportError = error.localizedDescription }
        }
        .alert("报告导出失败", isPresented: Binding(
            get: { exportError != nil },
            set: { if !$0 { exportError = nil } }
        )) {
            Button("好", role: .cancel) { exportError = nil }
        } message: {
            Text(exportError ?? "请使用“复制完整报告”重试。")
        }
        .sheet(isPresented: $showingRelaySetup) {
            NavigationStack {
                List {
                    Section("随身 iPhone：创建两个快捷指令") {
                        Text("请求地址和内容是远程控制凭证，只传给你自己的随身手机。中转服务可看到开关请求及时间，消息默认缓存约 12 小时；中枢仅接受 2 分钟内的有效请求。")
                        Text("每个快捷指令添加“文本”，填入下方开灯或关灯内容；再添加“获取 URL 内容”，地址填下方地址，方法选 POST，请求体选“文件”，文件选择前面的“文本”变量。")
                        Text("手动运行两个快捷指令，确认旧手机显示回读成功且实体灯变化后，再添加到家和离家触发。HTTP 请求成功只表示中转收到，不能证明灯已动作。")
                    }
                    Section("请求地址") {
                        Text(relay.publishURL).textSelection(.enabled)
                        Button("复制请求地址") { UIPasteboard.general.string = relay.publishURL }
                    }
                    Section("回家开灯：文本内容") {
                        Text(relay.onBody).textSelection(.enabled)
                        Button("复制开灯内容") { UIPasteboard.general.string = relay.onBody }
                    }
                    Section("离家关灯：文本内容") {
                        Text(relay.offBody).textSelection(.enabled)
                        Button("复制关灯内容") { UIPasteboard.general.string = relay.offBody }
                    }
                    Section("自动化设置") {
                        Text("当前已使用家庭 Wi-Fi 自动化：连接家庭 Wi-Fi 时运行回家开灯，断开时运行离家关灯。已配置成功时无需重新创建。")
                        Text("家庭 Wi-Fi 触发由随身 iPhone 执行，中枢显示灯具回读结果。")
                        ShareLink("将配置传到自己的随身手机", item: "蓝牙灯自动化配置（含控制凭证，请勿公开）\nPOST 地址：\(relay.publishURL)\n开灯文本：\(relay.onBody)\n关灯文本：\(relay.offBody)")
                    }
                }
                .navigationTitle("到家与离家自动化")
                .toolbar { Button("完成") { showingRelaySetup = false } }
            }
        }
    }

    private func shareReport() {
        // Freeze a complete UTF-8 snapshot before presenting the share sheet.
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("LampBLEProbe-\(UUID().uuidString).txt")
        probe.exportDiagnostics { text in
            do {
                try Data(text.utf8).write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
                temporaryReportURL = url
                sharedReport = SharedReport(url: url)
            } catch {
                exportError = error.localizedDescription
            }
        }
    }

    private func removeTemporaryReport() {
        if let url = temporaryReportURL { try? FileManager.default.removeItem(at: url) }
        temporaryReportURL = nil
    }
}

// Keep mode selection away from the changing diagnostic page and UIKit menus.
private struct DiagnosticModePicker: View {
    @Binding var selection: ProbeMode
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        List(ProbeMode.allCases) { mode in
            Button {
                selection = mode
                dismiss()
            } label: {
                HStack {
                    Text(mode.rawValue).foregroundStyle(.primary)
                    Spacer()
                    if selection == mode { Image(systemName: "checkmark") }
                }.frame(minHeight: 44).contentShape(Rectangle())
            }.accessibilityAddTraits(selection == mode ? .isSelected : [])
        }
        .navigationTitle("诊断模式")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// No observation of the controller: log lines cannot force live text layout.
private struct ReportSnapshotView: View {
    let probe: BluetoothProbe
    @State private var snapshot = ""
    @State private var lines: [String] = []
    @State private var copied = false

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 3) {
                ForEach(lines.indices, id: \.self) { index in
                    Text(lines[index]).font(.system(.caption, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }.padding()
        }
        .navigationTitle("报告快照")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button(copied ? "已复制" : "复制") {
                    UIPasteboard.general.string = snapshot
                    copied = true
                }
                Button("刷新") { refresh() }
            }
        }
        .onAppear { refresh() }
    }

    private func refresh() {
        probe.exportDiagnostics { text in
            snapshot = text
            lines = text.components(separatedBy: "\n")
            copied = false
        }
    }
}

struct MeshKeyEditor: View {
    let deviceID: UUID
    let expectedMAC: String?
    @Environment(\.dismiss) private var dismiss
    @State private var keyText = ""
    @State private var importing = false
    @State private var message = "密钥仅保存在此 iPhone 的 Keychain，不进入报告。"
    var body: some View {
        NavigationStack {
            Form {
                Text("为所选灯保存 gatt_ltmk。需要本设备的 32 字节密钥（64 个十六进制字符），不是设备列表 token 或广播 bindkey。")
                Text(deviceID.uuidString).font(.caption)
                Button("导入本灯密钥文件") { importing = true }
                    .disabled(expectedMAC == nil)
                Text("从 Mac 本地凭证工具下载 JSON 文件后，通过隔空投送存入 iPhone 的文件 App，再在此选择。导入时会核对型号和 MAC。")
                    .font(.footnote)
                SecureField("gatt_ltmk", text: $keyText)
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                Text(message).font(.footnote)
                Button("保存到本机 Keychain") {
                    do {
                        try MeshKeyStore.save(MeshCrypto.parseKey(keyText), for: deviceID)
                        keyText = ""
                        message = "已保存。返回后选择实验性登录并再次点击灯具。"
                    } catch { message = "保存失败：请输入完整的 64 位十六进制密钥，并保持手机解锁。" }
                }
                Button("删除本机保存的密钥", role: .destructive) {
                    do { try MeshKeyStore.delete(deviceID); keyText = ""; message = "本机密钥已删除，灯的米家绑定未改变。" }
                    catch { message = "删除失败，请重试。" }
                }
            }
            .navigationTitle("本地认证凭证")
            .toolbar { Button("完成") { keyText = ""; dismiss() } }
        }
        .fileImporter(isPresented: $importing, allowedContentTypes: [.json]) { result in
            do {
                let url = try result.get()
                let accessing = url.startAccessingSecurityScopedResource()
                defer { if accessing { url.stopAccessingSecurityScopedResource() } }
                let file = try FileHandle(forReadingFrom: url)
                defer { try? file.close() }
                let data = try file.read(upToCount: 4097) ?? Data()
                let key = try MeshCrypto.credentialFile(data, expectedMAC: expectedMAC)
                try MeshKeyStore.save(key, for: deviceID)
                keyText = ""
                message = "已核对型号和 MAC，并保存到本机 Keychain。可返回选择实验性登录。"
            } catch {
                message = "未导入：请确认选择本灯的 JSON 文件、型号和 MAC 匹配，并保持手机解锁。"
            }
        }
    }
}
#Preview {
    ProbeView()
}
