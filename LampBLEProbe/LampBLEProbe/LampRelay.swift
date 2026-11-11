import Foundation
import Combine
import Security

private struct RelaySettings: Codable {
    let topic: String
    let secret: String
    var publishURL: String { "https://ntfy.sh/" + topic }
    var streamURL: URL { URL(string: publishURL + "/json?since=latest")! }

    private static let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "LampBLEProbe.relay.v1",
        kSecAttrAccount as String: "settings"
    ]
    static func loadOrCreate() throws -> RelaySettings {
        var request = query
        request[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecSuccess, let data = result as? Data {
            return try JSONDecoder().decode(Self.self, from: data)
        }
        guard status == errSecItemNotFound else { throw RelayError.configuration }
        func randomHex() throws -> String {
            var bytes = [UInt8](repeating: 0, count: 32)
            guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
                throw RelayError.configuration
            }
            return bytes.map { String(format: "%02x", $0) }.joined()
        }
        // ntfy caps topics at 64 characters: 32 random bytes in hex fit
        // exactly, so do not add a human-readable prefix.
        let settings = try Self(topic: randomHex(), secret: randomHex())
        request = query
        request[kSecValueData as String] = try JSONEncoder().encode(settings)
        request[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        guard SecItemAdd(request as CFDictionary, nil) == errSecSuccess else { throw RelayError.configuration }
        return settings
    }
}

private enum RelayError: Error { case configuration, network }

enum RelayResultPhase {
    case idle, pending, confirmed, failed
    var symbol: String {
        switch self {
        case .idle: return "clock"
        case .pending: return "hourglass"
        case .confirmed: return "checkmark.circle.fill"
        case .failed: return "exclamationmark.circle"
        }
    }
}

@MainActor
final class LampRelay: ObservableObject {
    static let shared = LampRelay()
    @Published private(set) var enabled = UserDefaults.standard.bool(forKey: "LampBLEProbe.relayEnabled")
    @Published private(set) var status = "云端接收未启动"
    @Published private(set) var connected = false
    @Published private(set) var connectionLabel = "接收未启动"
    @Published private(set) var resultPhase: RelayResultPhase = .idle
    @Published private(set) var lastResultAt: Date?
    @Published private(set) var lastResult = "尚未收到开关请求" {
        didSet { lastResultAt = Date() }
    }
    @Published private(set) var publishURL = ""
    @Published private(set) var onBody = ""
    @Published private(set) var offBody = ""
    private var listener: Task<Void, Never>?
    private var executor: Task<Void, Never>?
    private var pending: RelayCommand?
    private var generation = UUID()
    private var settings: RelaySettings?
    private var gate = (UserDefaults.standard.data(forKey: "LampBLEProbe.relayGate")
        .flatMap { try? JSONDecoder().decode(RelayGate.self, from: $0) }) ?? RelayGate()
    private let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 90
        config.timeoutIntervalForResource = 3600
        return URLSession(configuration: config)
    }()

    func prepareSetup() {
        do {
            let value = try RelaySettings.loadOrCreate()
            settings = value
            publishURL = value.publishURL
            onBody = "on:" + value.secret
            offBody = "off:" + value.secret
        } catch { status = "无法读取中转配置，请解锁旧手机后重试" }
    }

    func setEnabled(_ value: Bool) {
        if value {
            guard BluetoothProbe.shared.hubEnabled else { status = "请先开启常驻中枢模式"; return }
            prepareSetup()
            guard settings != nil else { return }
        }
        enabled = value
        UserDefaults.standard.set(value, forKey: "LampBLEProbe.relayEnabled")
        if value { start() } else { stop() }
    }

    func start() {
        guard enabled, listener == nil else { return }
        prepareSetup()
        guard let settings = settings else { return }
        listener = Task { [weak self] in
            var delay: UInt64 = 2
            while !Task.isCancelled {
                guard let self = self else { return }
                self.connected = false
                self.connectionLabel = "正在连接"
                self.status = "正在连接云端中转"
                do {
                    let (bytes, response) = try await self.session.bytes(from: settings.streamURL)
                    guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { throw RelayError.network }
                    self.connected = true
                    self.connectionLabel = "已连接"
                    DiagnosticLog.shared.record("relay", "connected")
                    self.status = "云端已连接，等待到家或离家请求"
                    for try await line in bytes.lines {
                        try Task.checkCancellation()
                        guard line.utf8.count <= 8192,
                              let data = line.data(using: .utf8),
                              let event = try? JSONDecoder().decode(RelayEvent.self, from: data) else { continue }
                        delay = 2
                        self.receive(event, settings: settings)
                    }
                } catch {
                    // Never put URLs or request bodies (control credentials)
                    // into diagnostics, including localized network errors.
                }
                if Task.isCancelled { return }
                self.connected = false
                self.connectionLabel = "断线重试中"
                DiagnosticLog.shared.record("relay", "disconnected_retrying", level: .warning)
                self.status = "云端连接中断，将重试；尚未确认灯具状态"
                do { try await Task.sleep(nanoseconds: delay * 1_000_000_000) } catch { return }
                delay = min(60, delay * 2)
            }
        }
    }

    private func receive(_ event: RelayEvent, settings: RelaySettings) {
        guard let command = gate.accept(event, topic: settings.topic, secret: settings.secret,
                                        now: Date().timeIntervalSince1970) else { return }
        if let data = try? JSONEncoder().encode(gate) {
            UserDefaults.standard.set(data, forKey: "LampBLEProbe.relayGate")
        }
        DiagnosticLog.shared.record("relay", "command_accepted", detail: "target=\(command.desired)")
        pending = command
        resultPhase = .pending
        lastResult = "已收到" + (command.desired ? "开灯" : "关灯") + "请求，等待蓝牙执行"
        guard executor == nil else { return }
        let currentGeneration = generation
        executor = Task { [weak self] in
            guard let self = self else { return }
            defer { if self.generation == currentGeneration { self.executor = nil } }
            while !Task.isCancelled, self.generation == currentGeneration, let command = self.pending {
                guard command.expires >= Date().timeIntervalSince1970 else {
                    self.pending = nil; self.resultPhase = .failed; self.lastResult = "请求已过期，未执行"; continue
                }
                let probe = BluetoothProbe.shared
                guard probe.hubEnabled, probe.hubRunning else {
                    self.pending = nil; self.resultPhase = .failed; self.lastResult = "中枢已停止，请求未执行"; continue
                }
                guard probe.canAcceptRelayOperation else {
                    do { try await Task.sleep(nanoseconds: 250_000_000) } catch { return }
                    continue
                }
                self.pending = nil
                do {
                    let actual = try await probe.performSavedOperation(desired: command.desired, source: "relay")
                    guard self.generation == currentGeneration else { return }
                    self.resultPhase = .confirmed
                    self.lastResult = actual ? "开灯已回读确认" : "关灯已回读确认"
                } catch {
                    guard self.generation == currentGeneration else { return }
                    self.resultPhase = .failed
                    self.lastResult = "操作失败或结果未确认；未自动重放，请查看蓝牙报告"
                }
            }
        }
    }

    private func stop() {
        generation = UUID()
        listener?.cancel(); listener = nil
        executor?.cancel(); executor = nil
        pending = nil
        connected = false
        connectionLabel = "接收已停止"
        status = "云端接收已停止"
    }
}
