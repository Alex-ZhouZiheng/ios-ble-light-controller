import Foundation
import CryptoKit
import CommonCrypto
import Security

enum ProbeMode: String, CaseIterable, Identifiable {
    case discovery = "只读诊断"
    case channel = "验证认证通道"
    case login = "实验性登录"
    case control = "连接并控制灯"
    var id: String { rawValue }
    var requiresCredential: Bool { self == .login || self == .control }
}

enum MeshAuthError: Error { case invalidInput, cipherFailure }

// A serial, backpressure-aware writer. Gaps are measured from actual submissions,
// not enqueue times; stale scheduled callbacks cannot resume a cancelled session.
final class PacedAuthWriter {
    struct Frame {
        let channel: String
        let data: Data
        let minimumGap: TimeInterval
    }
    private var frames: [Frame] = []
    private var lastSubmission: TimeInterval?
    private var generation = 0
    private var waiting = false
    let now: () -> TimeInterval
    let schedule: (TimeInterval, @escaping () -> Void) -> Void
    var canSend: () -> Bool = { false }
    var submit: (String, Data) -> Void = { _, _ in }
    var drained: () -> Void = {}
    var isEmpty: Bool { frames.isEmpty }

    init(now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         schedule: @escaping (TimeInterval, @escaping () -> Void) -> Void = { delay, action in
             DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: action)
         }) {
        self.now = now
        self.schedule = schedule
    }
    func enqueue(channel: String, data: Data, minimumGap: TimeInterval) {
        frames.append(Frame(channel: channel, data: data, minimumGap: max(0, minimumGap)))
        drain()
    }
    func cancel() {
        generation += 1
        frames = []
        waiting = false
        lastSubmission = nil
    }
    func drain() {
        guard !waiting else { return }
        let currentGeneration = generation
        while let frame = frames.first {
            guard canSend() else { return }
            let remaining = lastSubmission.map { $0 + frame.minimumGap - now() } ?? 0
            if remaining > 0.000001 {
                waiting = true
                schedule(remaining) { [weak self] in
                    guard let self = self, self.generation == currentGeneration else { return }
                    self.waiting = false
                    self.drain()
                }
                return
            }
            frames.removeFirst()
            lastSubmission = now()
            submit(frame.channel, frame.data)
            guard generation == currentGeneration else { return }
        }
        drained()
    }
}

enum AuthFrameLog {
    static func summary(channel: String, data: Data) -> String {
        let b = Array(data)
        func prefix(_ count: Int) -> String { b.prefix(count).map { String(format: "%02x", $0) }.joined() }
        if channel == "0010", b.count <= 4 { return "control=\(prefix(4)) bytes=\(b.count)" }
        if ["0016", "001A", "001B"].contains(channel), b.count >= 4, b[0] == 0, b[1] == 0 {
            // Show protocol metadata only, never public-key/proof payloads.
            if channel == "001B", b.count >= 6, b[2] == 2, b[3] == 0 {
                return "header=\(prefix(4)) wireCounter=\(Int(b[4]) | Int(b[5]) << 8) bytes=\(b.count) (payload omitted)"
            }
            if channel == "001A", b.count >= 6, b[2] == 1, b[3] == 5 {
                return "header=\(prefix(6)) requestedSeq=\(Int(b[4]) | Int(b[5]) << 8) bytes=\(b.count)"
            }
            let count = b[2] == 0 && b.count == 6 ? 6 : 4
            return "header=\(prefix(count)) bytes=\(b.count) (payload omitted)"
        }
        if ["0016", "001A", "001B"].contains(channel), b.count >= 2 {
            return "fragment seq=\(Int(b[0]) | Int(b[1]) << 8) bytes=\(b.count) (payload omitted)"
        }
        return "bytes=\(b.count) (payload omitted)"
    }
}

enum MeshCrypto {
    static func credentialFile(_ data: Data, expectedMAC: String?) throws -> Data {
        struct Credential: Decodable {
            let format: String
            let version: Int
            let region: String
            let model: String
            let mac: String
            let gatt_ltmk: String
        }
        func normalize(_ value: String) -> String {
            value.replacingOccurrences(of: ":", with: "").replacingOccurrences(of: "-", with: "").uppercased()
        }
        guard data.count <= 4096, let expectedMAC = expectedMAC else { throw MeshAuthError.invalidInput }
        let c = try JSONDecoder().decode(Credential.self, from: data)
        let mac = normalize(c.mac), expected = normalize(expectedMAC)
        guard c.format == "LampBLEProbeKey", c.version == 1, c.region == "cn",
              c.model == "shhf.light.slcwb8", mac.count == 12,
              mac.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) }),
              mac == expected else { throw MeshAuthError.invalidInput }
        return try parseKey(c.gatt_ltmk)
    }

    static func parseKey(_ text: String) throws -> Data {
        let s = text.filter { !$0.isWhitespace }
        guard s.count == 64, s.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }) else {
            throw MeshAuthError.invalidInput
        }
        let chars = Array(s)
        return Data(stride(from: 0, to: 64, by: 2).map { UInt8(String(chars[$0...$0 + 1]), radix: 16)! })
    }

    static func crc32(_ bytes: Data) -> UInt32 {
        var crc = UInt32.max
        for byte in bytes {
            crc ^= UInt32(byte)
            for _ in 0..<8 { crc = (crc >> 1) ^ (crc & 1 == 1 ? 0xedb88320 : 0) }
        }
        return ~crc
    }

    static func sessionKey(sharedSecret: Data, ltmk: Data) throws -> Data {
        guard sharedSecret.count == 32, ltmk.count == 32 else { throw MeshAuthError.invalidInput }
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: sharedSecret + ltmk),
            salt: Data("miot-mesh-login-salt".utf8), info: Data("miot-mesh-login-info".utf8), outputByteCount: 64)
        return key.withUnsafeBytes { Data($0) }
    }

    // Restricted AES-CCM: 128-bit key, 12-byte nonce, 4-byte tag, no AAD.
    // CCM B0 has L=3 and M=4. Used for login proof and session messages.
    static func seal(_ plaintext: Data, key: Data, nonce: Data) throws -> Data {
        guard key.count == 16, nonce.count == 12, plaintext.count <= 65535 else { throw MeshAuthError.invalidInput }
        func aes(_ block: [UInt8]) throws -> [UInt8] {
            var out = [UInt8](repeating: 0, count: 32)
            var written = 0
            let status = key.withUnsafeBytes { k in
                block.withUnsafeBytes { b in
                    CCCrypt(CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                        k.baseAddress, 16, nil, b.baseAddress, 16, &out, 32, &written)
                }
            }
            guard status == kCCSuccess, written == 16 else { throw MeshAuthError.cipherFailure }
            return Array(out.prefix(16))
        }
        let n = Array(nonce), p = Array(plaintext), length = p.count
        let b0: [UInt8] = [0x0a] + n + [UInt8((length >> 16) & 255), UInt8((length >> 8) & 255), UInt8(length & 255)]
        var mac = try aes(b0)
        for start in stride(from: 0, to: length, by: 16) {
            var block = [UInt8](repeating: 0, count: 16)
            for j in 0..<min(16, length - start) { block[j] = p[start + j] }
            mac = try aes(zip(mac, block).map { $0 ^ $1 })
        }
        func counter(_ i: Int) -> [UInt8] { [2] + n + [UInt8((i >> 16) & 255), UInt8((i >> 8) & 255), UInt8(i & 255)] }
        let s0 = try aes(counter(0))
        var cipher: [UInt8] = []
        for start in stride(from: 0, to: length, by: 16) {
            let stream = try aes(counter(start / 16 + 1))
            for j in 0..<min(16, length - start) { cipher.append(p[start + j] ^ stream[j]) }
        }
        return Data(cipher + zip(mac.prefix(4), s0.prefix(4)).map { $0 ^ $1 })
    }

    static func proof(privateKey: P256.KeyAgreement.PrivateKey, devicePublicKey: Data, ltmk: Data) throws -> Data {
        let okm = try deriveSession(privateKey: privateKey, devicePublicKey: devicePublicKey, ltmk: ltmk)
        return try loginProof(devicePublicKey: devicePublicKey, sessionKey: okm)
    }

    static func deriveSession(privateKey: P256.KeyAgreement.PrivateKey, devicePublicKey: Data, ltmk: Data) throws -> Data {
        guard devicePublicKey.count == 64 else { throw MeshAuthError.invalidInput }
        let remote = try P256.KeyAgreement.PublicKey(x963Representation: Data([4]) + devicePublicKey)
        let secret = try privateKey.sharedSecretFromKeyAgreement(with: remote).withUnsafeBytes { Data($0) }
        return try sessionKey(sharedSecret: secret, ltmk: ltmk)
    }

    static func loginProof(devicePublicKey: Data, sessionKey okm: Data) throws -> Data {
        guard devicePublicKey.count == 64, okm.count == 64 else { throw MeshAuthError.invalidInput }
        let crc = crc32(devicePublicKey)
        let payload = Data((0..<4).map { UInt8((crc >> ($0 * 8)) & 255) })
        return try seal(payload, key: Data(okm[16..<32]), nonce: Data(0x10...0x1b))
    }

    static func open(_ ciphertext: Data, key: Data, nonce: Data) throws -> Data {
        guard ciphertext.count >= 4, ciphertext.count <= 4099 else { throw MeshAuthError.invalidInput }
        // seal(zeros) yields the CTR stream plus a tag. Do not expose any
        // plaintext until its independently recomputed CCM tag matches.
        let count = ciphertext.count - 4
        let stream = try seal(Data(repeating: 0, count: count), key: key, nonce: nonce)
        let plaintext = Data(zip(ciphertext.prefix(count), stream.prefix(count)).map { $0 ^ $1 })
        let expected = try seal(plaintext, key: key, nonce: nonce)
        var difference: UInt8 = 0
        for (a, b) in zip(expected.suffix(4), ciphertext.suffix(4)) { difference |= a ^ b }
        guard difference == 0 else { throw MeshAuthError.cipherFailure }
        return plaintext
    }
}

enum MeshKeyStore {
    private static func query(_ deviceID: UUID) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "LampBLEProbe.mesh-gatt-ltmk",
         kSecAttrAccount as String: deviceID.uuidString]
    }
    static func load(_ deviceID: UUID) throws -> Data? {
        var q = query(deviceID)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &value)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = value as? Data, data.count == 32 else { throw MeshAuthError.invalidInput }
        return data
    }
    static func save(_ data: Data, for deviceID: UUID) throws {
        guard data.count == 32 else { throw MeshAuthError.invalidInput }
        let q = query(deviceID)
        let update = [kSecValueData as String: data]
        var status = SecItemUpdate(q as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var item = q
            item[kSecValueData as String] = data
            item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            status = SecItemAdd(item as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw MeshAuthError.invalidInput }
    }
    static func delete(_ deviceID: UUID) throws {
        let status = SecItemDelete(query(deviceID) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw MeshAuthError.invalidInput }
    }
    static func allowBackgroundAccess(_ deviceID: UUID) throws {
        let status = SecItemUpdate(query(deviceID) as CFDictionary,
            [kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly] as CFDictionary)
        guard status == errSecSuccess else { throw MeshAuthError.invalidInput }
    }
}

// Experimental Mesh login candidate. Reference captures are from other models.
// No registration, rebinding, property writes, or automatic retry is implemented.
final class MeshAuthSession {
    enum Stage { case idle, management0, management1, publicReady, deviceKey, proofReady, result, done }
    private(set) var stage: Stage = .idle
    private(set) var observedExpectedResponse = false
    private var sessionKeyMaterial: Data?
    var derivedSessionKey: Data? { observedExpectedResponse ? sessionKeyMaterial : nil }
    private var mtu: Int
    private let ltmk: Data?
    private let login: Bool
    private let key = P256.KeyAgreement.PrivateKey()
    private var proof = Data()
    private var received: [Int: Data] = [:]
    private var frameCount = 0
    var write: (String, Data, TimeInterval) -> Void = { _, _, _ in }
    var progress: (String) -> Void = { _ in }
    var completion: (String) -> Void = { _ in }

    init(maximumWriteLength: Int, login: Bool, ltmk: Data?) {
        self.mtu = min(242, maximumWriteLength - 2)
        self.login = login
        self.ltmk = ltmk
    }
    func start() {
        guard stage == .idle else { return }
        guard mtu >= 18, !login || ltmk?.count == 32 else { fail("Missing 32-byte credential or insufficient write length"); return }
        stage = .management0
        progress("A4 sent; waiting for management negotiation")
        transmit("0010", Data([0xa4]))
    }
    func cancel() { stage = .done; proof = Data(); received = [:]; sessionKeyMaterial = nil }
    func timeout() { fail("Timeout at \(stage). No authentication success established") }
    private func fail(_ reason: String) {
        guard stage != .done else { return }
        cancel()
        completion("AUTH STOP: " + reason)
    }
    private func finish(_ reason: String) {
        observedExpectedResponse = true
        stage = .done; proof = Data(); received = [:]
        // The owner can take the key synchronously on explicit 0x51 only.
        completion(reason)
        sessionKeyMaterial = nil
    }
    private func transmit(_ channel: String, _ data: Data, minimumGap: TimeInterval = 0) {
        write(channel, data, minimumGap)
    }
    private func sendPackage(_ payload: Data) {
        let bytes = Array(payload)
        for offset in stride(from: 0, to: bytes.count, by: mtu) {
            let seq = offset / mtu + 1
            transmit("0016", Data([UInt8(seq & 255), UInt8(seq >> 8)]) + Data(bytes[offset..<min(offset + mtu, bytes.count)]), minimumGap: seq == 1 ? 0 : 0.05)
        }
    }
    func receive(channel: String, data: Data) {
        guard stage != .done else { return }
        let b = Array(data)
        if channel == "0010" {
            if b == [0x52, 0, 0, 0] { fail("Device rejected experimental login (0x52)") }
            else if b == [0x51, 0, 0, 0] {
                guard stage == .result else { fail("Unexpected 0x51 before proof submission"); return }
                finish("Device returned 0x51 after login proof. Login acceptance observed; state/control NOT tested.")
            } else { fail("Unexpected control response; stopped without further writes") }
            return
        }
        guard channel == "0016", b.count >= 2 else { fail("Truncated or unexpected auth frame"); return }
        if stage == .management0 {
            guard b.count == 6, Array(b.prefix(5)) == [0, 0, 4, 0, 6], b[5] >= 18 else { fail("Unknown management-0 frame"); return }
            mtu = min(mtu, Int(b[5]))
            stage = .management1
            progress("Management-0 received; negotiated payload \(mtu) bytes")
            transmit("0016", Data([0, 0, 5, 0, 6, UInt8(mtu)]))
            return
        }
        if stage == .management1 {
            guard Array(b.prefix(4)) == [0, 0, 4, 1], b.count == mtu + 2,
                  b.dropFirst(4).allSatisfy({ $0 == UInt8(mtu) }) else { fail("Management echo length/content mismatch"); return }
            transmit("0016", Data([0, 0, 5, 1]) + Data(repeating: UInt8(mtu), count: mtu - 2))
            guard login else { finish("AUTH CHANNEL RESPONSE VERIFIED: expected A4/MNG responses received; final echo submitted. No login or light control attempted."); return }
            stage = .publicReady
            progress("Channel verified; pacing login request (250ms after echo, 200ms before transfer header)")
            transmit("0010", Data([0x50, 0, 0, 0]), minimumGap: 0.25)
            let count = (64 + mtu - 1) / mtu
            transmit("0016", Data([0, 0, 0, 3, UInt8(count), 0]), minimumGap: 0.2)
            return
        }
        if b == [0, 0, 1, 1] {
            if stage == .publicReady {
                stage = .deviceKey
                progress("Sending fresh P-256 public key; waiting for device public key")
                sendPackage(Data(key.publicKey.x963Representation.dropFirst()))
            } else if stage == .proofReady {
                stage = .result
                progress("Sending login proof; waiting for explicit device result")
                sendPackage(proof)
            } else { fail("Unexpected ready ACK") }
            return
        }
        if b == [0, 0, 1, 0], stage == .deviceKey || stage == .proofReady || stage == .result { return }
        if stage == .deviceKey {
            if b.count == 68, Array(b.prefix(4)) == [0, 0, 2, 3] {
                acceptDeviceKey(Data(b.dropFirst(4)), single: true)
            } else if b.count == 6, Array(b.prefix(4)) == [0, 0, 0, 3] {
                guard frameCount == 0 else { fail("Repeated transfer header"); return }
                frameCount = Int(b[4]) | Int(b[5]) << 8
                guard (1...64).contains(frameCount) else { fail("Invalid public-key frame count"); return }
                transmit("0016", Data([0, 0, 1, 1]))
            } else if frameCount > 0 {
                let seq = Int(b[0]) | Int(b[1]) << 8
                guard (1...frameCount).contains(seq), b.count > 2, b.count <= mtu + 2, received[seq] == nil else { fail("Invalid/duplicate public-key fragment"); return }
                received[seq] = Data(b.dropFirst(2))
                guard received.values.reduce(0, { $0 + $1.count }) <= 64 else { fail("Oversized device public key"); return }
                if received.count == frameCount {
                    acceptDeviceKey((1...frameCount).reduce(Data()) { $0 + received[$1]! }, single: false)
                }
            } else { fail("Unknown device-key frame") }
        } else { fail("Unexpected auth frame at \(stage)") }
    }
    private func acceptDeviceKey(_ bytes: Data, single: Bool) {
        do {
            guard let ltmk = ltmk else { throw MeshAuthError.invalidInput }
            let okm = try MeshCrypto.deriveSession(privateKey: key, devicePublicKey: bytes, ltmk: ltmk)
            sessionKeyMaterial = okm
            proof = try MeshCrypto.loginProof(devicePublicKey: bytes, sessionKey: okm)
            stage = .proofReady
            progress("Validated P-256 device public key; preparing proof")
            transmit("0016", Data(single ? [0, 0, 3, 0] : [0, 0, 1, 0]))
            transmit("0016", Data([0, 0, 0, 5, 1, 0]), minimumGap: 0.2)
        } catch { fail("Invalid public key or proof computation failed (secret values omitted)") }
    }
}
