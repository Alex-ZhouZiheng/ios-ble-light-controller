import Foundation

enum LampProtocolError: Error {
    case malformed, authentication, replay, exhausted
    case deviceStatus(UInt16)
    case duplicate(UInt16), stale(UInt16)
    var diagnostic: String {
        switch self {
        case .malformed: return "MIoT response format/type/property mismatch"
        case .authentication: return "Session key unavailable"
        case .replay: return "Unsupported receive counter rollover"
        case .exhausted: return "Session counter exhausted; reconnect required"
        case .deviceStatus(let code): return String(format: "Device returned property error 0x%04x", code)
        case .duplicate(let count): return "Duplicate authenticated frame counter=\(count) ignored"
        case .stale(let count): return "Authenticated frame outside receive window counter=\(count) ignored"
        }
    }
}

struct LampPacket {
    let tid: UInt16
    let opcode: UInt8
    let body: [UInt8]
}

enum LampCodec {
    static func pack(tid: UInt16, opcode: UInt8, body: [UInt8] = []) -> Data {
        let size = 5 + body.count
        return Data([UInt8(size & 255), UInt8(0x20 | (size >> 8)), UInt8(tid & 255), UInt8(tid >> 8), opcode] + body)
    }
    static func exchange(tid: UInt16) -> Data { pack(tid: tid, opcode: 0xf0) }
    static func getOn(tid: UInt16) -> Data { pack(tid: tid, opcode: 2, body: [1,2,1,0]) }
    static func setOn(tid: UInt16, value: Bool) -> Data {
        // MIoT siid=2/piid=1, BOOL type=0, value length=1. Never toggle.
        pack(tid: tid, opcode: 0, body: [1,2,1,0,1,0,value ? 1 : 0])
    }
    static func parse(_ data: Data) throws -> LampPacket {
        let b = Array(data)
        guard b.count >= 5, b.count <= 4095, b[1] >> 4 == 2,
              (Int(b[0]) | Int(b[1] & 15) << 8) == b.count else { throw LampProtocolError.malformed }
        return LampPacket(tid: UInt16(b[2]) | UInt16(b[3]) << 8, opcode: b[4], body: Array(b.dropFirst(5)))
    }
    static func onValue(_ packet: LampPacket) throws -> Bool {
        // A matching GetPropertyResp must explicitly contain one 2.1 result.
        let b = packet.body
        guard packet.opcode == 3, b.count >= 6, b[0] == 1,
              Array(b[1...3]) == [2,1,0] else { throw LampProtocolError.malformed }
        let code = UInt16(b[4]) | UInt16(b[5]) << 8
        guard code == 0 else { throw LampProtocolError.deviceStatus(code) }
        guard b.count == 9, b[6] == 1, [UInt8(0),16].contains(b[7]), b[8] <= 1 else {
            throw LampProtocolError.malformed
        }
        return b[8] == 1
    }
    static func successfulWrite(_ packet: LampPacket) -> Bool {
        packet.opcode == 1 && packet.body == [1,2,1,0,0,0]
    }
    static func writeStatus(_ packet: LampPacket) throws -> UInt16 {
        guard packet.opcode == 1, packet.body.count == 6, Array(packet.body.prefix(4)) == [1,2,1,0] else { throw LampProtocolError.malformed }
        return UInt16(packet.body[4]) | UInt16(packet.body[5]) << 8
    }
}

// One short-lived session; no rollover or nonce reuse. Counter exhaustion
// closes the session, requiring fresh ECDH. Receive counter advances only after
// CCM authentication succeeds. A 64-counter replay window accepts each fresh
// counter once, including late notifications. Duplicates never reach the codec.
final class LampCipher {
    private var key: Data
    private var txCounter: UInt16 = 0
    private var highestRX: UInt16?
    private var receivedBitmap: UInt64 = 0
    private(set) var lastAcceptedCounter: UInt16?
    init(key: Data) throws {
        guard key.count == 64 else { throw LampProtocolError.authentication }
        self.key = key
    }
    func invalidate() { key = Data() }
    private func nonce(iv: Data, counter: UInt16) -> Data {
        iv + Data(repeating: 0, count: 4) + Data([UInt8(counter & 255), UInt8(counter >> 8),0,0])
    }
    func encrypt(_ plaintext: Data) throws -> Data {
        guard key.count == 64, txCounter < 0x8000 else { throw LampProtocolError.exhausted }
        let count = txCounter
        let data = try MeshCrypto.seal(plaintext, key: Data(key[16..<32]), nonce: nonce(iv: Data(key[36..<40]), counter: count))
        txCounter += 1
        return Data([UInt8(count & 255), UInt8(count >> 8)]) + data
    }
    func decrypt(_ frame: Data) throws -> Data {
        let b = Array(frame)
        guard key.count == 64, b.count >= 6 else { throw LampProtocolError.malformed }
        let count = UInt16(b[0]) | UInt16(b[1]) << 8
        guard count < 0x8000 else { throw LampProtocolError.replay }
        let value = try MeshCrypto.open(Data(b.dropFirst(2)), key: Data(key[0..<16]), nonce: nonce(iv: Data(key[32..<36]), counter: count))
        // Authenticate before modifying window state or classifying a replay.
        if let highest = highestRX {
            if count > highest {
                let shift = Int(count - highest)
                receivedBitmap = shift >= 64 ? 1 : (receivedBitmap << shift) | 1
                highestRX = count
            } else {
                let distance = Int(highest - count)
                guard distance < 64 else { throw LampProtocolError.stale(count) }
                let mask: UInt64 = 1 << distance
                guard receivedBitmap & mask == 0 else { throw LampProtocolError.duplicate(count) }
                receivedBitmap |= mask
            }
        } else {
            highestRX = count
            receivedBitmap = 1
        }
        lastAcceptedCounter = count
        return value
    }
}

final class LampControlSession {
    enum Stage { case idle, waitingReady, exchange, preflight, setResponse, readback, ready, done }
    private(set) var stage: Stage = .idle
    private var cipher: LampCipher
    private let writeLimit: Int
    private var goal: Bool?
    private var didWrite = false
    private var nextTID: UInt16 = 1
    private var expectedTID: UInt16 = 0
    private var nextStage: Stage = .exchange
    private var pendingFrame = Data()
    private var sentFrame = Data()
    private var retransmissions = 0
    private var incomingFrames: [Int: Data] = [:]
    private var incomingCount = 0
    var write: (String, Data) -> Void = { _, _ in }
    var progress: (String) -> Void = { _ in }
    var verified: (Bool, Bool?, Bool) -> Void = { _, _, _ in }
    var failure: (String) -> Void = { _ in }
    var isReady: Bool { stage == .ready }

    init(key: Data, writeLimit: Int, desired: Bool? = nil) throws {
        cipher = try LampCipher(key: key)
        self.writeLimit = writeLimit
        goal = desired
    }
    func cancel() {
        stage = .done; cipher.invalidate(); pendingFrame = Data(); sentFrame = Data(); incomingFrames = [:]
    }
    func timeout() { stop("Timeout at \(stage); light operation NOT confirmed") }
    private func stop(_ reason: String) {
        guard stage != .done else { return }
        cancel(); failure(reason)
    }
    func start() {
        guard stage == .idle else { return }
        send(opcode: 0xf0, body: [], then: .exchange)
    }
    func refresh() {
        guard stage == .ready else { return }
        goal = nil; didWrite = false; read(then: .preflight)
    }
    func setOn(_ value: Bool) {
        guard stage == .ready else { return }
        goal = value; didWrite = false; read(then: .preflight)
    }
    private func read(then stage: Stage) { send(opcode: 2, body: [1,2,1,0], then: stage) }
    private func send(opcode: UInt8, body: [UInt8], then targetStage: Stage) {
        do {
            guard nextTID < UInt16.max else { throw LampProtocolError.exhausted }
            expectedTID = nextTID; nextTID += 1
            let packet = LampCodec.pack(tid: expectedTID, opcode: opcode, body: body)
            pendingFrame = Data([1,0]) + (try cipher.encrypt(packet))
            guard pendingFrame.count <= writeLimit else { throw LampProtocolError.malformed }
            sentFrame = Data(); retransmissions = 0
            nextStage = targetStage; stage = .waitingReady
            progress("SPEC request opcode=\(String(format: "%02x", opcode)) tid=\(expectedTID); waiting for Ready ACK")
            write("001A", Data([0,0,0,0,1,0]))
        } catch { stop("Could not encrypt/frame request; no success established") }
    }
    func receive(channel: String, data: Data) {
        guard stage != .done else { return }
        let b = Array(data)
        if channel == "001A" {
            if b == [0,0,1,1] {
                guard stage == .waitingReady, !pendingFrame.isEmpty else { stop("Unexpected/duplicate data-channel Ready ACK"); return }
                stage = nextStage
                let frame = pendingFrame; pendingFrame = Data()
                sentFrame = frame
                progress("SPEC sending encrypted request; waiting for \(stage)")
                write("001A", frame)
            } else if b.count >= 4, Array(b.prefix(4)) == [0,0,1,5] {
                // Single outgoing frame: accept only an explicit request for
                // sequence 1. Reuse bytes/TID/counter; never re-encrypt or retry
                // a whole property operation just because a reply is missing.
                guard b == [0,0,1,5,1,0], !sentFrame.isEmpty,
                      [.exchange, .preflight, .setResponse, .readback].contains(stage) else {
                    stop("Invalid or out-of-phase missing-frame request; operation NOT confirmed"); return
                }
                guard retransmissions < 2 else { stop("Missing-frame retry limit reached; operation NOT confirmed"); return }
                retransmissions += 1
                progress("Device requested missing sequence 1; retransmitting identical encrypted frame (\(retransmissions)/2)")
                write("001A", sentFrame)
            } else if b != [0,0,1,0] { stop("Unknown data-channel ACK/status; operation NOT confirmed") }
            return
        }
        guard channel == "001B", b.count >= 2 else { stop("Malformed data-channel frame"); return }
        if b.count >= 4 && Array(b.prefix(4)) == [0,0,2,0] {
            guard incomingCount == 0, b.count >= 10, b.count <= 4105 else { stop("Invalid single encrypted frame"); return }
            write("001B", Data([0,0,3,0]))
            decode(Data(b.dropFirst(4)))
        } else if b.count == 6 && Array(b.prefix(4)) == [0,0,0,0] {
            guard incomingCount == 0 else { stop("Overlapping incoming transfer"); return }
            incomingCount = Int(b[4]) | Int(b[5]) << 8
            guard (1...128).contains(incomingCount) else { stop("Invalid incoming frame count"); return }
            incomingFrames = [:]
            write("001B", Data([0,0,1,1]))
        } else if incomingCount > 0 {
            let seq = Int(b[0]) | Int(b[1]) << 8
            guard (1...incomingCount).contains(seq), b.count > 2, b.count <= writeLimit,
                  incomingFrames[seq] == nil else { stop("Invalid/duplicate incoming fragment"); return }
            incomingFrames[seq] = Data(b.dropFirst(2))
            guard incomingFrames.values.reduce(0, { $0 + $1.count }) <= 4101 else { stop("Oversized encrypted message"); return }
            if incomingFrames.count == incomingCount {
                let frame = (1...incomingCount).reduce(Data()) { $0 + incomingFrames[$1]! }
                incomingCount = 0; incomingFrames = [:]
                write("001B", Data([0,0,1,0]))
                decode(frame)
            }
        } else { stop("Unknown data-channel framing") }
    }
    private func decode(_ frame: Data) {
        do {
            let packet = try LampCodec.parse(cipher.decrypt(frame))
            metadata("SPEC accepted encrypted counter=\(cipher.lastAcceptedCounter.map(String.init) ?? "unknown")")
            progressMetadata(packet)
            // Notifications and unrelated replies never stand in for our readback.
            if packet.opcode == 4 || packet.opcode == 7 { return }
            guard packet.tid == expectedTID else { return }
            switch stage {
            case .exchange:
                guard packet.opcode == 0xf0, packet.body.isEmpty else { throw LampProtocolError.malformed }
                progress("SPEC v2 exchange verified; reading lamp siid=2 piid=1")
                read(then: .preflight)
            case .preflight, .readback:
                guard packet.opcode == 3 else { return }
                let value = try LampCodec.onValue(packet)
                if stage == .readback {
                    guard let requested = goal, requested == value else { stop("State readback differs from requested value; operation NOT confirmed"); return }
                    complete(value)
                } else if let requested = goal, requested != value {
                    didWrite = true
                    send(opcode: 0, body: [1,2,1,0,1,0,requested ? 1 : 0], then: .setResponse)
                } else { complete(value) }
            case .setResponse:
                guard packet.opcode == 1 else { return }
                let code = try LampCodec.writeStatus(packet)
                guard code == 0 else { throw LampProtocolError.deviceStatus(code) }
                progress("SetPropertyResp code=0; verifying with GetProperty")
                read(then: .readback)
            default: break
            }
        } catch let error as LampProtocolError {
            switch error {
            case .duplicate, .stale:
                metadata(error.diagnostic)
            default:
                stop(error.diagnostic + "; operation NOT confirmed")
            }
        } catch { stop("CCM tag validation or encrypted response decoding failed; operation NOT confirmed") }
    }
    private func progressMetadata(_ packet: LampPacket) {
        // This is intentionally not progress(): unsolicited traffic must not
        // extend a request timeout indefinitely. Payloads are not logged.
        metadata("SPEC RX tid=\(packet.tid) opcode=\(String(format: "%02x", packet.opcode)) bytes=\(packet.body.count + 5)")
    }
    var metadata: (String) -> Void = { _ in }
    private func complete(_ value: Bool) {
        let requested = goal, wrote = didWrite
        sentFrame = Data(); retransmissions = 0
        goal = nil; didWrite = false; stage = .ready
        verified(value, requested, wrote)
    }
}

struct LampOperationError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

struct SavedLamp: Codable {
    let id: UUID
    let mac: String
    let model: String
    let firmware: String
    private static let preferenceKey = "LampBLEProbe.shortcutTarget.v1"
    static func load() -> SavedLamp? {
        guard let data = UserDefaults.standard.data(forKey: preferenceKey),
              let lamp = try? JSONDecoder().decode(SavedLamp.self, from: data),
              lamp.model == "shhf.light.slcwb8", lamp.firmware == "2.1.2_0004", lamp.mac.count == 12 else { return nil }
        return lamp
    }
    func save() throws {
        UserDefaults.standard.set(try JSONEncoder().encode(self), forKey: Self.preferenceKey)
    }
}
