import Foundation
import CryptoKit

// Standalone protocol tests: no BLE hardware, account access or Keychain changes.
// Crypto fixtures independently generated with Python cryptography AESCCM/HKDF.
@main
struct MeshAuthTests {
    static func hex(_ s: String) -> Data {
        let c = Array(s)
        return Data(stride(from: 0, to: c.count, by: 2).map { UInt8(String(c[$0...$0 + 1]), radix: 16)! })
    }
    static var assertions = 0
    static func expect(_ ok: @autoclosure () -> Bool, _ label: String) {
        assertions += 1
        guard ok() else { fatalError("FAIL: \(label)") }
    }
    static func main() throws {
        let aesFixtures = [
            (0, "4b50e5da"), (4, "23b4bba316bc20b4"),
            (16, "23b4bba346f12bb502a575cb7869d589ea6a8d74"),
            (17, "23b4bba346f12bb502a575cb7869d5896bd017b6a4"),
            (64, "23b4bba346f12bb502a575cb7869d5896ba6c0a421521c3ceef1bd4bcf38739b7d328e49c7b9199432cd68d5d31396efadfe61031ced3734a5fc6998d6d2320f24e99fd1")]
        for (count, expected) in aesFixtures {
            let actual = try MeshCrypto.seal(Data((0..<count).map(UInt8.init)), key: Data(0..<16), nonce: Data(16..<28))
            expect(actual == hex(expected), "CCM independent fixture length \(count)")
        }
        let hkdf = try MeshCrypto.sessionKey(sharedSecret: Data(0..<32), ltmk: Data(32..<64))
        expect(hkdf == hex("e7f84deb02399853824922acea8c5769b9ae64b6d3715d0e76fced1bf6af88721f3579aafb7cf3d8cfca4262a3d2b93035a1377dfbdef6ad53dee7faf058ec56"), "HKDF independent fixture")
        expect(MeshCrypto.crc32(Data("123456789".utf8)) == 0xcbf43926, "standard CRC32 check")
        let scalar1 = Data(repeating: 0, count: 31) + Data([1])
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: scalar1)
        let remote = hex("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1")
        let proof = try MeshCrypto.proof(privateKey: privateKey, devicePublicKey: remote, ltmk: Data(0..<32))
        expect(proof == hex("547c1c29e40177b8"), "ECDH+HKDF+CRC+CCM independent proof")
        for invalid in ["", String(repeating: "z", count: 64), String(repeating: "0", count: 63), String(repeating: "0", count: 66)] {
            do { _ = try MeshCrypto.parseKey(invalid); fatalError("accepted malformed key") } catch { assertions += 1 }
        }
        let parsedKey = try MeshCrypto.parseKey(String(repeating: "ab ", count: 32))
        expect(parsedKey == Data(repeating: 0xab, count: 32), "whitespace key import")
        let credential: [String: Any] = ["format": "LampBLEProbeKey", "version": 1, "region": "cn",
            "model": "shhf.light.slcwb8", "mac": "001122334455", "gatt_ltmk": String(repeating: "ab", count: 32)]
        let credentialData = try JSONSerialization.data(withJSONObject: credential)
        let imported = try MeshCrypto.credentialFile(credentialData, expectedMAC: "00:11:22:33:44:55")
        expect(imported == parsedKey, "device-bound credential file import")
        for (field, wrong) in [("format", "Other"), ("model", "other.light"), ("region", "de"),
                               ("mac", "112233445566"), ("gatt_ltmk", "short")] {
            var changed = credential; changed[field] = wrong
            do {
                _ = try MeshCrypto.credentialFile(JSONSerialization.data(withJSONObject: changed), expectedMAC: "001122334455")
                fatalError("accepted invalid credential field")
            } catch { assertions += 1 }
        }
        for expectedMAC in [nil, "112233445566"] as [String?] {
            do { _ = try MeshCrypto.credentialFile(credentialData, expectedMAC: expectedMAC); fatalError("accepted wrong target") }
            catch { assertions += 1 }
        }
        do {
            _ = try MeshCrypto.credentialFile(Data(repeating: 32, count: 4097), expectedMAC: "001122334455")
            fatalError("accepted oversized credential")
        } catch { assertions += 1 }
        var writes: [(String, Data)] = [], results: [String] = []
        func session(login: Bool = false, maximum: Int = 20, key: Data? = nil) -> MeshAuthSession {
            writes = []; results = []
            let s = MeshAuthSession(maximumWriteLength: maximum, login: login, ltmk: key)
            s.write = { channel, data, _ in writes.append((channel, data)) }; s.completion = { results.append($0) }
            return s
        }
        func negotiate(_ s: MeshAuthSession) {
            s.start()
            s.receive(channel: "0016", data: Data([0,0,4,0,6,242]))
            s.receive(channel: "0016", data: Data([0,0,4,1]) + Data(repeating: 18, count: 16))
        }
        let noKey = session(login: true)
        noKey.start()
        expect(writes.isEmpty && results.count == 1 && !noKey.observedExpectedResponse, "missing key sends nothing")
        let channel = session()
        negotiate(channel)
        expect(channel.observedExpectedResponse && results.count == 1, "channel response verified")
        expect(writes.count == 3 && writes[0].1 == Data([0xa4]), "channel only A4 and two echoes")
        expect(writes.allSatisfy { $0.1.count <= 20 }, "respect BLE minimum MTU")
        let echo = session()
        echo.start(); echo.receive(channel: "0016", data: Data([0,0,4,0,6,18]))
        echo.receive(channel: "0016", data: Data([0,0,4,1,99]))
        expect(!echo.observedExpectedResponse && results.count == 1 && writes.count == 2, "malformed echo stops before login")
        let early = session(login: true, key: Data(0..<32))
        early.start(); early.receive(channel: "0010", data: Data([0x51,0,0,0]))
        expect(!early.observedExpectedResponse && results.first?.contains("Unexpected") == true, "early success cannot authenticate")
        let full = session(login: true, key: Data(0..<32))
        negotiate(full)
        expect(results.isEmpty && full.stage == .publicReady, "await ready before public key")
        let beforePublic = writes.count
        full.receive(channel: "0016", data: Data([0,0,1,1]))
        expect(writes.count - beforePublic == 4 && writes.suffix(4).allSatisfy { $0.1.count <= 20 }, "public key fragmented at MTU20")
        full.receive(channel: "0016", data: Data([0,0,2,3]) + remote)
        expect(full.stage == .proofReady && results.isEmpty, "no success after device key alone")
        full.receive(channel: "0016", data: Data([0,0,1,0])) // late ACK for public key
        expect(full.stage == .proofReady, "late public ACK handled")
        full.receive(channel: "0016", data: Data([0,0,1,1]))
        expect(full.stage == .result && writes.last?.1.count == 10, "proof sent only after ready ACK")
        expect(full.derivedSessionKey == nil, "unaccepted login cannot expose a data-channel key")
        var acceptedSessionKey: Data?
        full.completion = { [weak full] result in acceptedSessionKey = full?.derivedSessionKey; results.append(result) }
        full.receive(channel: "0010", data: Data([0x51,0,0,0]))
        expect(full.observedExpectedResponse && results.count == 1, "explicit post-proof result")
        expect(acceptedSessionKey?.count == 64 && full.derivedSessionKey == nil, "data key handed off only on acceptance then released")
        let completedWrites = writes.count
        full.receive(channel: "0016", data: Data([0,0,1,1]))
        expect(writes.count == completedWrites, "finished session ignores stale frames")
        let fragmented = session(login: true, key: Data(0..<32))
        negotiate(fragmented); fragmented.receive(channel: "0016", data: Data([0,0,1,1]))
        fragmented.receive(channel: "0016", data: Data([0,0,0,3,4,0]))
        for i in 0..<4 {
            fragmented.receive(channel: "0016", data: Data([UInt8(i+1),0]) + remote.subdata(in: i*16..<(i+1)*16))
        }
        expect(fragmented.stage == .proofReady, "fragmented device key assembled")
        let shortTail = session(login: true, maximum: 65, key: Data(0..<32))
        shortTail.start()
        shortTail.receive(channel: "0016", data: Data([0,0,4,0,6,63]))
        shortTail.receive(channel: "0016", data: Data([0,0,4,1]) + Data(repeating: 63, count: 61))
        shortTail.receive(channel: "0016", data: Data([0,0,1,1]))
        shortTail.receive(channel: "0016", data: Data([0,0,0,3,2,0]))
        shortTail.receive(channel: "0016", data: Data([1,0]) + remote.prefix(63))
        shortTail.receive(channel: "0016", data: Data([2,0]) + remote.suffix(1))
        expect(shortTail.stage == .proofReady, "one-byte tail fragment accepted")
        let invalid = session(login: true, key: Data(0..<32))
        negotiate(invalid); invalid.receive(channel: "0016", data: Data([0,0,1,1]))
        invalid.receive(channel: "0016", data: Data([0,0,2,3]) + Data(repeating: 0, count: 64))
        expect(!invalid.observedExpectedResponse && results.first?.contains("Invalid public key") == true, "invalid EC point rejected")
        let rejected = session(login: true, key: Data(0..<32))
        negotiate(rejected); rejected.receive(channel: "0010", data: Data([0x52,0,0,0]))
        expect(!rejected.observedExpectedResponse && results.count == 1, "device rejection is failure")
        let timed = session()
        timed.start(); timed.timeout(); let atTimeout = writes.count; timed.timeout()
        expect(results.count == 1 && writes.count == atTimeout, "timeout terminal; no retry")
        // Virtual clock: verify gaps from actual BLE submission, without sleeps.
        var clock: TimeInterval = 0
        var jobs: [(TimeInterval, () -> Void)] = []
        var submitted: [(TimeInterval, String, Data)] = []
        var ready = true
        let writer = PacedAuthWriter(now: { clock }, schedule: { delay, action in jobs.append((clock + delay, action)) })
        writer.canSend = { ready }
        writer.submit = { submitted.append((clock, $0, $1)) }
        func advance(_ time: TimeInterval) {
            while let next = jobs.enumerated().filter({ $0.element.0 <= time }).min(by: { $0.element.0 < $1.element.0 }) {
                let job = jobs.remove(at: next.offset)
                clock = job.0
                job.1()
            }
            clock = time
        }
        writer.enqueue(channel: "0016", data: Data([1]), minimumGap: 0)
        writer.enqueue(channel: "0010", data: Data([0x50,0,0,0]), minimumGap: 0.25)
        writer.enqueue(channel: "0016", data: Data([0,0,0,3,1,0]), minimumGap: 0.2)
        expect(submitted.count == 1, "login waits after MNG echo")
        advance(0.249)
        expect(submitted.count == 1, "no early login write")
        advance(0.25)
        expect(submitted.count == 2 && submitted.last?.1 == "0010", "login submitted after 250ms")
        advance(0.449)
        expect(submitted.count == 2, "header waits after actual login submission")
        advance(0.45)
        expect(submitted.count == 3 && writer.isEmpty, "header submitted after additional 200ms")
        writer.cancel(); submitted = []; ready = false
        writer.enqueue(channel: "0016", data: Data([2]), minimumGap: 0)
        advance(1)
        expect(submitted.isEmpty, "backpressure prevents submission")
        ready = true; writer.drain()
        writer.enqueue(channel: "0010", data: Data([3]), minimumGap: 0.25)
        advance(1.24)
        expect(submitted.count == 1, "gap starts when previously blocked packet actually sent")
        advance(1.25)
        expect(submitted.count == 2, "backpressure release retains timing")
        writer.enqueue(channel: "0016", data: Data([4]), minimumGap: 0.25)
        writer.cancel()
        advance(2)
        expect(submitted.count == 2 && writer.isEmpty, "cancelled timer never submits login data")
        writer.enqueue(channel: "0016", data: Data([5]), minimumGap: 0)
        writer.enqueue(channel: "0016", data: Data([6]), minimumGap: 0.25)
        writer.cancel()
        writer.enqueue(channel: "0016", data: Data([7]), minimumGap: 0)
        let afterCancel = submitted.count
        advance(3)
        expect(submitted.count == afterCancel && submitted.last?.2 == Data([7]), "stale callback cannot affect new generation")
        writer.enqueue(channel: "0016", data: Data([10]), minimumGap: 0)
        let beforeBackpressure = submitted.count
        ready = false
        writer.enqueue(channel: "0016", data: Data([8]), minimumGap: 0.25)
        ready = true; writer.drain(); ready = false
        advance(3.25)
        expect(submitted.count == beforeBackpressure, "backpressure is checked again at timer fire")
        ready = true; writer.drain()
        expect(submitted.count == beforeBackpressure + 1, "readiness callback resumes queued packet")
        writer.cancel()
        writer.submit = { [weak writer] _, _ in writer?.cancel() }
        writer.enqueue(channel: "0016", data: Data([9]), minimumGap: 0)
        expect(writer.isEmpty, "reentrant cancellation stops drain safely")
        let secretProof = Data([1,0]) + Data(repeating: 0xab, count: 8)
        let proofLog = AuthFrameLog.summary(channel: "0016", data: secretProof)
        expect(proofLog.contains("seq=1") && !proofLog.contains("abab"), "proof payload omitted from diagnostics")
        expect(AuthFrameLog.summary(channel: "0010", data: Data([0x50,0,0,0])).contains("50000000"), "public login opcode is visible")
        expect(AuthFrameLog.summary(channel: "0016", data: Data([0,0,1,1])).contains("00000101"), "ready ACK header is visible")
        expect(!AuthFrameLog.summary(channel: "0016", data: Data([0,0,2,3]) + remote).contains("7cf27b"), "device-key payload omitted")
        // Replay the observed 111-byte negotiation through the real session+writer.
        var flowClock: TimeInterval = 0
        var flowJobs: [(TimeInterval, () -> Void)] = []
        var flowWrites: [(TimeInterval, Data)] = []
        let flowWriter = PacedAuthWriter(now: { flowClock }, schedule: { delay, action in flowJobs.append((flowClock + delay, action)) })
        flowWriter.canSend = { true }
        flowWriter.submit = { _, data in flowWrites.append((flowClock, data)) }
        let flow = MeshAuthSession(maximumWriteLength: 113, login: true, ltmk: Data(0..<32))
        flow.write = { flowWriter.enqueue(channel: $0, data: $1, minimumGap: $2) }
        func advanceFlow(_ time: TimeInterval) {
            while let next = flowJobs.enumerated().filter({ $0.element.0 <= time }).min(by: { $0.element.0 < $1.element.0 }) {
                let job = flowJobs.remove(at: next.offset); flowClock = job.0; job.1()
            }
            flowClock = time
        }
        flow.start()
        advanceFlow(0.06); flow.receive(channel: "0016", data: Data([0,0,4,0,6,111]))
        advanceFlow(0.12); flow.receive(channel: "0016", data: Data([0,0,4,1]) + Data(repeating: 111, count: 109))
        expect(flowWrites.count == 3 && flowWrites.last?.1.count == 113, "111-byte real-world MNG submitted before login")
        advanceFlow(0.369)
        expect(flowWrites.count == 3, "session actually paces login after real echo")
        advanceFlow(0.371)
        expect(flowWrites.count == 4 && flowWrites.last?.1 == Data([0x50,0,0,0]), "session emits login after settle interval")
        advanceFlow(0.571)
        expect(flowWrites.count == 5 && flowWrites.last?.1 == Data([0,0,0,3,1,0]), "session emits header separately after login")
        expect(flowWrites[4].0 - flowWrites[3].0 >= 0.199999 && flow.stage == .publicReady,
               "actual session retains Ready ACK requirement")
        flow.timeout(); flowWriter.cancel(); let stoppedFlow = flowWrites.count
        advanceFlow(10)
        expect(flowWrites.count == stoppedFlow && !flow.observedExpectedResponse, "timed-out flow does not retry or report success")
        assertions += try ControlTests.run()
        print("PASS: \(assertions) crypto/protocol assertions; no hardware or credentials used")
    }
}
