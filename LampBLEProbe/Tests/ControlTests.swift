import Foundation

struct ControlTests {
    static var checks = 0
    static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        checks += 1
        if !condition() { fatalError("FAIL: \(message)") }
    }
    static func hex(_ s: String) -> Data { MeshAuthTests.hex(s) }
    static let testKey = Data(0..<64)
    static func deviceFrame(_ plaintext: Data, counter: UInt16) throws -> Data {
        let n = Data(32..<36) + Data(repeating: 0, count: 4) + Data([UInt8(counter & 255), UInt8(counter >> 8),0,0])
        let encrypted = try MeshCrypto.seal(plaintext, key: Data(0..<16), nonce: n)
        return Data([0,0,2,0,UInt8(counter & 255),UInt8(counter >> 8)]) + encrypted
    }
    static func onReply(tid: UInt16, value: Bool, reportedType: UInt8 = 16) -> Data {
        LampCodec.pack(tid: tid, opcode: 3, body: [1,2,1,0,0,0,1,reportedType,value ? 1 : 0])
    }
    final class Harness {
        let session: LampControlSession
        var writes: [(String, Data)] = []
        var successes: [(Bool, Bool?, Bool)] = []
        var failures: [String] = []
        var counter: UInt16 = 0
        init(desired: Bool? = nil, limit: Int = 113) throws {
            session = try LampControlSession(key: ControlTests.testKey, writeLimit: limit, desired: desired)
            session.write = { [weak self] in self?.writes.append(($0,$1)) }
            session.verified = { [weak self] in self?.successes.append(($0,$1,$2)) }
            session.failure = { [weak self] in self?.failures.append($0) }
        }
        func ready() { session.receive(channel: "001A", data: Data([0,0,1,1])) }
        func reply(_ packet: Data) throws {
            session.receive(channel: "001B", data: try ControlTests.deviceFrame(packet, counter: counter)); counter += 1
        }
        func exchange() throws {
            session.start(); ready(); try reply(LampCodec.exchange(tid: 1)); ready()
        }
        func lastPlaintext() throws -> Data {
            let bytes = Array(writes.last(where: { $0.0 == "001A" && $0.1.count > 6 })!.1)
            let count = UInt16(bytes[2]) | UInt16(bytes[3]) << 8
            let nonce = Data(36..<40) + Data(repeating: 0, count: 4) + Data([UInt8(count & 255),UInt8(count >> 8),0,0])
            return try MeshCrypto.open(Data(bytes.dropFirst(4)), key: Data(16..<32), nonce: nonce)
        }
    }
    static func run() throws -> Int {
        expect(LampCodec.getOn(tid: 2) == hex("092002000201020100"), "only get siid2/piid1")
        expect(LampCodec.setOn(tid: 3, value: true) == hex("0c2003000001020100010001"), "on is BOOL type 0")
        expect(LampCodec.setOn(tid: 3, value: false).last == 0, "off explicit false, never toggle")
        for (encrypted, plain) in [("4b50e5da", ""), ("23b4bba316bc20b4", "00010203"), ("23b4bba346f12bb502a575cb7869d5896bd017b6a4", "000102030405060708090a0b0c0d0e0f10")] {
            let decoded = try MeshCrypto.open(hex(encrypted), key: Data(0..<16), nonce: Data(16..<28))
            expect(decoded == hex(plain), "CCM open independent Python fixture")
            var modified = Array(hex(encrypted)); modified[modified.count-1] ^= 1
            do { _ = try MeshCrypto.open(Data(modified), key: Data(0..<16), nonce: Data(16..<28)); fatalError("accepted corrupt tag") }
            catch { checks += 1 }
        }
        let cipher = try LampCipher(key: testKey)
        let tx = try cipher.encrypt(LampCodec.exchange(tid: 1))
        expect(tx == hex("00000c5afe386683ca6643"), "TX direction and nonce independent Python fixture")
        let rx = try cipher.decrypt(hex("0000750e944e7716f36302"))
        expect(rx == LampCodec.exchange(tid: 1), "RX direction independent Python fixture")
        do { _ = try cipher.decrypt(hex("0000750e944e7716f36302")); fatalError("accepted replay") } catch { checks += 1 }
        var bad = Array(hex("01001dc288a114e8b29ea065c682ed7aa789aa43")); bad[bad.count-1] ^= 1
        do { _ = try cipher.decrypt(Data(bad)); fatalError("accepted bad tag") } catch { checks += 1 }
        let corrected = try cipher.decrypt(hex("01001dc288a114e8b29ea065c682ed7aa789aa43"))
        expect(corrected == onReply(tid: 2, value: false), "bad-tag packet did not consume RX counter")
        do { _ = try cipher.decrypt(Data([0,128,0,0,0,0])); fatalError("accepted counter rollover") } catch { checks += 1 }
        for bytes in [Data(), hex("05200100"), hex("06200100f0"), hex("05300100f0"), LampCodec.exchange(tid: 1)+Data([0])] {
            do { _ = try LampCodec.parse(bytes); fatalError("accepted malformed packet") } catch { checks += 1 }
        }
        for invalidBody: [UInt8] in [[1,2,1,0,1,0], [1,2,1,0,0,0,1,16,2], [1,3,1,0,0,0,1,16,1], [1,2,1,0,0,0,1,32,1]] {
            do { _ = try LampCodec.onValue(LampPacket(tid: 2, opcode: 3, body: invalidBody)); fatalError("accepted false state") } catch { checks += 1 }
        }
        let read = try Harness()
        read.session.start()
        expect(read.writes.count == 1 && read.successes.isEmpty, "header is not read success")
        read.ready()
        expect(read.writes.last?.1 == Data([1,0])+hex("00000c5afe386683ca6643"), "fresh F0 submitted immediately after ready")
        try read.reply(LampCodec.exchange(tid: 1)); read.ready()
        try read.reply(LampCodec.pack(tid: 2, opcode: 4, body: [1,2,1,0,1,16,1]))
        expect(read.successes.isEmpty && read.session.stage == .preflight, "notification cannot stand in for readback")
        try read.reply(onReply(tid: 99, value: false))
        expect(read.successes.isEmpty, "wrong TID cannot stand in for response")
        try read.reply(onReply(tid: 2, value: false))
        expect(read.successes.count == 1 && !read.successes[0].0 && !read.successes[0].2, "read-only mode verified without property write")
        read.session.setOn(true); read.ready()
        let manualPreflight = try read.lastPlaintext()
        let parsedPreflight = try LampCodec.parse(manualPreflight)
        expect(parsedPreflight.opcode == 2, "manual ON re-reads actual state before deciding")
        let on = try Harness(desired: true)
        try on.exchange(); try on.reply(onReply(tid: 2, value: false)); on.ready()
        let setOn = try on.lastPlaintext()
        expect(setOn == LampCodec.setOn(tid: 3, value: true), "desired ON emits only 2.1 BOOL set")
        try on.reply(LampCodec.pack(tid: 3, opcode: 1, body: [1,2,1,0,0,0]))
        expect(on.successes.isEmpty && on.session.stage == .waitingReady, "code=0 alone is not control success")
        on.ready(); try on.reply(onReply(tid: 4, value: true, reportedType: 0))
        expect(on.successes.count == 1 && on.successes[0].0 && on.successes[0].2, "ON acknowledged and readback verified")
        let off = try Harness(desired: false)
        try off.exchange(); try off.reply(onReply(tid: 2, value: true)); off.ready()
        let setOff = try off.lastPlaintext()
        expect(setOff == LampCodec.setOn(tid: 3, value: false), "OFF is explicit bool false")
        try off.reply(LampCodec.pack(tid: 3, opcode: 1, body: [1,2,1,0,0,0])); off.ready()
        try off.reply(onReply(tid: 4, value: false))
        expect(off.successes.count == 1 && !off.successes[0].0, "OFF verified")
        let noop = try Harness(desired: true)
        try noop.exchange(); try noop.reply(onReply(tid: 2, value: true))
        expect(noop.successes.count == 1 && !noop.successes[0].2, "already ON is freshly verified without toggle/write")
        let rejected = try Harness(desired: true)
        try rejected.exchange(); try rejected.reply(onReply(tid: 2, value: false)); rejected.ready()
        try rejected.reply(LampCodec.pack(tid: 3, opcode: 1, body: [1,2,1,0,1,0]))
        expect(rejected.successes.isEmpty && rejected.failures.count == 1, "nonzero set code fails")
        let mismatch = try Harness(desired: true)
        try mismatch.exchange(); try mismatch.reply(onReply(tid: 2, value: false)); mismatch.ready()
        try mismatch.reply(LampCodec.pack(tid: 3, opcode: 1, body: [1,2,1,0,0,0])); mismatch.ready()
        try mismatch.reply(onReply(tid: 4, value: false))
        expect(mismatch.successes.isEmpty && mismatch.failures.count == 1, "mismatched readback never reports ON success")
        let fragmented = try Harness(limit: 20)
        fragmented.session.start(); fragmented.ready()
        let frame = try deviceFrame(LampCodec.exchange(tid: 1), counter: 0).dropFirst(4)
        fragmented.session.receive(channel: "001B", data: Data([0,0,0,0,2,0]))
        fragmented.session.receive(channel: "001B", data: Data([1,0])+frame.prefix(10))
        fragmented.session.receive(channel: "001B", data: Data([2,0])+frame.suffix(1))
        expect(fragmented.session.stage == .waitingReady && fragmented.failures.isEmpty, "fragmented encrypted F0 and one-byte tail supported")
        let missingAck = try Harness()
        missingAck.session.start(); missingAck.session.timeout()
        expect(missingAck.writes.count == 1 && missingAck.successes.isEmpty, "timeout before ready never transmits encrypted payload")
        let count = missingAck.writes.count
        missingAck.ready()
        expect(missingAck.writes.count == count, "stopped control session ignores delayed ACK")
        let cancelled = try Harness(desired: true)
        try cancelled.exchange(); cancelled.session.cancel(); let before = cancelled.writes.count
        try cancelled.reply(onReply(tid: 2, value: false)); cancelled.ready()
        expect(cancelled.writes.count == before && cancelled.successes.isEmpty, "cancelled session cannot later turn on lamp")
        let window = try LampCipher(key: testKey)
        func encrypted(_ counter: UInt16) throws -> Data {
            Data(try deviceFrame(LampCodec.exchange(tid: 1), counter: counter).dropFirst(4))
        }
        _ = try window.decrypt(encrypted(70))
        let boundary = try window.decrypt(encrypted(7))
        expect(boundary == LampCodec.exchange(tid: 1), "authenticated late packet inside 64-counter window accepted")
        do { _ = try window.decrypt(encrypted(7)); fatalError("duplicate reached codec") }
        catch LampProtocolError.duplicate(7) { checks += 1 }
        do { _ = try window.decrypt(encrypted(6)); fatalError("stale packet accepted") }
        catch LampProtocolError.stale(6) { checks += 1 }
        var forged = Array(try encrypted(600)); forged[forged.count-1] ^= 1
        do { _ = try window.decrypt(Data(forged)); fatalError("bad tag advanced window") }
        catch MeshAuthError.cipherFailure { checks += 1 }
        _ = try window.decrypt(encrypted(71))
        let afterForgery = try window.decrypt(encrypted(8))
        expect(afterForgery == LampCodec.exchange(tid: 1), "failed authentication does not advance replay window")
        var forgedDuplicate = Array(try encrypted(71)); forgedDuplicate[forgedDuplicate.count-1] ^= 1
        do { _ = try window.decrypt(Data(forgedDuplicate)); fatalError("duplicate bypassed tag check") }
        catch MeshAuthError.cipherFailure { checks += 1 }

        // Regression: OFF accepted, then a previously generated notification
        // arrives behind SetPropertyResp. It must not interrupt the readback.
        let lateOff = try Harness(desired: false)
        try lateOff.exchange(); try lateOff.reply(onReply(tid: 2, value: true)); lateOff.ready()
        let setReply = LampCodec.pack(tid: 3, opcode: 1, body: [1,2,1,0,0,0])
        lateOff.session.receive(channel: "001B", data: try deviceFrame(setReply, counter: 3))
        lateOff.ready()
        let notification = LampCodec.pack(tid: 3, opcode: 4, body: [1,2,1,0,1,16,0])
        let delayed = try deviceFrame(notification, counter: 2)
        lateOff.session.receive(channel: "001B", data: delayed)
        expect(lateOff.failures.isEmpty && lateOff.successes.isEmpty && lateOff.session.stage == .readback,
               "late property notification does not abort or confirm OFF")
        lateOff.session.receive(channel: "001B", data: delayed)
        lateOff.session.receive(channel: "001B", data: try deviceFrame(setReply, counter: 3))
        expect(lateOff.failures.isEmpty && lateOff.successes.isEmpty && lateOff.session.stage == .readback,
               "duplicate notifications/replies ignored without accepting stale success")
        lateOff.session.receive(channel: "001B", data: try deviceFrame(onReply(tid: 4, value: false), counter: 4))
        expect(lateOff.successes.count == 1 && !lateOff.successes[0].0 && lateOff.successes[0].2,
               "OFF completed only after matching post-write readback despite reordering")
        let counterLog = AuthFrameLog.summary(channel: "001B", data: Data([0,0,2,0,3,0])+Data(repeating: 0xab, count: 16))
        expect(counterLog.contains("wireCounter=3") && !counterLog.contains("abab"), "wire counter visible without encrypted payload")
        let missing = Data([0,0,1,5,1,0])
        let retry = try Harness(desired: false)
        try retry.exchange(); try retry.reply(onReply(tid: 2, value: true)); retry.ready()
        let originalFrame = retry.writes.last!.1
        retry.session.receive(channel: "001A", data: missing)
        expect(retry.writes.last?.1 == originalFrame && retry.successes.isEmpty && retry.failures.isEmpty,
               "missing frame retransmits identical encrypted OFF bytes without claiming success")
        let retryPlaintext = try retry.lastPlaintext()
        expect(retryPlaintext == LampCodec.setOn(tid: 3, value: false), "retransmission preserves TID and explicit false value")
        try retry.reply(LampCodec.pack(tid: 3, opcode: 1, body: [1,2,1,0,0,0])); retry.ready()
        let postRetryRead = try retry.lastPlaintext()
        expect(postRetryRead == LampCodec.getOn(tid: 4), "retry does not advance TID or change next request")
        let originalCounter = UInt16(originalFrame[2]) | UInt16(originalFrame[3]) << 8
        let readFrame = retry.writes.last!.1
        let nextCounter = UInt16(readFrame[2]) | UInt16(readFrame[3]) << 8
        expect(nextCounter == originalCounter + 1, "retry never re-encrypts or consumes another nonce/counter")
        try retry.reply(onReply(tid: 4, value: false))
        expect(retry.successes.count == 1 && !retry.successes[0].0, "retry completes only after actual matching readback")
        let capped = try Harness()
        capped.session.start(); capped.ready()
        let first = capped.writes.last!.1
        capped.session.receive(channel: "001A", data: missing)
        capped.session.receive(channel: "001A", data: missing)
        expect(capped.writes.suffix(2).allSatisfy { $0.1 == first } && capped.failures.isEmpty, "at most two identical retries allowed")
        let atCap = capped.writes.count
        capped.session.receive(channel: "001A", data: missing)
        expect(capped.writes.count == atCap && capped.failures.count == 1 && capped.successes.isEmpty, "retry cap terminates without another send")
        for wrong in [Data([0,0,1,5]), Data([0,0,1,5,2,0]), Data([0,0,1,5,0,0])] {
            let badRetry = try Harness(); badRetry.session.start(); badRetry.ready()
            let beforeRetry = badRetry.writes.count
            badRetry.session.receive(channel: "001A", data: wrong)
            expect(badRetry.writes.count == beforeRetry && badRetry.failures.count == 1, "invalid missing-frame sequence not retransmitted")
        }
        let noReadyRetry = try Harness(); noReadyRetry.session.start()
        noReadyRetry.session.receive(channel: "001A", data: missing)
        expect(noReadyRetry.writes.count == 1 && noReadyRetry.failures.count == 1, "cannot retransmit before Ready ACK")
        let retryLog = AuthFrameLog.summary(channel: "001A", data: missing)
        expect(retryLog.contains("requestedSeq=1"), "missing-frame sequence included in diagnostics")
        // A retained authenticated session must handle many operations without
        // reusing TIDs/nonces, and must not confirm before each fresh readback.
        let retained = try Harness()
        try retained.exchange(); try retained.reply(onReply(tid: 2, value: false))
        var retainedTID: UInt16 = 3
        var previousValue = false
        var lastTXCounter: UInt16 = 1
        for index in 1...12 {
            let desired = !previousValue
            retained.session.setOn(desired); retained.ready()
            let get = try retained.lastPlaintext()
            expect(get == LampCodec.getOn(tid: retainedTID), "retained session advances read TID")
            try retained.reply(onReply(tid: retainedTID, value: previousValue)); retained.ready()
            let set = try retained.lastPlaintext()
            expect(set == LampCodec.setOn(tid: retainedTID + 1, value: desired), "retained session uses explicit fresh SET")
            try retained.reply(LampCodec.pack(tid: retainedTID + 1, opcode: 1, body: [1,2,1,0,0,0])); retained.ready()
            expect(retained.successes.count == index, "retained operation waits for readback")
            let frame = retained.writes.last(where: { $0.0 == "001A" && $0.1.count > 6 })!.1
            let txCounter = UInt16(frame[2]) | UInt16(frame[3]) << 8
            expect(txCounter == lastTXCounter + 3, "retained session never resets TX counter")
            try retained.reply(onReply(tid: retainedTID + 2, value: desired))
            expect(retained.session.isReady && retained.successes.count == index + 1 && retained.failures.isEmpty,
                   "retained session ready after verified operation")
            lastTXCounter = txCounter
            retainedTID += 3
            previousValue = desired
        }
        return checks
    }
}
