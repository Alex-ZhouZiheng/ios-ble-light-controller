import Foundation

@main
struct RelayTests {
    static func main() throws {
        var checks = 0
        func expect(_ value: Bool, _ label: String) {
            checks += 1
            precondition(value, label)
        }
        let now: TimeInterval = 1000
        func event(_ id: String, _ text: String = "on:test-secret", time: TimeInterval = 1000,
                   topic: String = "test-topic", kind: String = "message") -> RelayEvent {
            RelayEvent(id: id, time: time, event: kind, topic: topic, message: text)
        }
        var gate = RelayGate()
        func accept(_ event: RelayEvent, at time: TimeInterval = now) -> RelayCommand? {
            gate.accept(event, topic: "test-topic", secret: "test-secret", now: time)
        }
        expect(accept(event("1"))?.desired == true, "valid ON")
        expect(accept(event("1")) == nil, "duplicate suppressed")
        expect(accept(event("2", "off:test-secret"))?.desired == false, "same-second OFF ordered after ON")
        for text in ["off:wrong", "on", "toggle", "on:test-secret\n", " on:test-secret"] {
            expect(accept(event("bad-" + text, text)) == nil, "strict payload validation")
        }
        expect(accept(event("wrong-topic", topic: "other")) == nil, "topic isolation")
        expect(accept(event("keepalive", kind: "keepalive")) == nil, "ignore keepalive")
        expect(accept(event("stale", time: 879)) == nil, "expiry check")
        expect(accept(event("future", time: 1031)) == nil, "future timestamp rejected")
        expect(accept(event("out-of-order", time: 999)) == nil, "older command cannot override newer")
        expect(accept(event("unauth-newer", "on:wrong", time: 1030)) == nil, "invalid auth cannot advance time")
        expect(gate.newestTime == 1000, "failed validation leaves watermark intact")
        expect(accept(event("")) == nil, "empty ID rejected")
        expect(accept(event(String(repeating: "x", count: 129))) == nil, "ID bound")
        let encoded = try JSONEncoder().encode(gate)
        var restored = try JSONDecoder().decode(RelayGate.self, from: encoded)
        expect(restored.accept(event("2", "off:test-secret"), topic: "test-topic", secret: "test-secret", now: now) == nil,
               "persisted acceptance prevents reconnect replay")
        expect(accept(event("expired-cache", time: 1000), at: 1121) == nil, "cached command expires on reconnect")
        let command = accept(event("fresh"))!
        expect(command.expires == 1120, "queued request retains original expiry")
        for index in 0..<200 {
            _ = accept(event("many-\(index)", time: 1000 + Double(index)), at: 1000 + Double(index))
        }
        expect(gate.seen.count == 128 && gate.newestTime == 1199, "bounded persisted replay history")
        expect(accept(event("many-0"), at: 1199) == nil, "evicted ID still rejected when old")
        let line = #"{"id":"wire","time":1200,"event":"message","topic":"test-topic","message":"off:test-secret"}"#
        let decoded = try JSONDecoder().decode(RelayEvent.self, from: Data(line.utf8))
        expect(accept(decoded, at: 1200)?.desired == false, "ntfy wire format decoded")
        expect((try? JSONDecoder().decode(RelayEvent.self, from: Data("{}".utf8))) == nil, "malformed event ignored")
        print("PASS: \(checks) relay validation assertions; synthetic data only")
    }
}
