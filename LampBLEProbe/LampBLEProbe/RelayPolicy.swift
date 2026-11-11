import Foundation

struct RelayEvent: Decodable {
    let id: String
    let time: TimeInterval
    let event: String
    let topic: String
    let message: String?
}

struct RelayCommand {
    let desired: Bool
    let expires: TimeInterval
}

// Persist acceptance before execution: reconnects must not repeat an operation
// whose result is unknown. The newest queued command supersedes older ones.
struct RelayGate: Codable {
    var seen: [String] = []
    var newestTime: TimeInterval = 0
    static let lifetime: TimeInterval = 120

    mutating func accept(_ event: RelayEvent, topic: String, secret: String, now: TimeInterval) -> RelayCommand? {
        guard event.event == "message", event.topic == topic,
              !event.id.isEmpty, event.id.count <= 128,
              event.time.isFinite, now - event.time <= Self.lifetime,
              event.time <= now + 30, event.time >= newestTime,
              !seen.contains(event.id) else { return nil }
        let desired: Bool
        switch event.message {
        case "on:" + secret: desired = true
        case "off:" + secret: desired = false
        default: return nil
        }
        newestTime = event.time
        seen.append(event.id)
        if seen.count > 128 { seen.removeFirst(seen.count - 128) }
        return RelayCommand(desired: desired, expires: event.time + Self.lifetime)
    }
}
