import Foundation

// Gate Apple's model output; one high-score episode fires once across windows.
struct SnapClassificationPolicy {
    private(set) var lastDecision = "none"
    private var armed = true
    private var lastEnd = -Double.infinity
    private var cooldownUntil = -Double.infinity

    mutating func invalidateEpisode() { armed = false }

    mutating func process(score: Double, competing: Double, start: Double, end: Double, now: Double) -> Bool {
        lastDecision = "invalid_or_out_of_order"
        guard score.isFinite, competing.isFinite, start.isFinite, end.isFinite, now.isFinite,
              (0...1).contains(score), (0...1).contains(competing),
              start >= 0, end > start, end > lastEnd else { return false }
        lastEnd = end
        // Drop delayed gestures instead of replaying them after a backlog.
        lastDecision = "stale_or_future"
        guard now - end <= 1.25, end - now <= 0.25 else { armed = false; return false }
        if score < 0.25 { lastDecision = "rearmed"; armed = true; return false }
        lastDecision = "below_threshold"
        guard score >= 0.65 else { return false }
        let wasArmed = armed
        armed = false
        guard wasArmed else { lastDecision = "episode_not_rearmed"; return false }
        guard end >= cooldownUntil else { lastDecision = "cooldown"; return false }
        guard score - competing >= 0.15 else { lastDecision = "competing_sound"; return false }
        lastDecision = "accepted"
        cooldownUntil = end + 1.2
        return true
    }
}

// Caller serializes access. Only the most recent bounded work is retained.
struct LatestAnalysisQueue<Element> {
    private var elements: [Element] = []
    let capacity: Int
    init(capacity: Int = 8) { self.capacity = max(1, capacity) }
    var count: Int { elements.count }
    mutating func enqueue(_ element: Element) -> Element? {
        let discarded = elements.count == capacity ? elements.removeFirst() : nil
        elements.append(element)
        return discarded
    }
    mutating func dequeue() -> Element? { elements.isEmpty ? nil : elements.removeFirst() }
    mutating func removeAll() { elements.removeAll(keepingCapacity: true) }
}

// Audio positions follow capture time, including skipped buffers and input gaps.
struct SnapAudioTimeline {
    private(set) var origin: TimeInterval?
    private var nextFrame: Int64 = 0
    private(set) var skippedFrames: Int64 = 0
    mutating func position(capturedAt: TimeInterval, frames: UInt32, sampleRate: Double) -> Int64 {
        if origin == nil { origin = capturedAt }
        let elapsed = max(0, capturedAt - (origin ?? capturedAt))
        let frame = max(nextFrame, Int64((elapsed * sampleRate).rounded()))
        skippedFrames = frame - nextFrame
        nextFrame = frame + Int64(frames)
        return frame
    }
}
