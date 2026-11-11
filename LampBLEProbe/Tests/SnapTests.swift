import Foundation

@main struct SnapTests {
    static func main() {
        var checks = 0
        func check(_ value: Bool, _ message: String) {
            precondition(value, message); checks += 1
        }
        func emit(_ policy: inout SnapClassificationPolicy, _ score: Double, _ end: Double,
                  competing: Double = 0.1, lag: Double = 0.1) -> Bool {
            policy.process(score: score, competing: competing, start: max(0, end - 0.5), end: end, now: end + lag)
        }
        var policy = SnapClassificationPolicy()
        check(!emit(&policy, 0.1, 0.5), "silence")
        check(!emit(&policy, 0.6, 0.75), "below threshold")
        check(emit(&policy, 0.85, 1), "confident snap")
        check(!emit(&policy, 0.9, 1.25), "overlapping window")
        check(!emit(&policy, 0.9, 2.5), "continuous scores never repeat")
        check(!emit(&policy, 0.1, 2.75), "release")
        check(emit(&policy, 0.8, 3), "new episode")
        check(!emit(&policy, 0.1, 3.25), "release during cooldown")
        check(!emit(&policy, 0.9, 3.5), "cooldown")
        check(!emit(&policy, 0.9, 4.5), "suppressed episode cannot fire later")
        check(!emit(&policy, 0.1, 4.75), "second release")
        check(!emit(&policy, 0.8, 5, competing: 0.75), "competing clap/knock")
        check(!emit(&policy, 0.9, 5.25), "rejected episode still latched")
        check(!emit(&policy, 0.1, 5.5), "release after competing event")
        check(emit(&policy, 0.9, 5.75), "snap after competing episode")
        var stale = SnapClassificationPolicy()
        check(!emit(&stale, 0.9, 1, lag: 2), "stale result")
        check(!emit(&stale, 0.9, 1.25), "stale episode cannot replay")
        check(!emit(&stale, 0.1, 1.5), "stale release")
        check(emit(&stale, 0.9, 1.75), "fresh new episode")
        check(!emit(&stale, 0.1, 1.5), "out of order cannot rearm")
        check(!emit(&stale, 0.9, 3), "out of order release was ignored")
        check(!emit(&stale, .nan, 3.5), "invalid confidence")
        check(!emit(&stale, 1.1, 3.5), "out of range confidence")
        check(!emit(&stale, 0.9, 3.5, competing: .infinity), "invalid competitor")
        check(!emit(&stale, 0.9, 3.5, lag: -1), "future result")
        var reset = SnapClassificationPolicy()
        check(emit(&reset, 0.9, 0.5), "fresh session has no old latch")
        check(!emit(&reset, 0.1, 0.5), "duplicate window cannot rearm")
        check(!emit(&reset, 0.9, 2), "duplicate low did not rearm")
        var diagnostic = SnapClassificationPolicy()
        _ = emit(&diagnostic, 0.9, 1, lag: 2)
        check(diagnostic.lastDecision == "stale_or_future", "stale rejection must be observable")
        _ = emit(&diagnostic, 0.1, 1.5)
        check(diagnostic.lastDecision == "rearmed", "rearm must be observable")
        _ = emit(&diagnostic, 0.9, 1.75)
        check(diagnostic.lastDecision == "accepted", "accepted gesture must be observable")
        _ = emit(&diagnostic, 0.9, 2)
        check(diagnostic.lastDecision == "episode_not_rearmed", "latched gesture must be observable")
        var recent = LatestAnalysisQueue<Int>(capacity: 8)
        for index in 0..<1000 {
            let dropped = recent.enqueue(index)
            check(recent.count <= 8, "model stalls cannot grow pending audio without bound")
            check(dropped == (index < 8 ? nil : index - 8), "overflow evicts oldest input")
        }
        for expected in 992..<1000 {
            check(recent.dequeue() == expected, "recovery consumes recent audio in order")
        }
        check(recent.dequeue() == nil, "drained queue terminates")
        _ = recent.enqueue(1)
        recent.removeAll()
        check(recent.count == 0, "cancel releases pending audio")
        var timeline = SnapAudioTimeline()
        check(timeline.position(capturedAt: 100, frames: 4800, sampleRate: 48000) == 0, "first frame anchors time")
        check(timeline.position(capturedAt: 100.1, frames: 4800, sampleRate: 48000) == 4800, "continuous capture")
        check(timeline.position(capturedAt: 110, frames: 4800, sampleRate: 48000) == 480000, "input gaps advance real timeline")
        check(timeline.skippedFrames == 470400, "input gap is observable")
        check(timeline.position(capturedAt: 109, frames: 4800, sampleRate: 48000) == 484800, "clock jitter cannot reverse frame positions")
        var afterGap = SnapClassificationPolicy()
        afterGap.invalidateEpisode()
        check(!emit(&afterGap, 0.9, 1), "high score after discarded audio cannot replay an old gesture")
        _ = emit(&afterGap, 0.1, 1.25)
        check(emit(&afterGap, 0.9, 1.5), "fresh gesture works after post-gap release")
        print("PASS: \(checks) sound classification policy assertions; synthetic scores, not model accuracy")
    }
}
