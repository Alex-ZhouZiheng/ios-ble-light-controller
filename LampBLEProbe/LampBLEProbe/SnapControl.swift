import AVFoundation
import Combine
import UIKit
import SoundAnalysis

// UI state stays on main; session and engine work is serialized off main.
final class SnapControl: ObservableObject {
    static let shared = SnapControl()
    @Published private(set) var enabled = UserDefaults.standard.bool(forKey: "LampBLEProbe.snapEnabled")
    @Published private(set) var status = "响指控制已关闭"
    @Published private(set) var lastResult = "尚未触发"
    private var healthTimer: Timer?
    private var pendingOperation: String?
    var diagnosticState: String {
        "snapEnabled=\(enabled) active=\(active) interrupted=\(interrupted) engineRunning=\(audioRunning) status=\(status) lastResult=\(lastResult)\n\(audioHealth)"
    }
    private var active = false
    private var interrupted = false
    private var requesting = false
    private var runtime: SnapAudioRuntime?
    private var audioRunning = false
    private var audioHealth = "audio=not_started"
    private var generation = UUID()
    private var observers: [NSObjectProtocol] = []

    private init() {
        let center = NotificationCenter.default
        observers.append(center.addObserver(forName: AVAudioSession.interruptionNotification, object: nil, queue: .main) { [weak self] note in
            guard let self, let raw = note.userInfo?[AVAudioSessionInterruptionTypeKey] as? UInt,
                  let type = AVAudioSession.InterruptionType(rawValue: raw) else { return }
            DiagnosticLog.shared.record("audio", "interruption", detail: "type=\(raw)")
            self.interrupted = type == .began
            if self.interrupted { self.stop(); self.status = "麦克风被占用，识别暂停" }
            else { self.reconcile() }
        })
        for name in [AVAudioSession.routeChangeNotification, AVAudioSession.mediaServicesWereResetNotification, .AVAudioEngineConfigurationChange] {
            observers.append(center.addObserver(forName: name, object: nil, queue: .main) { [weak self] note in
                guard let self, let current = self.runtime else { return }
                if name == .AVAudioEngineConfigurationChange {
                    guard let source = note.object as? AVAudioEngine, current.ownsEngine(source) else { return }
                }
                if name == AVAudioSession.routeChangeNotification {
                    guard let raw = note.userInfo?[AVAudioSessionRouteChangeReasonKey] as? UInt,
                          let reason = AVAudioSession.RouteChangeReason(rawValue: raw),
                          reason == .newDeviceAvailable || reason == .oldDeviceUnavailable || reason == .noSuitableRouteForCategory else { return }
                }
                DiagnosticLog.shared.record("audio", "configuration_changed", detail: "notification=\(name.rawValue)")
                self.stop()
                self.reconcile()
            })
        }
    }

    func setEnabled(_ value: Bool) {
        DiagnosticLog.shared.record("snap", "enabled_changed", detail: "value=\(value)")
        enabled = value
        UserDefaults.standard.set(value, forKey: "LampBLEProbe.snapEnabled")
        reconcile()
    }

    func setActive(_ value: Bool) {
        DiagnosticLog.shared.record("snap", "active_changed", detail: "value=\(value)")
        active = value
        reconcile()
    }

    private func reconcile() {
        guard enabled, active, !interrupted else {
            stop()
            status = !enabled ? "响指控制已关闭" : interrupted ? "麦克风被占用，识别暂停" : "离开前台，识别暂停"
            return
        }
        DiagnosticLog.shared.record("audio", "reconcile", detail: "permission=\(AVAudioApplication.shared.recordPermission.rawValue) interrupted=\(interrupted)")
        switch AVAudioApplication.shared.recordPermission {
        case .undetermined:
            guard !requesting else { return }
            requesting = true
            status = "等待麦克风授权"
            AVAudioApplication.requestRecordPermission { [weak self] _ in
                DispatchQueue.main.async {
                    self?.requesting = false
                    self?.reconcile()
                }
            }
        case .denied:
            stop()
            status = "请在系统设置中允许麦克风访问"
        case .granted:
            if runtime == nil { start() }
        @unknown default:
            status = "麦克风权限不可用"
        }
    }

    private func start() {
        let token = UUID()
        generation = token
        status = "正在启动声音识别"
        let next = SnapAudioRuntime()
        runtime = next
        next.start(onStarted: { [weak self] in
            guard let self, self.generation == token, self.runtime != nil else { return }
            self.audioRunning = true
            self.status = "Apple 内置分类器正在监听单响指"
            DiagnosticLog.shared.record("audio", "started", detail: "session=\(token)")
            let timer = Timer(timeInterval: 30, repeats: true) { [weak self] _ in
                guard let self, let runtime = self.runtime else { return }
                runtime.sampleHealth { [weak self] running, healthy, detail in
                    guard let self, self.generation == token else { return }
                    self.audioRunning = running
                    self.audioHealth = detail
                    DiagnosticLog.shared.record("audio", "health", level: healthy ? .info : .warning,
                                                detail: "engineRunning=\(running) \(detail)")
                    self.status = healthy ? "Apple 内置分类器正在监听单响指" : "监听异常：音频输入、分类结果或时间轴异常，可关闭后重试"
                }
            }
            self.healthTimer = timer
            RunLoop.main.add(timer, forMode: .common)
        }, onSnap: { [weak self] id in
            let detectedAt = ProcessInfo.processInfo.systemUptime
            DispatchQueue.main.async {
                guard ProcessInfo.processInfo.systemUptime - detectedAt <= 0.5 else {
                    DiagnosticLog.shared.record("snap", "dispatch_dropped", level: .warning, detail: "id=\(id) reason=main_queue_delay")
                    return
                }
                guard let self, self.generation == token, self.enabled, self.active, self.runtime != nil else { return }
                self.trigger(id: id)
            }
        }, onFailure: { [weak self] message in
            guard let self, self.generation == token else { return }
            DiagnosticLog.shared.record("audio", "analysis_failed", level: .error, detail: message)
            self.stop()
            self.status = message
        })
    }

    private func stop() {
        healthTimer?.invalidate(); healthTimer = nil
        generation = UUID()
        let old = runtime
        runtime = nil
        audioRunning = false
        audioHealth = "audio=stopped"
        old?.stop()
    }

    private func trigger(id: String) {
        let probe = BluetoothProbe.shared
        guard probe.hubRunning, probe.controlReady, let power = probe.lastConfirmedPower else {
            DiagnosticLog.shared.record("snap", "trigger_ignored", level: .warning, detail: "id=\(id) hub=\(probe.hubRunning) ready=\(probe.controlReady) knownPower=\(probe.lastConfirmedPower != nil)")
            lastResult = "已识别；蓝牙未就绪或正在执行，本次忽略"
            return
        }
        pendingOperation = id
        guard probe.setLampOn(!power, source: "snap", diagnosticID: id) else {
            pendingOperation = nil
            lastResult = "已识别；指令未被接受"
            return
        }
        lastResult = "\(Date().formatted(date: .omitted, time: .standard)) 已请求" + (power ? "关灯，等待回读" : "开灯，等待回读")
    }
    func operationCompleted(id: String, power: Bool?, error: String?) {
        guard pendingOperation == id else { return }
        pendingOperation = nil
        let time = Date().formatted(date: .omitted, time: .standard)
        if error != nil { lastResult = "\(time) 操作失败或回读未确认" }
        else if let power { lastResult = "\(time) " + (power ? "开灯已回读确认" : "关灯已回读确认") }
    }
}

// One shared queue orders old-session teardown before new-session activation,
// including rapid toggle, route-change and interruption callbacks.
private final class SnapAudioRuntime {
    private static let queue = DispatchQueue(label: "LampBLEProbe.audioLifecycle", qos: .userInitiated)
    private let lock = NSLock()
    private var cancelled = false
    private weak var engineIdentity: AVAudioEngine? // protected by lock
    private var engine: AVAudioEngine? // lifecycle queue only
    private var classification: SnapSoundAnalyzer? // lifecycle queue only
    private var activated = false
    private var tapInstalled = false

    private var isCancelled: Bool {
        lock.lock(); defer { lock.unlock() }
        return cancelled
    }

    func ownsEngine(_ candidate: AVAudioEngine) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return engineIdentity === candidate
    }

    func start(onStarted: @escaping () -> Void, onSnap: @escaping (String) -> Void,
               onFailure: @escaping (String) -> Void) {
        Self.queue.async { [self] in
            guard !isCancelled else { return }
            dispatchPrecondition(condition: .notOnQueue(.main))
            let audio = AVAudioSession.sharedInstance()
            do {
                try audio.setCategory(.record, mode: .measurement, options: [])
                // Compatible with iOS 17+: this blocking call never runs on main.
                try audio.setActive(true)
                activated = true
                guard !isCancelled else { cleanup(); return }
                let next = AVAudioEngine()
                engine = next
                lock.lock(); engineIdentity = next; lock.unlock()
                let input = next.inputNode
                let format = input.outputFormat(forBus: 0)
                guard format.sampleRate > 0, format.channelCount > 0 else {
                    cleanup()
                    DispatchQueue.main.async { onFailure("没有可用麦克风，可关闭后重试") }
                    return
                }
                DiagnosticLog.shared.record("audio", "starting", detail: "sampleRate=\(format.sampleRate) channels=\(format.channelCount)")
                let analyzer = try SnapSoundAnalyzer(format: format, onSnap: onSnap, onFailure: { message in
                    DispatchQueue.main.async { onFailure(message) }
                })
                classification = analyzer
                guard !isCancelled else { cleanup(); return }
                input.installTap(onBus: 0, bufferSize: 4096, format: format) { buffer, time in
                    analyzer.consume(buffer, at: time)
                }
                tapInstalled = true
                next.prepare()
                try next.start()
                guard !isCancelled else { cleanup(); return }
                DispatchQueue.main.async { onStarted() }
            } catch {
                let failure = error as NSError
                DiagnosticLog.shared.record("audio", "start_failed", level: .error, detail: "domain=\(failure.domain) code=\(failure.code)")
                cleanup()
                let message = (error as? SnapSoundAnalyzer.SetupError)?.message ?? "声音识别启动失败，可关闭后重试"
                DispatchQueue.main.async { onFailure(message) }
            }
        }
    }

    func sampleHealth(completion: @escaping (Bool, Bool, String) -> Void) {
        Self.queue.async { [self] in
            guard !isCancelled else { return }
            let health = classification?.health()
            let running = engine?.isRunning == true
            let healthy = running && health?.healthy == true
            let detail = health?.detail ?? "audio=not_started"
            DispatchQueue.main.async { completion(running, healthy, detail) }
        }
    }

    func stop() {
        lock.lock(); cancelled = true; lock.unlock()
        Self.queue.async { [self] in cleanup() }
    }

    private func cleanup() {
        dispatchPrecondition(condition: .onQueue(Self.queue))
        if let classification {
            DiagnosticLog.shared.record("audio", "stopped", detail: classification.health().detail)
            classification.cancel()
        }
        classification = nil
        engine?.stop()
        if tapInstalled { engine?.inputNode.removeTap(onBus: 0) }
        tapInstalled = false
        engine = nil
        lock.lock(); engineIdentity = nil; lock.unlock()
        if activated {
            do { try AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation) }
            catch {
                let failure = error as NSError
                DiagnosticLog.shared.record("audio", "deactivate_failed", level: .warning, detail: "domain=\(failure.domain) code=\(failure.code)")
            }
        }
        activated = false
    }
}

// Copy tap buffers before returning. Keep only bounded recent work on overload;
// never replay stale gestures or classify across discarded audio.
private final class SnapSoundAnalyzer: NSObject, SNResultsObserving {
    enum SetupError: Error {
        case unsupportedLabel
        case unsupportedFormat
        var message: String {
            switch self {
            case .unsupportedLabel: return "此系统内置分类器不支持响指，识别未启动"
            case .unsupportedFormat: return "麦克风音频格式不受支持，识别未启动"
            }
        }
    }
    private let analyzer: SNAudioStreamAnalyzer
    private let queue = DispatchQueue(label: "LampBLEProbe.soundAnalysis", qos: .userInitiated)
    private struct PendingAudio {
        let buffer: AVAudioPCMBuffer
        let position: AVAudioFramePosition
        let capturedEnd: TimeInterval
    }
    private var pending = LatestAnalysisQueue<PendingAudio>() // protected by lock
    private var draining = false // protected by lock
    private var timeline = SnapAudioTimeline() // protected by lock
    private var droppedBuffers = 0 // protected by lock
    private var droppedQueuedBuffers = 0 // protected by lock
    private var validAfter = 0.0 // protected by lock
    private var lastGap: TimeInterval? // protected by lock
    private let lock = NSLock()
    private var cancelled = false
    private var policy = SnapClassificationPolicy() // protected by lock
    private let created = ProcessInfo.processInfo.systemUptime
    private var lastBuffer: TimeInterval?
    private var lastClassification: TimeInterval?
    private var bufferCount = 0
    private var resultCount = 0
    private var decisions: [String: Int] = [:]
    private var latestScore = 0.0
    private var latestLag = 0.0
    private let onSnap: (String) -> Void
    private let onFailure: (String) -> Void

    init(format: AVAudioFormat, onSnap: @escaping (String) -> Void, onFailure: @escaping (String) -> Void) throws {
        guard format.commonFormat == .pcmFormatFloat32, !format.isInterleaved else { throw SetupError.unsupportedFormat }
        let request = try SNClassifySoundRequest(classifierIdentifier: .version1)
        guard request.knownClassifications.contains("finger_snapping") else { throw SetupError.unsupportedLabel }
        // The framework rounds this to a supported duration on the current OS.
        request.windowDuration = CMTime(seconds: 0.5, preferredTimescale: 16000)
        request.overlapFactor = 0.5
        analyzer = SNAudioStreamAnalyzer(format: format)
        self.onSnap = onSnap
        self.onFailure = onFailure
        super.init()
        try analyzer.add(request, withObserver: self)
    }

    func health() -> (healthy: Bool, detail: String) {
        lock.lock(); defer { lock.unlock() }
        let now = ProcessInfo.processInfo.systemUptime
        let bufferAge = now - (lastBuffer ?? created)
        let resultAge = now - (lastClassification ?? created)
        let detail = "buffers=\(bufferCount) results=\(resultCount) bufferAge=\(String(format: "%.2f", bufferAge)) resultAge=\(String(format: "%.2f", resultAge)) score=\(String(format: "%.3f", latestScore)) lag=\(String(format: "%.3f", latestLag)) pending=\(pending.count) droppedBuffers=\(droppedBuffers) droppedQueuedBuffers=\(droppedQueuedBuffers) decisions=\(decisions.sorted { $0.key < $1.key })"
        return (!cancelled && bufferAge < 5 && resultAge < 5 && abs(latestLag) <= 1.25 && now - (lastGap ?? -.infinity) > 2, detail)
    }

    private var isCancelled: Bool {
        lock.lock(); defer { lock.unlock() }
        return cancelled
    }

    func cancel() {
        lock.lock(); cancelled = true; pending.removeAll(); lock.unlock()
        queue.async { [self] in analyzer.removeAllRequests() }
    }

    private func fail(_ message: String) {
        lock.lock()
        let notify = !cancelled
        cancelled = true
        lock.unlock()
        if notify { onFailure(message) }
    }

    func consume(_ buffer: AVAudioPCMBuffer, at time: AVAudioTime) {
        guard !isCancelled, buffer.frameLength > 0 else { return }
        let duration = Double(buffer.frameLength) / buffer.format.sampleRate
        let capturedAt = time.isHostTimeValid ? AVAudioTime.seconds(forHostTime: time.hostTime)
            : ProcessInfo.processInfo.systemUptime - duration
        lock.lock()
        let framePosition = timeline.position(capturedAt: capturedAt, frames: buffer.frameLength,
                                              sampleRate: buffer.format.sampleRate)
        if Double(timeline.skippedFrames) / buffer.format.sampleRate > 0.02 {
            validAfter = max(validAfter, Double(framePosition) / buffer.format.sampleRate)
            policy.invalidateEpisode()
            lastGap = ProcessInfo.processInfo.systemUptime
            decisions["input_timeline_gap", default: 0] += 1
        }
        bufferCount += 1
        lastBuffer = ProcessInfo.processInfo.systemUptime
        lock.unlock()
        guard let copy = AVAudioPCMBuffer(pcmFormat: buffer.format, frameCapacity: buffer.frameLength),
              let source = buffer.floatChannelData, let destination = copy.floatChannelData else {
            fail("音频缓冲区不可用，识别已暂停")
            return
        }
        copy.frameLength = buffer.frameLength
        for channel in 0..<Int(buffer.format.channelCount) {
            destination[channel].update(from: source[channel], count: Int(buffer.frameLength))
        }
        let item = PendingAudio(buffer: copy, position: framePosition, capturedEnd: capturedAt + duration)
        lock.lock()
        guard !cancelled else { lock.unlock(); return }
        if let discarded = pending.enqueue(item) {
            droppedBuffers += 1
            invalidate(discarded)
        }
        let schedule = !draining
        draining = true
        lock.unlock()
        // Only one drain task exists, regardless of how long model warmup takes.
        if schedule { queue.async { [self] in drain() } }
    }

    // Lock must be held. A future result needs a complete post-gap window and
    // a fresh low-confidence release before it may trigger another operation.
    private func invalidate(_ item: PendingAudio) {
        let end = Double(item.position + Int64(item.buffer.frameLength)) / item.buffer.format.sampleRate
        validAfter = max(validAfter, end)
        lastGap = ProcessInfo.processInfo.systemUptime
        policy.invalidateEpisode()
    }

    private func drain() {
        while true {
            lock.lock()
            guard !cancelled, let item = pending.dequeue() else {
                draining = false
                lock.unlock()
                return
            }
            if ProcessInfo.processInfo.systemUptime - item.capturedEnd > 0.5 {
                droppedQueuedBuffers += 1
                invalidate(item)
                lock.unlock()
                continue
            }
            lock.unlock()
            analyzer.analyze(item.buffer, atAudioFramePosition: item.position)
        }
    }

    func request(_ request: SNRequest, didProduce result: SNResult) {
        guard !isCancelled, let result = result as? SNClassificationResult else { return }
        let score = result.classification(forIdentifier: "finger_snapping")?.confidence ?? 0
        let competing = max(result.classification(forIdentifier: "clapping")?.confidence ?? 0,
                            result.classification(forIdentifier: "knock")?.confidence ?? 0)
        let start = result.timeRange.start.seconds
        let end = CMTimeRangeGetEnd(result.timeRange).seconds
        lock.lock()
        let shouldTrigger: Bool
        if !cancelled, let origin = timeline.origin {
            lastClassification = ProcessInfo.processInfo.systemUptime
            resultCount += 1
            latestScore = score
            latestLag = ProcessInfo.processInfo.systemUptime - origin - end
            if start < validAfter {
                policy.invalidateEpisode()
                decisions["discarded_audio_gap", default: 0] += 1
                shouldTrigger = false
            } else {
                shouldTrigger = policy.process(score: score, competing: competing, start: start, end: end,
                                               now: ProcessInfo.processInfo.systemUptime - origin)
                decisions[policy.lastDecision, default: 0] += 1
            }
        } else { shouldTrigger = false }
        lock.unlock()
        if shouldTrigger {
            let id = UUID().uuidString
            DiagnosticLog.shared.record("snap", "recognized", detail: "id=\(id) score=\(score) competing=\(competing) start=\(start) end=\(end)")
            onSnap(id)
        }
    }

    func request(_ request: SNRequest, didFailWithError error: Error) {
        let failure = error as NSError
        DiagnosticLog.shared.record("audio", "classifier_error", level: .error, detail: "domain=\(failure.domain) code=\(failure.code)")
        fail("Apple 声音分析失败，已暂停；可关闭后重试")
    }

    func requestDidComplete(_ request: SNRequest) {
        if !isCancelled { fail("声音分析已结束，可关闭后重试") }
    }
}
