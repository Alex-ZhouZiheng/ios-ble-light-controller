import Foundation
import OSLog
import CryptoKit

// All disk work is serialized. No microphone data or credentials belong here.
final class DiagnosticLog {
    static let shared = DiagnosticLog()
    enum Level: String { case debug, info, warning, error }
    private let queue = DispatchQueue(label: "LampBLEProbe.diagnostics", qos: .utility)
    private let directory: URL
    private let maxBytes: Int
    private let maxFiles: Int
    private let retention: TimeInterval
    private let session = String(UUID().uuidString.prefix(8))
    private var sequence: UInt64 = 0
    private var fileSequence: UInt64 = 0
    private let started = ProcessInfo.processInfo.systemUptime
    private var file: URL?
    private var size = 0
    private var storageError: String?
    private let logger = Logger(subsystem: "LampBLEProbe", category: "diagnostics")

    init(directory: URL? = nil, maxBytes: Int = 1_000_000, maxFiles: Int = 10,
         retention: TimeInterval = 7 * 86400) {
        self.directory = directory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Diagnostics", isDirectory: true)
        self.maxBytes = max(1024, maxBytes)
        self.maxFiles = max(1, maxFiles)
        self.retention = retention
    }

    // Defense in depth for protocol messages. Callers must never pass secrets or raw audio.
    static func redact(_ message: String) -> String {
        if message.hasPrefix("Manufacturer data:") || message.hasPrefix("Service data ") || message.hasPrefix("Name:") {
            return "device_metadata=<redacted>"
        }
        if message.hasPrefix("READ value ") || message.hasPrefix("  ASCII:") {
            return "read_payload=<omitted>"
        }
        var result = message
        let uuidPattern = "(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        if let regex = try? NSRegularExpression(pattern: uuidPattern) {
            for match in regex.matches(in: result, range: NSRange(result.startIndex..., in: result)).reversed() {
                guard let range = Range(match.range, in: result) else { continue }
                let digest = SHA256.hash(data: Data(result[range].lowercased().utf8))
                let alias = digest.prefix(8).map { String(format: "%02x", $0) }.joined()
                result.replaceSubrange(range, with: "id:\(alias)")
            }
        }
        result = result.replacingOccurrences(of: "(?i)(\\bmac(?: address)?[=: ]+)[0-9a-f]{12}\\b", with: "$1<redacted>", options: .regularExpression)
        for pattern in [ "(?i)\\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\\b", "https?://[^\\s]+"] {
            result = result.replacingOccurrences(of: pattern, with: "<redacted>", options: .regularExpression)
        }
        return result
    }

    func record(_ category: String, _ event: String, level: Level = .info, detail: String = "") {
        let date = Date()
        let uptime = ProcessInfo.processInfo.systemUptime - started
        let boundedDetail = String(detail.prefix(4096))
        queue.async { [self] in
            let safe = Self.redact(boundedDetail).replacingOccurrences(of: "\n", with: "\\n").replacingOccurrences(of: "\r", with: "\\r")
            sequence += 1
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            let entry = "session=\(session) seq=\(sequence) \(formatter.string(from: date)) +\(String(format: "%.3f", uptime))s \(level.rawValue.uppercased()) [\(category)] \(event) \(safe)"
            let outputLogger = Logger(subsystem: "LampBLEProbe", category: category)
            switch level {
            case .debug: outputLogger.debug("\(event, privacy: .public) \(entry, privacy: .private)")
            case .info: outputLogger.info("\(event, privacy: .public) \(entry, privacy: .private)")
            case .warning: outputLogger.warning("\(event, privacy: .public) \(entry, privacy: .private)")
            case .error: outputLogger.error("\(event, privacy: .public) \(entry, privacy: .private)")
            }
            do { try append(Data((entry + "\n").utf8), now: date) }
            catch { let failure = error as NSError; storageError = "日志文件写入失败 domain=\(failure.domain) code=\(failure.code)"; logger.error("Diagnostic file write failed") }
        }
    }

    private func files() throws -> [URL] {
        try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.contentModificationDateKey])
            .filter { $0.pathExtension == "log" }.sorted { lhs, rhs in
                let left = (try? lhs.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                let right = (try? rhs.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                return left == right ? lhs.lastPathComponent < rhs.lastPathComponent : left < right
            }
    }

    private func append(_ data: Data, now: Date) throws {
        let manager = FileManager.default
        try manager.createDirectory(at: directory, withIntermediateDirectories: true)
        var resources = URLResourceValues(); resources.isExcludedFromBackup = true
        var folder = directory; try folder.setResourceValues(resources)
        if let current = file,
           let modified = try current.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate,
           now.timeIntervalSince(modified) > retention { file = nil }
        if file == nil || size + data.count > maxBytes {
            fileSequence += 1
            let next = directory.appendingPathComponent("\(Int64(Date().timeIntervalSince1970 * 1000))-\(session)-\(String(format: "%08llu", fileSequence)).log")
            try Data().write(to: next, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
            file = next; size = 0
        }
        guard let file else { return }
        let handle = try FileHandle(forWritingTo: file)
        defer { try? handle.close() }
        try handle.seekToEnd(); try handle.write(contentsOf: data)
        size += data.count
        try prune(now: now)
        storageError = nil
    }

    private func prune(now: Date) throws {
        var remaining: [URL] = []
        for url in try files() {
            let modified = try url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate ?? .distantPast
            if now.timeIntervalSince(modified) > retention && url.standardizedFileURL != file?.standardizedFileURL {
                try FileManager.default.removeItem(at: url)
            } else { remaining.append(url) }
        }
        while remaining.count > maxFiles {
            guard let index = remaining.firstIndex(where: { $0.standardizedFileURL != file?.standardizedFileURL }) else { break }
            try FileManager.default.removeItem(at: remaining.remove(at: index))
        }
    }

    // Queue barrier: includes every event submitted before the export request.
    func snapshot(context: String = "") -> String {
        queue.sync { makeSnapshot(context: context) }
    }

    func export(context: String, completion: @escaping (String) -> Void) {
        queue.async { [self] in
            let report = makeSnapshot(context: context)
            DispatchQueue.main.async { completion(report) }
        }
    }

    private func makeSnapshot(context: String) -> String {
        var output = "LampBLEProbe diagnostics\nexportedAt=\(ISO8601DateFormatter().string(from: Date())) timezone=\(TimeZone.current.identifier)\nsession=\(session)\n\(context)\n"
        do {
            if FileManager.default.fileExists(atPath: directory.path) {
                try prune(now: Date())
                for url in try files() {
                    output += "\n--- \(url.lastPathComponent) ---\n"
                    output += try String(contentsOf: url, encoding: .utf8)
                }
            }
        } catch { output += "\n诊断日志读取失败\n" }
        if let storageError { output += "\n\(storageError)\n" }
        return output
    }
}
