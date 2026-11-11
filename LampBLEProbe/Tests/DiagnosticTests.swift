import Foundation

@main struct DiagnosticTests {
    static func main() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let log = DiagnosticLog(directory: root, maxBytes: 1024, maxFiles: 3)
        let id = "5FB0D499-C6A0-4816-A1F9-E83D4A975B94"
        let alias = DiagnosticLog.redact(id)
        precondition(!alias.contains(id) && alias.hasPrefix("id:"))
        precondition(alias == DiagnosticLog.redact(id.lowercased()))
        precondition(alias != DiagnosticLog.redact("6FB0D499-C6A0-4816-A1F9-E83D4A975B94"))
        precondition(DiagnosticLog.redact("AA:BB:CC:DD:EE:FF https://example.test/secret") == "<redacted> <redacted>")
        precondition(DiagnosticLog.redact("Manufacturer data: aabbccddeeff") == "device_metadata=<redacted>")
        precondition(DiagnosticLog.redact("READ value 001B: deadbeef") == "read_payload=<omitted>")
        precondition(DiagnosticLog.redact("header=000000000100") == "header=000000000100", "protocol headers are not device MAC addresses")
        precondition(DiagnosticLog.redact("MAC=AABBCCDDEEFF") == "MAC=<redacted>")
        for index in 0..<25 {
            log.record("test", "event", detail: "index=\(index) " + String(repeating: "x", count: 200))
        }
        let output = log.snapshot(context: "health=test")
        precondition(output.contains("index=24"), "snapshot must drain pending writes")
        precondition(!output.contains("index=0 "), "old segments must rotate out")
        let files = try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)
        precondition(files.count <= 3 && !files.isEmpty)
        for file in files {
            let size = try file.resourceValues(forKeys: [.fileSizeKey]).fileSize!
            precondition(size <= 1024, "segment must remain bounded")
        }
        log.record("test", "escaped", detail: "line1\nforged entry\rnext")
        let escaped = log.snapshot()
        precondition(escaped.contains("line1\\nforged entry\\rnext"), "dynamic newlines cannot forge entries")
        var exported: String?
        log.export(context: "async-export") { report in
            precondition(Thread.isMainThread, "export completion must reach UI on main thread")
            exported = report
        }
        let deadline = Date(timeIntervalSinceNow: 5)
        while exported == nil && Date() < deadline {
            _ = RunLoop.main.run(mode: .default, before: Date(timeIntervalSinceNow: 0.01))
        }
        precondition(exported?.contains("async-export") == true, "async export must complete")
        let reopened = DiagnosticLog(directory: root, maxBytes: 1024, maxFiles: 3)
        precondition(reopened.snapshot().contains("index=24"), "logs must survive logger recreation")
        let expired = root.appendingPathComponent("000-old.log")
        try Data("old event".utf8).write(to: expired)
        try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSinceNow: -8 * 86400)], ofItemAtPath: expired.path)
        _ = reopened.snapshot()
        precondition(!FileManager.default.fileExists(atPath: expired.path), "expired files must be pruned")
        let blocked = root.appendingPathComponent("blocked")
        try Data().write(to: blocked)
        let unavailable = DiagnosticLog(directory: blocked)
        unavailable.record("test", "failure")
        precondition(unavailable.snapshot().contains("日志文件写入失败"), "export must disclose storage failure")
        print("Diagnostic logging: rotation, retention, persistence, redaction, queue barrier and I/O failure checks passed")
    }
}
