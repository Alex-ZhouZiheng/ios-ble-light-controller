import AppIntents

struct TurnOnLampIntent: AppIntent {
    static var title: LocalizedStringResource = "打开家里的灯"
    static var description = IntentDescription("通过本机蓝牙登录已保存的灯，明确设置为开启，并回读确认。")
    static var openAppWhenRun: Bool = false
    static var authenticationPolicy: IntentAuthenticationPolicy = .alwaysAllowed
    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        let state = try await BluetoothProbe.shared.performSavedOperation(desired: true)
        guard state else { throw LampOperationError(message: "回读未确认灯已开启") }
        return .result(dialog: "开灯操作已确认，回读为开启。")
    }
}

struct TurnOffLampIntent: AppIntent {
    static var title: LocalizedStringResource = "关闭家里的灯"
    static var description = IntentDescription("通过本机蓝牙登录已保存的灯，明确设置为关闭，并回读确认。")
    static var openAppWhenRun: Bool = false
    static var authenticationPolicy: IntentAuthenticationPolicy = .alwaysAllowed
    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        let state = try await BluetoothProbe.shared.performSavedOperation(desired: false)
        guard !state else { throw LampOperationError(message: "回读未确认灯已关闭") }
        return .result(dialog: "关灯操作已确认，回读为关闭。")
    }
}

struct LampShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: TurnOnLampIntent(), phrases: ["用\(.applicationName)打开家里的灯"], shortTitle: "打开家里的灯", systemImageName: "lightbulb")
        AppShortcut(intent: TurnOffLampIntent(), phrases: ["用\(.applicationName)关闭家里的灯"], shortTitle: "关闭家里的灯", systemImageName: "lightbulb.slash")
    }
}
