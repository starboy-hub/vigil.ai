import Cocoa
import WebKit
import UserNotifications

class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate, WKScriptMessageHandler {
    var statusItem: NSStatusItem!
    var popover: NSPopover!
    var webView: WKWebView!
    var firewallProcess: Process?

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        // Run as Menu Bar accessory app (icon in top right menu bar, no dock clutter)
        NSApp.setActivationPolicy(.accessory)

        // Request notification permissions
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { granted, error in
            if let error = error {
                print("Notification permission error: \(error)")
            }
        }

        // Start Node.js VIGIL Firewall backend if not running
        startFirewallIfNeeded()

        // Setup System Tray / Menu Bar Status Item
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.title = "🛡️ VIGIL"
            button.target = self
            button.action = #selector(togglePopover(_:))
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        }

        // Create WebKit View
        let webConfiguration = WKWebViewConfiguration()
        let contentController = WKUserContentController()
        contentController.add(self, name: "vigilNative")
        webConfiguration.userContentController = contentController

        webView = WKWebView(frame: NSRect(x: 0, y: 0, width: 380, height: 620), configuration: webConfiguration)
        webView.navigationDelegate = self
        
        // Transparent background & sleek webview styling
        webView.setValue(false, forKey: "drawsBackground")

        // Create Popover
        popover = NSPopover()
        popover.contentSize = NSSize(width: 380, height: 620)
        popover.behavior = .transient
        popover.animates = true

        let viewController = NSViewController()
        viewController.view = webView
        popover.contentViewController = viewController

        // Load VIGIL Dashboard URL
        loadDashboard()

        // Global Event Monitor to close popover when clicking outside
        NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] event in
            if self?.popover.isShown == true {
                self?.popover.performClose(event)
            }
        }
    }

    func startFirewallIfNeeded() {
        // Check if firewall is listening on port 8765
        let checkTask = Process()
        checkTask.launchPath = "/usr/bin/curl"
        checkTask.arguments = ["-s", "-o", "/dev/null", "http://127.0.0.1:8765/vigil-dashboard"]
        
        let pipe = Pipe()
        checkTask.standardOutput = pipe
        checkTask.launch()
        checkTask.waitUntilExit()

        if checkTask.terminationStatus != 0 {
            print("🚀 VIGIL Backend not running. Starting companion/vigil-agent-firewall.js...")
            let firewall = Process()
            let bundlePath = Bundle.main.bundlePath
            let rootDir = (bundlePath as NSString).deletingLastPathComponent
            
            // Try node path
            firewall.launchPath = "/usr/local/bin/node"
            if !FileManager.default.fileExists(atPath: firewall.launchPath!) {
                firewall.launchPath = "/opt/homebrew/bin/node"
            }
            if !FileManager.default.fileExists(atPath: firewall.launchPath!) {
                firewall.launchPath = "/usr/bin/node"
            }

            let scriptPath = (rootDir as NSString).appendingPathComponent("companion/vigil-agent-firewall.js")
            firewall.arguments = [scriptPath, "--mode=guard"]
            
            do {
                try firewall.run()
                self.firewallProcess = firewall
                Thread.sleep(forTimeInterval: 1.5)
            } catch {
                print("Failed to start firewall process: \(error)")
            }
        }
    }

    func loadDashboard() {
        if let url = URL(string: "http://127.0.0.1:8765/vigil-dashboard") {
            let request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 10.0)
            webView.load(request)
        }
    }

    @objc func togglePopover(_ sender: AnyObject?) {
        guard let event = NSApp.currentEvent else { return }

        if event.type == .rightMouseUp {
            // Right click context menu
            let menu = NSMenu()
            menu.addItem(NSMenuItem(title: "🛡️ VIGIL Native Desktop Guardian", action: nil, keyEquivalent: ""))
            menu.addItem(NSMenuItem.separator())
            menu.addItem(NSMenuItem(title: "Show Dashboard", action: #selector(showPopover), keyEquivalent: "d"))
            menu.addItem(NSMenuItem(title: "Reload Dashboard", action: #selector(reloadDashboard), keyEquivalent: "r"))
            menu.addItem(NSMenuItem.separator())
            menu.addItem(NSMenuItem(title: "Quit VIGIL", action: #selector(quitApp), keyEquivalent: "q"))
            
            statusItem.menu = menu
            statusItem.button?.performClick(nil)
            statusItem.menu = nil
        } else {
            // Left click toggle popover
            if popover.isShown {
                popover.performClose(sender)
            } else {
                showPopover()
            }
        }
    }

    @objc func showPopover() {
        if let button = statusItem.button {
            NSApp.activate(ignoringOtherApps: true)
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        }
    }

    @objc func reloadDashboard() {
        loadDashboard()
    }

    @objc func quitApp() {
        firewallProcess?.terminate()
        NSApplication.shared.terminate(nil)
    }

    // MARK: - WKScriptMessageHandler for Native OS Alerts
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        if message.name == "vigilNative", let body = message.body as? [String: Any] {
            let title = body["title"] as? String ?? "🛡️ VIGIL Alert"
            let subtitle = body["subtitle"] as? String ?? ""
            let contentText = body["message"] as? String ?? ""

            sendNativeNotification(title: title, subtitle: subtitle, body: contentText)
        }
    }

    func sendNativeNotification(title: String, subtitle: String, body: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.subtitle = subtitle
        content.body = body
        content.sound = UNNotificationSound.default

        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request) { error in
            if let error = error {
                print("Error posting notification: \(error)")
            }
        }
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        print("Navigation failed: \(error.localizedDescription)")
        // Retry loading after a short delay if firewall is still spinning up
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) { [weak self] in
            self?.loadDashboard()
        }
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
