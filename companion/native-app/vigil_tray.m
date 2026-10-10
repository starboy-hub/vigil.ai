#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>
#import <UserNotifications/UserNotifications.h>

@interface AppDelegate : NSObject <NSApplicationDelegate, WKNavigationDelegate, WKScriptMessageHandler, UNUserNotificationCenterDelegate>
@property (strong, nonatomic) NSStatusItem *statusItem;
@property (strong, nonatomic) NSPopover *popover;
@property (strong, nonatomic) WKWebView *webView;
@property (strong, nonatomic) NSTask *firewallTask;
@property (assign, nonatomic) BOOL isLoaded;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    self.isLoaded = NO;

    // 1. Run as Menu Bar Accessory App (Icon in Top Status Bar, no Dock icon clutter)
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];

    // 2. Request OS Notification Permissions
    if (@available(macOS 10.14, *)) {
        UNUserNotificationCenter *center = [UNUserNotificationCenter currentNotificationCenter];
        center.delegate = self;
        [center requestAuthorizationWithOptions:(UNAuthorizationOptionAlert | UNAuthorizationOptionSound | UNAuthorizationOptionBadge)
                              completionHandler:^(BOOL granted, NSError * _Nullable error) {
            if (error) {
                NSLog(@"[VIGIL Native] Notification Auth Error: %@", error);
            }
        }];
    }

    // 3. Ensure VIGIL Agent Firewall Backend is running
    [self startFirewallIfNeeded];

    // 4. Create Menu Bar Status Item (System Tray) with Minimalist Template Icon
    self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
    NSStatusBarButton *button = self.statusItem.button;
    if (button) {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
        NSString *resDir = [bundlePath stringByAppendingPathComponent:@"Contents/Resources"];
        NSString *iconPath = [resDir stringByAppendingPathComponent:@"shield_template.png"];

        if (![fm fileExistsAtPath:iconPath]) {
            NSString *nativeAppDir = [bundlePath stringByDeletingLastPathComponent];
            iconPath = [nativeAppDir stringByAppendingPathComponent:@"shield_template.png"];
        }

        NSImage *menuIcon = [[NSImage alloc] initWithContentsOfFile:iconPath];
        if (menuIcon) {
            [menuIcon setTemplate:YES];
            [menuIcon setSize:NSMakeSize(18, 18)];
            button.image = menuIcon;
            button.title = @"";
        } else {
            button.title = @"🛡️";
        }

        button.target = self;
        button.action = @selector(statusItemClicked:);
        [button sendActionOn:NSEventMaskLeftMouseUp | NSEventMaskRightMouseUp];
    }

    // 5. Create WebKit View
    WKWebViewConfiguration *config = [[WKWebViewConfiguration alloc] init];
    WKUserContentController *userController = [[WKUserContentController alloc] init];
    [userController addScriptMessageHandler:self name:@"vigilNative"];
    config.userContentController = userController;

    self.webView = [[WKWebView alloc] initWithFrame:NSMakeRect(0, 0, 380, 630) configuration:config];
    self.webView.navigationDelegate = self;
    [self.webView setValue:@NO forKey:@"drawsBackground"];

    // 6. Create Native Popover
    self.popover = [[NSPopover alloc] init];
    self.popover.contentSize = NSMakeSize(380, 630);
    self.popover.behavior = NSPopoverBehaviorTransient;
    self.popover.animates = YES;

    NSViewController *vc = [[NSViewController alloc] init];
    vc.view = self.webView;
    self.popover.contentViewController = vc;

    // 7. Load Dashboard
    [self loadDashboard];

    // 8. Close popover when user clicks outside window
    [NSEvent addGlobalMonitorForEventsMatchingMask:(NSEventMaskLeftMouseDown | NSEventMaskRightMouseDown) handler:^(NSEvent *event) {
        if (self.popover.isShown) {
            [self.popover performClose:event];
        }
    }];

    NSLog(@"[VIGIL Native] Desktop Guardian Menu Bar Tray App initialized with custom template icon.");
}

- (void)startFirewallIfNeeded {
    // Ping port 8765
    NSTask *checkTask = [[NSTask alloc] init];
    checkTask.launchPath = @"/usr/bin/curl";
    checkTask.arguments = @[@"-s", @"-o", @"/dev/null", @"http://127.0.0.1:8765/vigil-dashboard"];
    
    @try {
        [checkTask launch];
        [checkTask waitUntilExit];
        
        if ([checkTask terminationStatus] != 0) {
            NSLog(@"[VIGIL Native] Backend not detected on 8765. Resolving vigil-agent-firewall.js...");
            NSFileManager *fm = [NSFileManager defaultManager];
            NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
            NSString *nativeAppDir = [bundlePath stringByDeletingLastPathComponent];
            NSString *companionDir = [nativeAppDir stringByDeletingLastPathComponent];
            NSString *rootDir = [companionDir stringByDeletingLastPathComponent];

            NSString *scriptPath = [companionDir stringByAppendingPathComponent:@"vigil-agent-firewall.js"];
            if (![fm fileExistsAtPath:scriptPath]) {
                scriptPath = [rootDir stringByAppendingPathComponent:@"companion/vigil-agent-firewall.js"];
            }

            NSLog(@"[VIGIL Native] Launching script path: %@", scriptPath);
            
            // Resolve node executable path
            NSString *nodePath = @"/usr/local/bin/node";
            if (![fm fileExistsAtPath:nodePath]) {
                nodePath = @"/opt/homebrew/bin/node";
            }
            if (![fm fileExistsAtPath:nodePath]) {
                nodePath = @"/usr/bin/node";
            }

            self.firewallTask = [[NSTask alloc] init];
            self.firewallTask.launchPath = nodePath;
            self.firewallTask.arguments = @[scriptPath, @"--mode=guard"];
            [self.firewallTask launch];
            
            [NSThread sleepForTimeInterval:1.2];
        }
    } @catch (NSException *exception) {
        NSLog(@"[VIGIL Native] Exception launching backend: %@", exception);
    }
}

- (void)loadDashboard {
    NSURL *url = [NSURL URLWithString:@"http://127.0.0.1:8765/vigil-dashboard"];
    NSURLRequest *req = [NSURLRequest requestWithURL:url cachePolicy:NSURLRequestReloadIgnoringLocalCacheData timeoutInterval:5.0];
    [self.webView loadRequest:req];
}

- (void)statusItemClicked:(id)sender {
    NSEvent *event = [NSApp currentEvent];
    if (event.type == NSEventTypeRightMouseUp) {
        NSMenu *menu = [[NSMenu alloc] init];
        [menu addItemWithTitle:@"🛡️ Vigil AI Native Desktop Guardian" action:nil keyEquivalent:@""];
        [menu addItem:[NSMenuItem separatorItem]];
        [menu addItemWithTitle:@"Open Dashboard" action:@selector(showPopover) keyEquivalent:@"d"];
        [menu addItemWithTitle:@"Reload View" action:@selector(loadDashboard) keyEquivalent:@"r"];
        [menu addItem:[NSMenuItem separatorItem]];
        [menu addItemWithTitle:@"Quit Vigil AI" action:@selector(quitApp) keyEquivalent:@"q"];
        
        self.statusItem.menu = menu;
        [self.statusItem.button performClick:nil];
        self.statusItem.menu = nil;
    } else {
        if (self.popover.isShown) {
            [self.popover performClose:sender];
        } else {
            [self showPopover];
        }
    }
}

- (void)showPopover {
    NSStatusBarButton *button = self.statusItem.button;
    if (button) {
        [self loadDashboard];
        [NSApp activateIgnoringOtherApps:YES];
        [self.popover showRelativeToRect:button.bounds ofView:button preferredEdge:NSRectEdgeMinY];
    }
}

- (void)quitApp {
    if (self.firewallTask && [self.firewallTask isRunning]) {
        [self.firewallTask terminate];
    }
    [NSApp terminate:nil];
}

#pragma mark - WKScriptMessageHandler
- (void)userContentController:(WKUserContentController *)userContentController didReceiveScriptMessage:(WKScriptMessage *)message {
    if ([message.name isEqualToString:@"vigilNative"] && [message.body isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dict = (NSDictionary *)message.body;
        NSString *title = dict[@"title"] ?: @"🛡️ Vigil AI Threat Blocked";
        NSString *body = dict[@"message"] ?: @"Shield active.";

        [self showNativeNotificationWithTitle:title body:body];
    }
}

- (void)showNativeNotificationWithTitle:(NSString *)title body:(NSString *)body {
    if (@available(macOS 10.14, *)) {
        UNMutableNotificationContent *content = [[UNMutableNotificationContent alloc] init];
        content.title = title;
        content.body = body;
        content.sound = [UNNotificationSound defaultSound];

        UNNotificationRequest *request = [UNNotificationRequest requestWithIdentifier:[[NSUUID UUID] UUIDString] content:content trigger:nil];
        [[UNUserNotificationCenter currentNotificationCenter] addNotificationRequest:request withCompletionHandler:nil];
    }
}

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {
    self.isLoaded = YES;
}

- (void)webView:(WKWebView *)webView didFailProvisionalNavigation:(WKNavigation *)navigation withError:(NSError *)error {
    NSLog(@"[VIGIL Native] Web view failed provisional load: %@", error.localizedDescription);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [self loadDashboard];
    });
}

- (void)webView:(WKWebView *)webView didFailNavigation:(WKNavigation *)navigation withError:(NSError *)error {
    NSLog(@"[VIGIL Native] Web view failed load: %@", error.localizedDescription);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [self loadDashboard];
    });
}

// Show notifications even when app is active
- (void)userNotificationCenter:(UNUserNotificationCenter *)center willPresentNotification:(UNNotification *)notification withCompletionHandler:(void (^)(UNNotificationPresentationOptions options))completionHandler {
    if (@available(macOS 10.14, *)) {
        completionHandler(UNNotificationPresentationOptionList | UNNotificationPresentationOptionBanner | UNNotificationPresentationOptionSound);
    }
}

@end

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSApplication *app = [NSApplication sharedApplication];
        AppDelegate *delegate = [[AppDelegate alloc] init];
        app.delegate = delegate;
        [app run];
    }
    return 0;
}
