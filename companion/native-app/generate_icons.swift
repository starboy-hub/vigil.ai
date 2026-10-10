import Cocoa
import CoreGraphics

func createShieldTemplateIcon(size: CGFloat) -> NSImage {
    let img = NSImage(size: NSSize(width: size, height: size))
    img.lockFocus()

    let ctx = NSGraphicsContext.current?.cgContext
    ctx?.clear(CGRect(x: 0, y: 0, width: size, height: size))

    let pad: CGFloat = size * 0.15
    let w = size - (pad * 2)
    let h = size - (pad * 2)

    let path = NSBezierPath()
    let topMid = NSPoint(x: size / 2, y: size - pad)
    let topRight = NSPoint(x: size - pad, y: size - pad)
    let botMid = NSPoint(x: size / 2, y: pad)
    let topLeft = NSPoint(x: pad, y: size - pad)

    path.move(to: topMid)
    path.line(to: topRight)
    path.curve(to: botMid, controlPoint1: NSPoint(x: size - pad, y: pad + h * 0.4), controlPoint2: NSPoint(x: size / 2 + w * 0.2, y: pad))
    path.curve(to: topLeft, controlPoint1: NSPoint(x: size / 2 - w * 0.2, y: pad), controlPoint2: NSPoint(x: pad, y: pad + h * 0.4))
    path.line(to: topMid)
    path.close()

    // Fill with black (template image uses alpha/black mask for macOS menu bar)
    NSColor.black.setFill()
    path.fill()

    // Inner cutout checkmark / emblem for sharp modern look
    let check = NSBezierPath()
    check.move(to: NSPoint(x: size * 0.35, y: size * 0.5))
    check.line(to: NSPoint(x: size * 0.46, y: size * 0.38))
    check.line(to: NSPoint(x: size * 0.68, y: size * 0.62))
    check.lineWidth = size * 0.1
    check.lineCapStyle = .round
    check.lineJoinStyle = .round

    ctx?.setBlendMode(.clear)
    check.stroke()

    img.unlockFocus()
    img.isTemplate = true
    return img
}

func createAppIcon(size: CGFloat) -> NSImage {
    let img = NSImage(size: NSSize(width: size, height: size))
    img.lockFocus()

    let ctx = NSGraphicsContext.current?.cgContext

    // macOS Dark Glass Background Squircle
    let rect = NSRect(x: 0, y: 0, width: size, height: size)
    let cornerRadius = size * 0.223
    let bgPath = NSBezierPath(roundedRect: rect, xRadius: cornerRadius, yRadius: cornerRadius)

    // Dark Gradient Background
    let bgGradient = NSGradient(colors: [
        NSColor(red: 0.08, green: 0.11, blue: 0.15, alpha: 1.0),
        NSColor(red: 0.03, green: 0.04, blue: 0.06, alpha: 1.0)
    ])!
    bgGradient.draw(in: bgPath, angle: -45)

    // Glowing Outer Border
    bgPath.lineWidth = size * 0.02
    NSColor(red: 0.06, green: 0.73, blue: 0.54, alpha: 0.5).setStroke()
    bgPath.stroke()

    // Shield Emblem
    let pad = size * 0.22
    let w = size - (pad * 2)
    let h = size - (pad * 2)

    let shield = NSBezierPath()
    let topMid = NSPoint(x: size / 2, y: size - pad)
    let topRight = NSPoint(x: size - pad, y: size - pad)
    let botMid = NSPoint(x: size / 2, y: pad)
    let topLeft = NSPoint(x: pad, y: size - pad)

    shield.move(to: topMid)
    shield.line(to: topRight)
    shield.curve(to: botMid, controlPoint1: NSPoint(x: size - pad, y: pad + h * 0.4), controlPoint2: NSPoint(x: size / 2 + w * 0.2, y: pad))
    shield.curve(to: topLeft, controlPoint1: NSPoint(x: size / 2 - w * 0.2, y: pad), controlPoint2: NSPoint(x: pad, y: pad + h * 0.4))
    shield.line(to: topMid)
    shield.close()

    // Emerald Green Gradient Shield
    let shieldGradient = NSGradient(colors: [
        NSColor(red: 0.06, green: 0.73, blue: 0.54, alpha: 1.0),
        NSColor(red: 0.02, green: 0.59, blue: 0.41, alpha: 1.0)
    ])!
    shieldGradient.draw(in: shield, angle: -45)

    // Checkmark Emblem inside Shield
    let check = NSBezierPath()
    check.move(to: NSPoint(x: size * 0.38, y: size * 0.5))
    check.line(to: NSPoint(x: size * 0.47, y: size * 0.41))
    check.line(to: NSPoint(x: size * 0.64, y: size * 0.6))
    check.lineWidth = size * 0.06
    check.lineCapStyle = .round
    check.lineJoinStyle = .round

    NSColor.white.setStroke()
    check.stroke()

    img.unlockFocus()
    return img
}

func savePNG(image: NSImage, path: String) {
    if let tiff = image.tiffRepresentation, let bitmap = NSBitmapImageRep(data: tiff), let png = bitmap.representation(using: .png, properties: [:]) {
        try? png.write(to: URL(fileURLWithPath: path))
    }
}

let dir = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "."

let menuIcon = createShieldTemplateIcon(size: 36) // 36x36 for Retina status bar
savePNG(image: menuIcon, path: "\(dir)/shield_template.png")

let appIcon = createAppIcon(size: 512) // 512x512 App Icon
savePNG(image: appIcon, path: "\(dir)/AppIcon.png")

print("Generated shield_template.png and AppIcon.png at \(dir)")
