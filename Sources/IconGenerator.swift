import Cocoa

/// 使用 CoreGraphics 绘制 1024x1024 的 macOS 应用高清图标
func generateIconPNG(outputPath: String) {
    let size = 1024
    let rect = NSRect(x: 0, y: 0, width: size, height: size)

    guard let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: size,
        pixelsHigh: size,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: 0,
        bitsPerPixel: 0
    ) else { return }

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)

    // 1. 绘制 macOS 规范圆角矩形背景（Claude 珊瑚橙暖色渐变）
    let inset: CGFloat = 80
    let bgRect = rect.insetBy(dx: inset, dy: inset)
    let path = NSBezierPath(roundedRect: bgRect, xRadius: 195, yRadius: 195)

    let gradient = NSGradient(colors: [
        NSColor(calibratedRed: 0.89, green: 0.48, blue: 0.34, alpha: 1.0), // #E37A57
        NSColor(calibratedRed: 0.77, green: 0.35, blue: 0.23, alpha: 1.0)  // #C4593B
    ])
    gradient?.draw(in: path, angle: -45)

    // 2. 绘制中心白色星芒与雷达圆环
    let center = NSPoint(x: 512, y: 512)
    NSColor(calibratedWhite: 1.0, alpha: 0.22).setStroke()
    let ring = NSBezierPath(ovalIn: NSRect(x: 242, y: 242, width: 540, height: 540))
    ring.lineWidth = 22
    ring.stroke()

    // 绘制 Claude 风格 8 芒星
    NSColor.white.setStroke()
    let rays = 6
    for i in 0..<rays {
        let angle = Double(i) * (Double.pi / Double(rays))
        let r: Double = 215
        let dx = CGFloat(cos(angle) * r)
        let dy = CGFloat(sin(angle) * r)
        let line = NSBezierPath()
        line.lineWidth = 46
        line.lineCapStyle = .round
        line.move(to: NSPoint(x: center.x - dx, y: center.y - dy))
        line.line(to: NSPoint(x: center.x + dx, y: center.y + dy))
        line.stroke()
    }

    // 右下角绿色安全盾点缀
    let badgeRect = NSRect(x: 620, y: 170, width: 210, height: 210)
    let badgePath = NSBezierPath(ovalIn: badgeRect)
    NSColor(calibratedRed: 0.13, green: 0.72, blue: 0.38, alpha: 1.0).setFill()
    badgePath.fill()
    NSColor.white.setStroke()
    badgePath.lineWidth = 16
    badgePath.stroke()

    // 绿色圆盾内的白色对勾
    let check = NSBezierPath()
    check.lineWidth = 24
    check.lineCapStyle = .round
    check.lineJoinStyle = .round
    check.move(to: NSPoint(x: 678, y: 272))
    check.line(to: NSPoint(x: 714, y: 236))
    check.line(to: NSPoint(x: 778, y: 312))
    check.stroke()

    NSGraphicsContext.restoreGraphicsState()

    if let pngData = rep.representation(using: .png, properties: [:]) {
        try? pngData.write(to: URL(fileURLWithPath: outputPath))
    }
}

if CommandLine.arguments.count > 1 {
    generateIconPNG(outputPath: CommandLine.arguments[1])
}
