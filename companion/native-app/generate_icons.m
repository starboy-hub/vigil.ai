#import <Cocoa/Cocoa.h>

void savePNG(NSImage *image, NSString *path) {
    NSData *tiffData = [image TIFFRepresentation];
    NSBitmapImageRep *bitmapRep = [NSBitmapImageRep imageRepWithData:tiffData];
    NSData *pngData = [bitmapRep representationUsingType:NSBitmapImageRepFileTypePNG properties:@{}];
    [pngData writeToFile:path atomically:YES];
}

NSImage* createMenuTemplateIcon(CGFloat size) {
    NSImage *img = [[NSImage alloc] initWithSize:NSMakeSize(size, size)];
    [img lockFocus];

    CGContextRef ctx = [[NSGraphicsContext currentContext] CGContext];
    CGContextClearRect(ctx, CGRectMake(0, 0, size, size));

    CGFloat pad = size * 0.15;
    CGFloat w = size - (pad * 2);
    CGFloat h = size - (pad * 2);

    NSBezierPath *shield = [NSBezierPath bezierPath];
    NSPoint topMid = NSMakePoint(size / 2.0, size - pad);
    NSPoint topRight = NSMakePoint(size - pad, size - pad);
    NSPoint botMid = NSMakePoint(size / 2.0, pad);
    NSPoint topLeft = NSMakePoint(pad, size - pad);

    [shield moveToPoint:topMid];
    [shield lineToPoint:topRight];
    [shield curveToPoint:botMid controlPoint1:NSMakePoint(size - pad, pad + h * 0.4) controlPoint2:NSMakePoint(size / 2.0 + w * 0.2, pad)];
    [shield curveToPoint:topLeft controlPoint1:NSMakePoint(size / 2.0 - w * 0.2, pad) controlPoint2:NSMakePoint(pad, pad + h * 0.4)];
    [shield lineToPoint:topMid];
    [shield закрытьPath];

    [[NSColor blackColor] setFill];
    [shield fill];

    // Inner cutout checkmark (transparent overlay)
    NSBezierPath *check = [NSBezierPath bezierPath];
    [check moveToPoint:NSMakePoint(size * 0.35, size * 0.5)];
    [check lineToPoint:NSMakePoint(size * 0.46, size * 0.38)];
    [check lineToPoint:NSMakePoint(size * 0.68, size * 0.62)];
    [check setLineWidth:size * 0.1];
    [check setLineCapStyle:NSLineCapStyleRound];
    [check setLineJoinStyle:NSLineJoinStyleRound];

    CGContextSetBlendMode(ctx, kCGBlendModeClear);
    [check stroke];

    [img unlockFocus];
    [img setTemplate:YES];
    return img;
}

NSImage* createAppIcon(CGFloat size) {
    NSImage *img = [[NSImage alloc] initWithSize:NSMakeSize(size, size)];
    [img lockFocus];

    NSRect rect = NSMakeRect(0, 0, size, size);
    CGFloat cornerRadius = size * 0.223;
    NSBezierPath *bgPath = [NSBezierPath bezierPathWithRoundedRect:rect xRadius:cornerRadius yRadius:cornerRadius];

    NSGradient *bgGrad = [[NSGradient alloc] initWithStartingColor:[NSColor colorWithRed:0.08 green:0.11 blue:0.15 alpha:1.0]
                                                        endingColor:[NSColor colorWithRed:0.03 green:0.04 blue:0.06 alpha:1.0]];
    [bgGrad drawInBezierPath:bgPath angle:-45];

    [bgPath setLineWidth:size * 0.02];
    [[NSColor colorWithRed:0.06 green:0.73 blue:0.54 alpha:0.6] setStroke];
    [bgPath stroke];

    CGFloat pad = size * 0.22;
    CGFloat w = size - (pad * 2);
    CGFloat h = size - (pad * 2);

    NSBezierPath *shield = [NSBezierPath bezierPath];
    NSPoint topMid = NSMakePoint(size / 2.0, size - pad);
    NSPoint topRight = NSMakePoint(size - pad, size - pad);
    NSPoint botMid = NSMakePoint(size / 2.0, pad);
    NSPoint topLeft = NSMakePoint(pad, size - pad);

    [shield moveToPoint:topMid];
    [shield lineToPoint:topRight];
    [shield curveToPoint:botMid controlPoint1:NSMakePoint(size - pad, pad + h * 0.4) controlPoint2:NSMakePoint(size / 2.0 + w * 0.2, pad)];
    [shield curveToPoint:topLeft controlPoint1:NSMakePoint(size / 2.0 - w * 0.2, pad) controlPoint2:NSMakePoint(pad, pad + h * 0.4)];
    [shield lineToPoint:topMid];
    [shield закрытьPath];

    NSGradient *shieldGrad = [[NSGradient alloc] initWithStartingColor:[NSColor colorWithRed:0.06 green:0.73 blue:0.54 alpha:1.0]
                                                            endingColor:[NSColor colorWithRed:0.02 green:0.59 blue:0.41 alpha:1.0]];
    [shieldGrad drawInBezierPath:shield angle:-45];

    NSBezierPath *check = [NSBezierPath bezierPath];
    [check moveToPoint:NSMakePoint(size * 0.38, size * 0.5)];
    [check lineToPoint:NSMakePoint(size * 0.47, size * 0.41)];
    [check lineToPoint:NSMakePoint(size * 0.64, size * 0.6)];
    [check setLineWidth:size * 0.06];
    [check setLineCapStyle:NSLineCapStyleRound];
    [check setLineJoinStyle:NSLineJoinStyleRound];

    [[NSColor whiteColor] setStroke];
    [check stroke];

    [img unlockFocus];
    return img;
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSString *outDir = @"companion/native-app";
        if (argc > 1) outDir = [NSString stringWithUTF8String:argv[1]];

        NSImage *menuIcon = createMenuTemplateIcon(36);
        savePNG(menuIcon, [outDir stringByAppendingPathComponent:@"shield_template.png"]);

        NSImage *appIcon = createAppIcon(512);
        savePNG(appIcon, [outDir stringByAppendingPathComponent:@"AppIcon.png"]);

        NSLog(@"[VIGIL Native] Icons generated: shield_template.png and AppIcon.png");
    }
    return 0;
}
