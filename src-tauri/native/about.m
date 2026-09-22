#import <AppKit/AppKit.h>

// Standard macOS About panel, with centered and clickable repository credits.
void monitor_show_about(const char *version, const char *date, const unsigned char *icon, size_t icon_len, const unsigned char *github, size_t github_len) {
    NSCAssert(NSThread.isMainThread, @"About panel must open on the main thread");
    NSString *repository = @"https://github.com/intofo/Monitor";
    NSMutableParagraphStyle *paragraph = [NSMutableParagraphStyle new];
    paragraph.alignment = NSTextAlignmentCenter;
    NSImage *githubImage = [[NSImage alloc] initWithData:[NSData dataWithBytes:github length:github_len]];
    githubImage.size = NSMakeSize(16, 16);
    githubImage.template = YES;
    githubImage.accessibilityDescription = @"GitHub 开源仓库";
    NSTextAttachment *attachment = [NSTextAttachment new];
    attachment.image = githubImage;
    attachment.bounds = NSMakeRect(0, -2, 16, 16);
    NSMutableAttributedString *credits = [[NSMutableAttributedString alloc]
        initWithAttributedString:[NSAttributedString attributedStringWithAttachment:attachment]];
    [credits addAttributes:@{
        NSLinkAttributeName: [NSURL URLWithString:repository],
        NSParagraphStyleAttributeName: paragraph,
        NSToolTipAttributeName: repository
    } range:NSMakeRange(0, credits.length)];
    NSImage *image = [[NSImage alloc] initWithData:[NSData dataWithBytes:icon length:icon_len]];
    NSMutableDictionary *options = [@{
        NSAboutPanelOptionApplicationName: @"Monitor",
        NSAboutPanelOptionApplicationVersion: [NSString stringWithUTF8String:version],
        NSAboutPanelOptionVersion: @"",
        @"Copyright": [NSString stringWithFormat:@"发布时间：%s\n©VCENTER.dev", date],
        NSAboutPanelOptionCredits: credits
    } mutableCopy];
    if (image) options[NSAboutPanelOptionApplicationIcon] = image;
    [NSApp orderFrontStandardAboutPanelWithOptions:options];
}
