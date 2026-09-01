#ifndef _AOS_APPKIT_JDK25_H_
#define _AOS_APPKIT_JDK25_H_

#import <AppKit/AppKit.h>
#import <AppKit/NSAccessibility.h>

typedef NSUInteger NSWindowTitleVisibility;
enum {
  NSWindowTitleVisible = 0,
  NSWindowTitleHidden = 1,
};

typedef NSUInteger NSPaperOrientation;
enum {
  NSPaperOrientationPortrait = 0,
  NSPaperOrientationLandscape = 1,
};

typedef NSUInteger NSProgressIndicatorStyle;
enum {
  NSProgressIndicatorStyleBar = 0,
  NSProgressIndicatorStyleSpinning = 1,
};
static const NSProgressIndicatorStyle NSProgressIndicatorBarStyle = NSProgressIndicatorStyleBar;

enum {
  NSWindowStyleMaskBorderless = 0,
  NSWindowStyleMaskUtilityWindow = 1U << 4,
  NSWindowStyleMaskDocModalWindow = 1U << 6,
  NSWindowStyleMaskNonactivatingPanel = 1U << 7,
  NSWindowStyleMaskTexturedBackground = 1U << 8,
  NSWindowStyleMaskUnifiedTitleAndToolbar = 1U << 12,
  NSWindowStyleMaskHUDWindow = 1U << 13,
  NSWindowStyleMaskFullSizeContentView = 1U << 15,
  NSEventTypeLeftMouseDown = 1,
  NSEventTypeLeftMouseUp = 2,
  NSEventTypeRightMouseDown = 3,
  NSEventTypeRightMouseUp = 4,
  NSEventTypeMouseMoved = 5,
  NSEventTypeMouseEntered = 8,
  NSEventTypeMouseExited = 9,
  NSEventTypeOtherMouseDown = 25,
  NSEventTypeOtherMouseUp = 26,
};

typedef NSString *NSPrintInfoSettingKey;
typedef NSString *NSPrintInfoAttributeKey;
typedef NSString *NSPrintJobDispositionValue;
typedef NSString *NSAppearanceName;
typedef NSString *NSAttributedStringDocumentAttributeKey;
typedef NSString *NSAttributedStringDocumentType;
extern NSAppearanceName const NSAppearanceNameAqua;
extern NSAttributedStringDocumentAttributeKey NSDocumentTypeDocumentAttribute;
extern NSPrintInfoAttributeKey const NSPrintJobSavingURL;
extern NSPrintJobDispositionValue const NSPrintSaveJob;
extern NSPrintJobDispositionValue const NSPrintSpoolJob;
extern NSAttributedStringDocumentType NSRTFTextDocumentType;
extern NSNotificationName NSTextInputContextKeyboardSelectionDidChangeNotification;

@class NSRunningApplication;
@class NSWorkspaceOpenConfiguration;

@interface NSAppearance : NSObject
+ (NSAppearance *)appearanceNamed:(NSAppearanceName)name;
@end

@interface NSProgressIndicator : NSView <NSAccessibilityProgressIndicator>
- (void)setDoubleValue:(double)value;
- (void)setIndeterminate:(BOOL)flag;
- (void)setMaxValue:(double)value;
- (void)setMinValue:(double)value;
- (void)setStyle:(NSProgressIndicatorStyle)style;
@end

@interface NSWorkspaceOpenConfiguration : NSObject <NSCopying>
+ (instancetype)configuration;
@property BOOL activates;
@property BOOL forPrinting;
@property BOOL promptsUserIfNeeded;
@end

@interface NSWorkspace (AOSJDK25Surface)
- (NSURL *)URLForApplicationToOpenURL:(NSURL *)url;
- (void)openURLs:(NSArray<NSURL *> *)urls
    withApplicationAtURL:(NSURL *)applicationURL
           configuration:(NSWorkspaceOpenConfiguration *)configuration
       completionHandler:(void (^)(NSRunningApplication * _Nullable,
                                   NSError * _Nullable))completionHandler;
@end

@interface NSColor (AOSJDK25Surface)
+ (NSColor *)controlAccentColor;
+ (NSColor *)selectedContentBackgroundColor;
@end

@interface NSRunningApplication (AOSJDK25Surface)
- (NSInteger)executableArchitecture;
@end

@interface NSTextInputContext : NSObject
+ (NSTextInputContext *)currentInputContext;
- (NSString *)selectedKeyboardInputSource;
@end

@interface NSWindow (AOSJDK25Surface)
+ (void)setAllowsAutomaticWindowTabbing:(BOOL)allow;
- (NSPoint)cascadeTopLeftFromPoint:(NSPoint)topLeftPoint;
- (BOOL)isMainWindow;
- (void)setTitleVisibility:(NSWindowTitleVisibility)titleVisibility;
@end

@interface NSScreen (AOSJDK25Surface)
- (NSRect)visibleFrame;
@end

@interface NSImage (AOSJDK25Surface)
- (void)setTemplate:(BOOL)isTemplate;
@end

@protocol NSPasteboardWriting <NSObject>
@end

@interface NSPasteboard (AOSJDK25Surface)
- (BOOL)writeObjects:(NSArray<id<NSPasteboardWriting>> *)objects;
@end

@interface NSPrintInfo (AOSJDK25Surface)
- (void *)PMPrintSettings;
- (NSString *)jobDisposition;
- (NSMutableDictionary<NSPrintInfoSettingKey, id> *)printSettings;
- (void)updateFromPMPrintSettings;
@end

@interface NSOpenGLContext (AOSJDK25Surface)
- (CGLContextObj)CGLContextObj;
@end

@interface NSOpenGLPixelFormat (AOSJDK25Surface)
- (CGLPixelFormatObj)CGLPixelFormatObj;
@end

@interface NSUserNotification (AOSJDK25Surface)
- (void)setSoundName:(NSString *)soundName;
@end

#endif
