#ifndef _AOS_APPKIT_JDK_H_
#define _AOS_APPKIT_JDK_H_
#import <AppKit/AppKit.h>

extern NSRunLoopMode const NSModalPanelRunLoopMode;
extern NSRunLoopMode const NSEventTrackingRunLoopMode;
extern NSNotificationName const NSApplicationWillFinishLaunchingNotification;
extern NSNotificationName const NSWorkspaceWillPowerOffNotification;
extern NSNotificationName const NSWorkspaceSessionDidBecomeActiveNotification;
extern NSNotificationName const NSWorkspaceSessionDidResignActiveNotification;
extern NSNotificationName const NSWorkspaceScreensDidSleepNotification;
extern NSNotificationName const NSWorkspaceScreensDidWakeNotification;
extern NSNotificationName const NSWorkspaceWillSleepNotification;
extern NSNotificationName const NSWorkspaceDidWakeNotification;
extern NSNotificationName const NSApplicationDidBecomeActiveNotification;
extern NSNotificationName const NSApplicationDidResignActiveNotification;
extern NSNotificationName const NSApplicationDidHideNotification;
extern NSNotificationName const NSApplicationDidUnhideNotification;
extern NSNotificationName const NSApplicationDidFinishLaunchingNotification;
extern NSNotificationName const NSSystemColorsDidChangeNotification;
extern NSString *const NSWorkspaceRecycleOperation;

extern BOOL NSApplicationLoad(void);
extern NSString *NSAccessibilityRoleDescription(NSString *role, NSString *subrole);
extern id NSAccessibilityUnignoredAncestor(id element);
extern NSArray *NSAccessibilityUnignoredChildrenForOnlyChild(id originalChild);
extern void NSAccessibilityPostNotification(id element, NSString *notification);

extern NSString *const NSAccessibilityChildrenAttribute;
extern NSString *const NSAccessibilityContentsAttribute;
extern NSString *const NSAccessibilityEnabledAttribute;
extern NSString *const NSAccessibilityFocusedAttribute;
extern NSString *const NSAccessibilityHelpAttribute;
extern NSString *const NSAccessibilityHorizontalScrollBarAttribute;
extern NSString *const NSAccessibilityIndexAttribute;
extern NSString *const NSAccessibilityMaxValueAttribute;
extern NSString *const NSAccessibilityMinValueAttribute;
extern NSString *const NSAccessibilityOrientationAttribute;
extern NSString *const NSAccessibilityParentAttribute;
extern NSString *const NSAccessibilityPositionAttribute;
extern NSString *const NSAccessibilityRoleAttribute;
extern NSString *const NSAccessibilityRoleDescriptionAttribute;
extern NSString *const NSAccessibilitySelectedAttribute;
extern NSString *const NSAccessibilitySelectedChildrenAttribute;
extern NSString *const NSAccessibilitySizeAttribute;
extern NSString *const NSAccessibilitySubroleAttribute;
extern NSString *const NSAccessibilityTabsAttribute;
extern NSString *const NSAccessibilityTitleAttribute;
extern NSString *const NSAccessibilityTopLevelUIElementAttribute;
extern NSString *const NSAccessibilityValueAttribute;
extern NSString *const NSAccessibilityVerticalScrollBarAttribute;
extern NSString *const NSAccessibilityVisibleChildrenAttribute;
extern NSString *const NSAccessibilityWindowAttribute;
extern NSString *const NSAccessibilityHorizontalOrientationValue;
extern NSString *const NSAccessibilityVerticalOrientationValue;
extern NSString *const NSAccessibilityPickAction;
extern NSString *const NSAccessibilityPressAction;
extern NSString *const NSAccessibilityFocusedUIElementChangedNotification;
extern NSString *const NSAccessibilitySelectedChildrenChangedNotification;
extern NSString *const NSAccessibilitySelectedTextChangedNotification;
extern NSString *const NSAccessibilityValueChangedNotification;
extern NSString *const NSAccessibilitySecureTextFieldSubrole;

extern NSString *const NSColorPboardType;
extern NSString *const NSFileContentsPboardType;
extern NSString *const NSFilesPromisePboardType;
extern NSString *const NSFontPboardType;
extern NSString *const NSPostScriptPboardType;
extern NSString *const NSRTFDPboardType;
extern NSString *const NSRulerPboardType;
extern NSString *const NSTabularTextPboardType;
extern NSString *const NSVCardPboardType;
extern NSString *const NSFontTraitsAttribute;
extern NSString *const NSFontWeightTrait;
extern NSString *const NSFontWidthTrait;
extern NSString *const NSKernAttributeName;
extern NSString *const NSLigatureAttributeName;
extern NSString *const NSUnderlineColorAttributeName;
extern NSString *const NSAccessibilityBrowserRole;
extern NSString *const NSAccessibilityButtonRole;
extern NSString *const NSAccessibilityCheckBoxRole;
extern NSString *const NSAccessibilityColumnRole;
extern NSString *const NSAccessibilityComboBoxRole;
extern NSString *const NSAccessibilityErrorCodeExceptionInfo;
extern NSString *const NSAccessibilityException;
extern NSString *const NSAccessibilityGroupRole;
extern NSString *const NSAccessibilityImageRole;
extern NSString *const NSAccessibilityIncrementorRole;
extern NSString *const NSAccessibilityListRole;
extern NSString *const NSAccessibilityMenuBarRole;
extern NSString *const NSAccessibilityMenuItemRole;
extern NSString *const NSAccessibilityMenuRole;
extern NSString *const NSAccessibilityPopUpButtonRole;
extern NSString *const NSAccessibilityProgressIndicatorRole;
extern NSString *const NSAccessibilityRadioButtonRole;
extern NSString *const NSAccessibilityRowRole;
extern NSString *const NSAccessibilityScrollAreaRole;
extern NSString *const NSAccessibilityScrollBarRole;
extern NSString *const NSAccessibilitySliderRole;
extern NSString *const NSAccessibilitySplitGroupRole;
extern NSString *const NSAccessibilityStaticTextRole;
extern NSString *const NSAccessibilityTabGroupRole;
extern NSString *const NSAccessibilityTableRole;
extern NSString *const NSAccessibilityTextAreaRole;
extern NSString *const NSAccessibilityTextFieldRole;
extern NSString *const NSAccessibilityToolbarRole;
extern NSString *const NSAccessibilityUnknownRole;
extern NSString *const NSAccessibilityValueIndicatorRole;
extern NSString *const NSCalibratedRGBColorSpace;
extern NSString *const NSDeviceRGBColorSpace;
extern NSString *const NSDragPboard;
extern NSString *const NSFilenamesPboardType;
extern NSString *const NSHTMLPboardType;
extern NSString *const NSPDFPboardType;
extern NSString *const NSPICTPboardType;
extern NSString *const NSPasteboardTypePNG;
extern NSString *const NSRTFPboardType;
extern NSString *const NSStringPboardType;
extern NSString *const NSTIFFPboardType;
extern NSString *const NSURLPboardType;
extern NSString *const NSPrintAllPages;
extern NSString *const NSPrintCancelJob;
extern NSString *const NSPrintCopies;
extern NSString *const NSPrintFirstPage;
extern NSString *const NSPrintLastPage;
extern NSString *const NSPrintMustCollate;
extern NSString *const NSPrintSelectionOnly;

extern BOOL NSEqualPoints(NSPoint aPoint, NSPoint bPoint);
extern BOOL NSEqualSizes(NSSize aSize, NSSize bSize);
extern BOOL NSPointInRect(NSPoint aPoint, NSRect aRect);

extern const NSPoint NSZeroPoint;
extern const NSSize NSZeroSize;
extern const NSRect NSZeroRect;
extern NSRect NSIntegralRect(NSRect aRect);

NS_INLINE CGFloat NSMinX(NSRect aRect) { return aRect.origin.x; }
NS_INLINE CGFloat NSMinY(NSRect aRect) { return aRect.origin.y; }
NS_INLINE CGFloat NSMaxX(NSRect aRect) {
  return aRect.origin.x + aRect.size.width;
}
NS_INLINE CGFloat NSMaxY(NSRect aRect) {
  return aRect.origin.y + aRect.size.height;
}

typedef NSInteger NSWindowOrderingMode;
enum {
  NSWindowBelow = -1,
  NSWindowOut = 0,
  NSWindowAbove = 1,
};

enum {
  NSEventPhaseNone = 0,
  NSEventPhaseBegan = 1UL << 0,
  NSEventPhaseStationary = 1UL << 1,
  NSEventPhaseChanged = 1UL << 2,
  NSEventPhaseEnded = 1UL << 3,
  NSEventPhaseCancelled = 1UL << 4,
  NSEventPhaseMayBegin = 1UL << 5,
};
typedef NSUInteger NSEventPhase;

typedef NSUInteger NSPrintingOrientation;
enum {
  NSPortraitOrientation = 0,
  NSLandscapeOrientation = 1,
};

typedef NSUInteger NSDragOperation;
enum {
  NSDragOperationNone = 0,
  NSDragOperationCopy = 1,
  NSDragOperationLink = 2,
  NSDragOperationGeneric = 4,
  NSDragOperationPrivate = 8,
  NSDragOperationAll_Obsolete = 15,
  NSDragOperationMove = 16,
  NSDragOperationDelete = 32,
  NSDragOperationEvery = NSUIntegerMax,
};

typedef NSUInteger NSImageScaling;
enum {
  NSImageScaleProportionallyDown = 0,
  NSImageScaleAxesIndependently = 1,
  NSImageScaleNone = 2,
  NSImageScaleProportionallyUpOrDown = 3,
};

typedef NSUInteger NSBitmapFormat;
enum {
  NSAlphaFirstBitmapFormat = 1UL << 0,
  NSAlphaNonpremultipliedBitmapFormat = 1UL << 1,
};

typedef NSUInteger NSCompositingOperation;
enum {
  NSCompositeClear = 0,
  NSCompositeCopy = 1,
  NSCompositeSourceOver = 2,
  NSCompositeSourceIn = 3,
  NSCompositeSourceOut = 4,
  NSCompositeSourceAtop = 5,
  NSCompositeDestinationOver = 6,
  NSCompositeDestinationIn = 7,
  NSCompositeDestinationOut = 8,
  NSCompositeDestinationAtop = 9,
  NSCompositeXOR = 10,
};

enum {
  NSOffState = 0,
  NSOnState = 1,
  NSCancelButton = 0,
  NSOKButton = 1,
};

typedef NSUInteger NSApplicationDelegateReply;
enum {
  NSApplicationDelegateReplySuccess = 0,
  NSApplicationDelegateReplyCancel = 1,
  NSApplicationDelegateReplyFailure = 2,
};

#define NSVariableStatusItemLength (-1)

enum {
  NSLeftMouseDown = 1,
  NSLeftMouseUp = 2,
  NSRightMouseDown = 3,
  NSRightMouseUp = 4,
  NSMouseMoved = 5,
  NSLeftMouseDragged = 6,
  NSRightMouseDragged = 7,
  NSMouseEntered = 8,
  NSMouseExited = 9,
  NSKeyDown = 10,
  NSKeyUp = 11,
  NSFlagsChanged = 12,
  NSAppKitDefined = 13,
  NSSystemDefined = 14,
  NSApplicationDefined = 15,
  NSPeriodic = 16,
  NSCursorUpdate = 17,
  NSScrollWheel = 22,
  NSTabletPoint = 23,
  NSTabletProximity = 24,
  NSOtherMouseDown = 25,
  NSOtherMouseUp = 26,
  NSOtherMouseDragged = 27,
};

enum {
  NSAlphaShiftKeyMask = 1UL << 16,
  NSShiftKeyMask = 1UL << 17,
  NSControlKeyMask = 1UL << 18,
  NSAlternateKeyMask = 1UL << 19,
  NSCommandKeyMask = 1UL << 20,
  NSNumericPadKeyMask = 1UL << 21,
  NSHelpKeyMask = 1UL << 22,
  NSFunctionKeyMask = 1UL << 23,
};

enum {
  NSEnterCharacter = 0x0003,
  NSBackspaceCharacter = 0x0008,
  NSNewlineCharacter = 0x000a,
  NSCarriageReturnCharacter = 0x000d,
  NSDeleteCharacter = 0x007f,
  NSF1FunctionKey = 0xf704,
};

enum { NSFullSizeContentViewWindowMask = 1UL << 15 };

enum {
  NSBorderlessWindowMask = 0,
  NSTitledWindowMask = 1UL << 0,
  NSClosableWindowMask = 1UL << 1,
  NSMiniaturizableWindowMask = 1UL << 2,
  NSResizableWindowMask = 1UL << 3,
  NSUtilityWindowMask = 1UL << 4,
  NSDocModalWindowMask = 1UL << 6,
  NSNonactivatingPanelMask = 1UL << 7,
  NSTexturedBackgroundWindowMask = 1UL << 8,
  NSUnifiedTitleAndToolbarWindowMask = 1UL << 12,
  NSHUDWindowMask = 1UL << 13,
};

enum {
  NSWindowZoomButton = 2,
  NSWindowCollectionBehaviorDefault = 0,
  NSTrackingActiveAlways = 0x80,
  NSTrackingEnabledDuringMouseDrag = 0x400,
};

typedef NSUInteger NSWindowButton;
enum {
  NSWindowCloseButton = 0,
  NSWindowMiniaturizeButton = 1,
};

enum {
  NSViewWidthSizable = 2,
  NSViewMaxXMargin = 4,
  NSViewMinYMargin = 8,
  NSViewHeightSizable = 16,
};

#define NSNormalWindowLevel CGWindowLevelForKey(kCGNormalWindowLevelKey)
#define NSFloatingWindowLevel CGWindowLevelForKey(kCGFloatingWindowLevelKey)
#define NSPopUpMenuWindowLevel CGWindowLevelForKey(kCGPopUpMenuWindowLevelKey)

typedef NSUInteger NSRequestUserAttentionType;
enum {
  NSCriticalRequest = 0,
  NSInformationalRequest = 10,
};

typedef NSUInteger NSApplicationActivationOptions;
enum {
  NSApplicationActivateAllWindows = 1UL << 0,
  NSApplicationActivateIgnoringOtherApps = 1UL << 1,
};

typedef NS_OPTIONS(unsigned long long, NSEventMask) {
  NSLeftMouseDownMask = 1UL << 1,
  NSLeftMouseUpMask = 1UL << 2,
  NSRightMouseDownMask = 1UL << 3,
  NSRightMouseUpMask = 1UL << 4,
  NSMouseMovedMask = 1UL << 5,
  NSLeftMouseDraggedMask = 1UL << 6,
  NSRightMouseDraggedMask = 1UL << 7,
  NSMouseEnteredMask = 1UL << 8,
  NSMouseExitedMask = 1UL << 9,
  NSKeyDownMask = 1UL << 10,
  NSKeyUpMask = 1UL << 11,
  NSFlagsChangedMask = 1UL << 12,
  NSAppKitDefinedMask = 1UL << 13,
  NSSystemDefinedMask = 1UL << 14,
  NSApplicationDefinedMask = 1UL << 15,
  NSPeriodicMask = 1UL << 16,
  NSCursorUpdateMask = 1UL << 17,
  NSScrollWheelMask = 1UL << 22,
  NSTabletPointMask = 1UL << 23,
  NSTabletProximityMask = 1UL << 24,
  NSOtherMouseDownMask = 1UL << 25,
  NSOtherMouseUpMask = 1UL << 26,
  NSOtherMouseDraggedMask = 1UL << 27,
  NSAnyEventMask = ~0ULL,
};

enum {
  NSTabCharacter = 0x0009,
  NSBackTabCharacter = 0x0019,
  NSUpArrowFunctionKey = 0xf700,
  NSDownArrowFunctionKey = 0xf701,
  NSLeftArrowFunctionKey = 0xf702,
  NSRightArrowFunctionKey = 0xf703,
  NSF13FunctionKey = 0xf710,
  NSDeleteFunctionKey = 0xf728,
  NSHomeFunctionKey = 0xf729,
  NSEndFunctionKey = 0xf72b,
  NSPageUpFunctionKey = 0xf72c,
  NSPageDownFunctionKey = 0xf72d,
  NSClearDisplayFunctionKey = 0xf73a,
  NSHelpFunctionKey = 0xf746,
  NSModeSwitchFunctionKey = 0xf747,
};

@class NSPrinter;
@class NSAttributedString;
@class NSDockTile;
@class NSFontDescriptor;
@class NSStatusItem;
@class NSButton;
typedef struct OpaqueIconRef *IconRef;

@protocol NSMenuDelegate <NSObject>
@optional
- (void)menuWillOpen:(NSMenu *)menu;
- (void)menuDidClose:(NSMenu *)menu;
@end

@protocol NSDraggingInfo <NSObject>
@required
- (NSWindow *)draggingDestinationWindow;
- (NSDragOperation)draggingSourceOperationMask;
- (NSPoint)draggingLocation;
- (NSPoint)draggedImageLocation;
- (NSImage *)draggedImage;
- (NSPasteboard *)draggingPasteboard;
- (id)draggingSource;
- (NSInteger)draggingSequenceNumber;
- (void)slideDraggedImageTo:(NSPoint)screenPoint;
- (NSArray *)namesOfPromisedFilesDroppedAtDestination:(NSURL *)dropDestination;
@end

@protocol NSDraggingDestination <NSObject>
@optional
- (NSDragOperation)draggingEntered:(id<NSDraggingInfo>)sender;
- (NSDragOperation)draggingUpdated:(id<NSDraggingInfo>)sender;
- (void)draggingExited:(id<NSDraggingInfo>)sender;
- (BOOL)prepareForDragOperation:(id<NSDraggingInfo>)sender;
- (BOOL)performDragOperation:(id<NSDraggingInfo>)sender;
- (void)concludeDragOperation:(id<NSDraggingInfo>)sender;
- (void)draggingEnded:(id<NSDraggingInfo>)sender;
@end

@protocol NSTextInputClient <NSObject>
@required
- (void)insertText:(id)string replacementRange:(NSRange)replacementRange;
- (void)setMarkedText:(id)string
        selectedRange:(NSRange)selectedRange
      replacementRange:(NSRange)replacementRange;
- (void)unmarkText;
- (NSRange)selectedRange;
- (NSRange)markedRange;
- (BOOL)hasMarkedText;
- (NSAttributedString *)attributedSubstringForProposedRange:(NSRange)range
                                                actualRange:(NSRangePointer)actualRange;
- (NSArray *)validAttributesForMarkedText;
- (NSRect)firstRectForCharacterRange:(NSRange)range
                         actualRange:(NSRangePointer)actualRange;
- (NSUInteger)characterIndexForPoint:(NSPoint)point;
@optional
- (NSInteger)conversationIdentifier;
@end

@interface NSObject (AOSJDKAccessibilitySurface)
- (NSArray *)accessibilityAttributeNames;
- (BOOL)accessibilityIsAttributeSettable:(NSString *)attribute;
- (id)accessibilityFocusedUIElement;
- (NSUInteger)accessibilityIndexOfChild:(id)child;
- (NSArray *)accessibilityArrayAttributeValues:(NSString *)attribute
                                         index:(NSUInteger)index
                                      maxCount:(NSUInteger)maxCount;
- (id)accessibilityAttributeValue:(NSString *)attribute;
@end

@interface NSObject (AOSJDKDraggingSourceSurface)
- (NSDragOperation)draggingSourceOperationMaskForLocal:(BOOL)isLocal;
- (NSArray *)namesOfPromisedFilesDroppedAtDestination:(NSURL *)dropDestination;
- (void)draggedImage:(NSImage *)image beganAt:(NSPoint)screenPoint;
- (void)draggedImage:(NSImage *)image
             endedAt:(NSPoint)screenPoint
           operation:(NSDragOperation)operation;
- (void)draggedImage:(NSImage *)image movedTo:(NSPoint)screenPoint;
- (BOOL)ignoreModifierKeysWhileDragging;
@end

@interface NSWindow (AOSJDKSurface)
+ (NSRect)contentRectForFrameRect:(NSRect)frameRect styleMask:(NSUInteger)style;
- (instancetype)initWithContentRect:(NSRect)contentRect
                          styleMask:(NSUInteger)style
                            backing:(NSBackingStoreType)bufferingType
                              defer:(BOOL)flag
                             screen:(NSScreen *)screen;
- (void)addChildWindow:(NSWindow *)childWin ordered:(NSWindowOrderingMode)place;
- (BOOL)canBecomeMainWindow;
- (void)close;
- (NSRect)frame;
- (BOOL)isKeyWindow;
- (BOOL)isZoomed;
- (void)setAlphaValue:(CGFloat)windowAlpha;
- (__kindof NSView *)contentView;
- (void)setContentView:(NSView *)view;
- (void)setInitialFirstResponder:(NSView *)view;
- (void)setLevel:(NSInteger)newLevel;
- (void)setPreservesContentDuringLiveResize:(BOOL)flag;
- (void)setReleasedWhenClosed:(BOOL)flag;
- (void)setStyleMask:(NSUInteger)styleMask;
- (void)setTitlebarAppearsTransparent:(BOOL)flag;
- (void)setShowsResizeIndicator:(BOOL)flag;
- (void)setHasShadow:(BOOL)flag;
- (void)setHidesOnDeactivate:(BOOL)flag;
- (void)setMovableByWindowBackground:(BOOL)flag;
- (void)setDocumentEdited:(BOOL)flag;
- (NSPoint)convertScreenToBase:(NSPoint)aPoint;
- (void)setFrame:(NSRect)frameRect display:(BOOL)flag;
- (void)orderOut:(id)sender;
- (void)orderFrontRegardless;
- (NSResponder *)firstResponder;
- (NSRect)convertRectToScreen:(NSRect)rect;
- (NSPoint)mouseLocationOutsideOfEventStream;
- (NSButton *)standardWindowButton:(NSWindowButton)button;
- (BOOL)inLiveResize;
- (BOOL)isVisible;
- (NSRect)contentRectForFrameRect:(NSRect)frameRect;
- (void)orderBack:(id)sender;
- (void)invalidateShadow;
- (void)setMiniwindowImage:(NSImage *)image;
- (void)setRepresentedURL:(NSURL *)url;
- (NSInteger)level;
- (NSInteger)windowNumber;
- (void)orderWindow:(NSWindowOrderingMode)place relativeTo:(NSInteger)otherWindow;
- (BOOL)makeFirstResponder:(NSResponder *)responder;
- (NSPoint)convertBaseToScreen:(NSPoint)aPoint;
- (void)setMinSize:(NSSize)size;
- (void)setMaxSize:(NSSize)size;
- (void)setBackgroundColor:(NSColor *)color;
- (void)setOpaque:(BOOL)flag;
- (void)sendEvent:(NSEvent *)event;
- (void)setDelegate:(id<NSWindowDelegate>)delegate;
@end

@interface NSScreen (AOSJDKSurface)
+ (NSArray *)screens;
+ (NSScreen *)mainScreen;
- (CGFloat)backingScaleFactor;
- (NSRect)frame;
@end

@interface NSView (AOSJDKSurface)
- (NSRect)bounds;
- (NSPoint)convertPoint:(NSPoint)aPoint fromView:(NSView *)aView;
- (NSRect)frame;
- (void)setToolTip:(NSString *)string;
- (NSWindow *)window;
- (NSPoint)convertPoint:(NSPoint)aPoint toView:(NSView *)aView;
- (BOOL)mouse:(NSPoint)aPoint inRect:(NSRect)aRect;
- (void)setNeedsDisplay:(BOOL)flag;
- (void)setAutoresizesSubviews:(BOOL)flag;
- (void)setAutoresizingMask:(NSUInteger)mask;
- (void)setLayer:(CALayer *)layer;
- (void)removeTrackingArea:(NSTrackingArea *)trackingArea;
- (void)registerForDraggedTypes:(NSArray *)newTypes;
- (void)resizeWithOldSuperviewSize:(NSSize)oldSize;
- (void)dragImage:(NSImage *)image
               at:(NSPoint)location
           offset:(NSSize)offset
            event:(NSEvent *)event
       pasteboard:(NSPasteboard *)pasteboard
           source:(id)sourceObject
        slideBack:(BOOL)slideBack;
- (BOOL)dragFile:(NSString *)filename
        fromRect:(NSRect)rect
       slideBack:(BOOL)slideBack
           event:(NSEvent *)event;
- (void)lockFocus;
- (void)unlockFocus;
- (void)drawRect:(NSRect)dirtyRect;
- (BOOL)dragPromisedFilesOfTypes:(NSArray *)typeArray
                        fromRect:(NSRect)rect
                          source:(id)sourceObject
                       slideBack:(BOOL)slideBack
                           event:(NSEvent *)event;
- (NSRect)visibleRect;
- (void)updateTrackingAreas;
- (void)resetCursorRects;
- (NSView *)superview;
- (NSRect)convertRect:(NSRect)aRect toView:(NSView *)aView;
- (NSView *)hitTest:(NSPoint)aPoint;
@end

@interface NSResponder (AOSJDKSurface)
- (NSResponder *)nextResponder;
- (void)interpretKeyEvents:(NSArray *)eventArray;
@end

@interface NSApplication (AOSJDKSurface)
- (NSEvent *)currentEvent;
- (BOOL)isRunning;
- (NSWindow *)keyWindow;
- (void)setDelegate:(id<NSApplicationDelegate>)delegate;
- (NSMenu *)mainMenu;
- (NSArray *)windows;
- (void)stop:(id)sender;
- (void)finishLaunching;
- (void)activateIgnoringOtherApps:(BOOL)flag;
- (BOOL)isActive;
- (void)postEvent:(NSEvent *)event atStart:(BOOL)flag;
- (NSEvent *)nextEventMatchingMask:(NSEventMask)mask
                         untilDate:(NSDate *)expiration
                            inMode:(NSString *)mode
                           dequeue:(BOOL)deqFlag;
- (void)setApplicationIconImage:(NSImage *)image;
- (NSImage *)applicationIconImage;
- (NSDockTile *)dockTile;
- (void)orderFrontStandardAboutPanel:(id)sender;
- (void)replyToApplicationShouldTerminate:(BOOL)shouldTerminate;
- (NSInteger)requestUserAttention:(NSRequestUserAttentionType)requestType;
- (void)replyToOpenOrPrint:(NSApplicationDelegateReply)reply;
@end

@interface NSRunningApplication : NSObject
+ (NSRunningApplication *)currentApplication;
@property(readonly, getter=isActive) BOOL active;
- (BOOL)isActive;
- (BOOL)activateWithOptions:(NSApplicationActivationOptions)options;
@end

@interface NSFont (AOSJDKSurface)
+ (NSFont *)boldSystemFontOfSize:(CGFloat)fontSize;
+ (NSFont *)systemFontOfSize:(CGFloat)fontSize;
+ (NSFont *)fontWithName:(NSString *)fontName matrix:(const CGFloat *)fontMatrix;
- (NSString *)fontName;
- (NSUInteger)numberOfGlyphs;
- (NSFontDescriptor *)fontDescriptor;
- (NSCharacterSet *)coveredCharacterSet;
- (NSSize)maximumAdvancement;
@end

@interface NSFontDescriptor : NSObject
- (NSString *)postscriptName;
- (id)objectForKey:(NSString *)attribute;
@end

@interface NSFontManager (AOSJDKSurface)
- (NSArray *)availableFonts;
- (NSArray *)availableFontFamilies;
- (NSArray *)availableMembersOfFontFamily:(NSString *)family;
@end

@interface NSColor (AOSJDKSurface)
+ (NSColor *)alternateSelectedControlColor;
+ (NSColor *)alternateSelectedControlTextColor;
+ (NSColor *)controlBackgroundColor;
+ (NSColor *)controlColor;
+ (NSColor *)controlTextColor;
+ (NSColor *)disabledControlTextColor;
+ (NSColor *)grayColor;
+ (NSColor *)greenColor;
+ (NSColor *)selectedTextBackgroundColor;
+ (NSColor *)selectedTextColor;
+ (NSColor *)textBackgroundColor;
+ (NSColor *)textColor;
+ (NSColor *)windowFrameColor;
+ (NSColor *)windowFrameTextColor;
+ (NSColor *)clearColor;
+ (NSColor *)controlShadowColor;
+ (NSColor *)controlDarkShadowColor;
+ (NSColor *)secondarySelectedControlColor;
+ (NSColor *)keyboardFocusIndicatorColor;
+ (NSColor *)scrollBarColor;
+ (NSColor *)colorWithCalibratedRed:(CGFloat)red
                              green:(CGFloat)green
                               blue:(CGFloat)blue
                              alpha:(CGFloat)alpha;
- (void)getRed:(CGFloat *)red
         green:(CGFloat *)green
          blue:(CGFloat *)blue
         alpha:(CGFloat *)alpha;
- (void)set;
- (NSColor *)colorUsingColorSpaceName:(NSString *)colorSpace;
@end

@interface NSCursor (AOSJDKSurface)
- (instancetype)initWithImage:(NSImage *)newImage hotSpot:(NSPoint)aPoint;
- (void)set;
@end

@interface NSGraphicsContext (AOSJDKSurface)
+ (NSGraphicsContext *)graphicsContextWithWindow:(NSWindow *)window;
+ (NSGraphicsContext *)graphicsContextWithGraphicsPort:(void *)graphicsPort
                                               flipped:(BOOL)initialFlippedState;
+ (void)setCurrentContext:(NSGraphicsContext *)context;
- (void *)graphicsPort;
- (void)setCompositingOperation:(NSCompositingOperation)operation;
@end

@interface NSEvent (AOSJDKSurface)
+ (NSPoint)mouseLocation;
- (BOOL)hasPreciseScrollingDeltas;
- (NSEventPhase)momentumPhase;
- (NSEventPhase)phase;
- (NSEventType)type;
- (NSUInteger)modifierFlags;
- (NSTimeInterval)timestamp;
- (NSWindow *)window;
- (NSInteger)windowNumber;
- (NSPoint)locationInWindow;
- (NSInteger)clickCount;
- (NSInteger)buttonNumber;
- (CGFloat)deltaX;
- (CGFloat)deltaY;
- (CGFloat)scrollingDeltaX;
- (CGFloat)scrollingDeltaY;
- (CGFloat)magnification;
- (float)rotation;
+ (NSUInteger)modifierFlags;
+ (NSTimeInterval)doubleClickInterval;
+ (NSEvent *)mouseEventWithType:(NSEventType)type
                       location:(NSPoint)location
                  modifierFlags:(NSUInteger)flags
                      timestamp:(NSTimeInterval)time
                   windowNumber:(NSInteger)windowNumber
                        context:(NSGraphicsContext *)context
                    eventNumber:(NSInteger)eventNumber
                     clickCount:(NSInteger)clickCount
                       pressure:(float)pressure;
- (short)subtype;
- (NSInteger)data1;
- (NSInteger)data2;
+ (NSEvent *)enterExitEventWithType:(NSEventType)type
                           location:(NSPoint)location
                      modifierFlags:(NSUInteger)flags
                          timestamp:(NSTimeInterval)time
                       windowNumber:(NSInteger)windowNumber
                            context:(NSGraphicsContext *)context
                        eventNumber:(NSInteger)eventNumber
                     trackingNumber:(NSInteger)trackingNumber
                           userData:(void *)userData;
+ (NSEvent *)otherEventWithType:(NSEventType)type
                       location:(NSPoint)location
                  modifierFlags:(NSUInteger)flags
                      timestamp:(NSTimeInterval)time
                   windowNumber:(NSInteger)windowNumber
                        context:(NSGraphicsContext *)context
                        subtype:(short)subtype
                          data1:(NSInteger)data1
                          data2:(NSInteger)data2;
- (CGEventRef)CGEvent;
@end

@interface NSPrintInfo : NSObject
+ (NSPrintInfo *)sharedPrintInfo;
- (NSMutableDictionary *)dictionary;
- (NSRect)imageablePageBounds;
- (NSSize)paperSize;
- (void)setPaperSize:(NSSize)size;
- (NSPrintingOrientation)orientation;
- (void)setOrientation:(NSPrintingOrientation)orientation;
- (CGFloat)leftMargin;
- (void)setBottomMargin:(CGFloat)margin;
- (void)setLeftMargin:(CGFloat)margin;
- (CGFloat)rightMargin;
- (void)setRightMargin:(CGFloat)margin;
- (CGFloat)topMargin;
- (void)setTopMargin:(CGFloat)margin;
- (CGFloat)bottomMargin;
- (void)setJobDisposition:(NSString *)disposition;
- (void)setPrinter:(NSPrinter *)printer;
- (NSPrinter *)printer;
- (void)setUpPrintOperationDefaultValues;
@end

@interface NSPrinter : NSObject
+ (NSPrinter *)printerWithName:(NSString *)name;
- (NSString *)name;
@end

@interface NSPrintOperation : NSObject
+ (NSPrintOperation *)currentOperation;
+ (NSPrintOperation *)printOperationWithView:(NSView *)view
                                   printInfo:(NSPrintInfo *)printInfo;
- (BOOL)runOperation;
- (NSPrintInfo *)printInfo;
- (NSGraphicsContext *)context;
- (NSInteger)currentPage;
- (void)setShowPanels:(BOOL)flag;
@end

@interface NSPageLayout : NSObject
+ (NSPageLayout *)pageLayout;
- (NSInteger)runModalWithPrintInfo:(NSPrintInfo *)printInfo;
@end

@interface NSPrintPanel : NSObject
+ (NSPrintPanel *)printPanel;
- (NSInteger)runModalWithPrintInfo:(NSPrintInfo *)printInfo;
@end

@interface NSControl : NSView
@end

@interface NSButton : NSControl
@property(nullable, strong) NSImage *image;
@end

@interface NSImageRep : NSObject
- (NSSize)size;
- (void)setSize:(NSSize)aSize;
- (NSInteger)pixelsWide;
- (NSInteger)pixelsHigh;
@end

@interface NSBitmapImageRep : NSImageRep
- (instancetype)initWithBitmapDataPlanes:(unsigned char **)planes
                               pixelsWide:(NSInteger)width
                               pixelsHigh:(NSInteger)height
                            bitsPerSample:(NSInteger)bitsPerSample
                          samplesPerPixel:(NSInteger)samplesPerPixel
                                 hasAlpha:(BOOL)hasAlpha
                                 isPlanar:(BOOL)isPlanar
                           colorSpaceName:(NSString *)colorSpaceName
                              bytesPerRow:(NSInteger)bytesPerRow
                             bitsPerPixel:(NSInteger)bitsPerPixel;
- (instancetype)initWithBitmapDataPlanes:(unsigned char **)planes
                               pixelsWide:(NSInteger)width
                               pixelsHigh:(NSInteger)height
                            bitsPerSample:(NSInteger)bitsPerSample
                          samplesPerPixel:(NSInteger)samplesPerPixel
                                 hasAlpha:(BOOL)hasAlpha
                                 isPlanar:(BOOL)isPlanar
                           colorSpaceName:(NSString *)colorSpaceName
                             bitmapFormat:(NSBitmapFormat)bitmapFormat
                              bytesPerRow:(NSInteger)bytesPerRow
                             bitsPerPixel:(NSInteger)bitsPerPixel;
- (unsigned char *)bitmapData;
- (NSData *)TIFFRepresentation;
@end

@interface NSImageView : NSControl
- (void)setImage:(NSImage *)newImage;
- (void)setImageScaling:(NSImageScaling)scaling;
- (void)setEditable:(BOOL)flag;
- (NSImage *)image;
@end

@interface NSWorkspace (AOSJDKSurface)
- (NSNotificationCenter *)notificationCenter;
- (NSImage *)iconForFile:(NSString *)fullPath;
- (BOOL)performFileOperation:(NSString *)operation
                      source:(NSString *)source
                 destination:(NSString *)destination
                       files:(NSArray<NSString *> *)files
                         tag:(NSInteger *)tag;
- (BOOL)selectFile:(NSString *)fullPath
    inFileViewerRootedAtPath:(NSString *)rootFullPath;
@end

@interface NSImage (AOSJDKSurface)
+ (instancetype)imageNamed:(NSString *)name;
- (NSData *)TIFFRepresentation;
- (instancetype)initWithData:(NSData *)data;
- (instancetype)initWithSize:(NSSize)aSize;
- (instancetype)initWithIconRef:(IconRef)iconRef;
- (void)setBackgroundColor:(NSColor *)color;
- (void)addRepresentations:(NSArray *)imageReps;
- (void)addRepresentation:(NSImageRep *)imageRep;
- (NSArray *)representations;
- (void)setScalesWhenResized:(BOOL)flag;
- (NSSize)size;
- (void)setSize:(NSSize)aSize;
- (void)lockFocus;
- (void)unlockFocus;
- (void)drawInRect:(NSRect)destinationRect
          fromRect:(NSRect)sourceRect
         operation:(NSCompositingOperation)operation
          fraction:(CGFloat)fraction;
@end

@interface NSMenu (AOSJDKSurface)
- (NSInteger)indexOfItem:(NSMenuItem *)index;
- (NSInteger)indexOfItemWithSubmenu:(NSMenu *)submenu;
- (void)insertItem:(NSMenuItem *)newItem atIndex:(NSInteger)index;
- (NSMenuItem *)itemAtIndex:(NSInteger)index;
- (NSMenuItem *)itemWithTag:(NSInteger)tag;
- (BOOL)popUpMenuPositioningItem:(NSMenuItem *)item
                      atLocation:(NSPoint)location
                          inView:(NSView *)view;
- (void)removeItem:(NSMenuItem *)item;
- (void)removeItemAtIndex:(NSInteger)index;
- (NSMenu *)supermenu;
- (void)setTitle:(NSString *)title;
- (NSString *)title;
- (void)setSupermenu:(NSMenu *)supermenu;
- (NSInteger)numberOfItems;
- (BOOL)performKeyEquivalent:(NSEvent *)event;
- (void)setDelegate:(id<NSMenuDelegate>)delegate;
@end

@interface NSMenuItem (AOSJDKSurface)
- (NSString *)keyEquivalent;
- (void)setAction:(SEL)action;
- (void)setImage:(NSImage *)image;
- (void)setKeyEquivalent:(NSString *)keyEquivalent;
- (void)setToolTip:(NSString *)toolTip;
- (void)setSubmenu:(NSMenu *)submenu;
- (NSMenu *)submenu;
- (void)setTitle:(NSString *)title;
- (NSString *)title;
- (void)setTarget:(id)target;
- (id)target;
@end

@interface NSPasteboard (AOSJDKSurface)
+ (instancetype)pasteboardWithName:(NSString *)name;
- (NSArray *)types;
- (BOOL)setPropertyList:(id)propertyList forType:(NSString *)dataType;
- (NSData *)dataForType:(NSString *)dataType;
- (id)propertyListForType:(NSString *)dataType;
- (NSString *)stringForType:(NSString *)dataType;
- (BOOL)setString:(NSString *)string forType:(NSString *)dataType;
@end

@interface NSStatusBar : NSObject
+ (NSStatusBar *)systemStatusBar;
- (NSStatusItem *)statusItemWithLength:(CGFloat)length;
- (void)removeStatusItem:(NSStatusItem *)item;
- (CGFloat)thickness;
@end

@interface NSStatusBarButton : NSButton
@end

@interface NSStatusItem : NSObject
- (void)setLength:(CGFloat)length;
- (id)target;
- (void)setTarget:(id)target;
- (NSString *)title;
- (void)setTitle:(NSString *)title;
- (void)popUpStatusItemMenu:(NSMenu *)menu;
- (void)setView:(NSView *)view;
- (void)drawStatusBarBackgroundInRect:(NSRect)rect withHighlight:(BOOL)highlight;
@end

@interface NSDockTile : NSObject
- (NSSize)size;
- (void)setContentView:(NSView *)view;
- (NSView *)contentView;
- (void)display;
- (void)setBadgeLabel:(NSString *)string;
- (NSString *)badgeLabel;
@end

@interface NSInputManager : NSObject
+ (NSInputManager *)currentInputManager;
- (void)markedTextAbandoned:(id)client;
- (BOOL)wantsToHandleMouseEvents;
- (BOOL)handleMouseEvent:(NSEvent *)event;
@end

#endif
