#ifndef _AOS_JAVA_RUNTIME_SUPPORT_H_
#define _AOS_JAVA_RUNTIME_SUPPORT_H_

/*
 * Minimal public JavaRuntimeSupport ABI consumed by IcedTea/OpenJDK 8.
 * Declarations and values are verified against Apple's MacOSX10.8 SDK,
 * current OpenJDK consumers, and independently generated Darwin bindings.
 * This is an SDK contract only; AOS does not provide an implementation.
 */
#import <Cocoa/Cocoa.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreText/CoreText.h>
#include <stdint.h>

typedef CFTypeRef JRSUIRendererRef;
typedef CFTypeRef JRSUIControlRef;
typedef uint32_t JRSFontRenderingStyle;
typedef int32_t jint;
typedef uint16_t UTF16Char;
typedef NSUInteger NSDragOperation;

typedef CFIndex JRSUIKey;
typedef CFIndex JRSUIWidget;
typedef CFIndex JRSUIState;
typedef CFIndex JRSUISize;
typedef CFIndex JRSUIDirection;
typedef CFIndex JRSUIOrintation;
typedef CFIndex JRSUIAlignmentHorizontal;
typedef CFIndex JRSUIAlignmentVertical;
typedef CFIndex JRSUISegmentPosition;
typedef CFIndex JRSUIScrollBarPart;
typedef CFIndex JRSUIVariant;
typedef CFIndex JRSUIWindowType;
typedef CFIndex JRSUIPresentationState;
typedef CFIndex JRSUIUserInterfaceLayoutDirection;
typedef CFIndex JRSUIPartHit;

enum {
  kJRSUI_Key_widget = 1, kJRSUI_Key_state = 2, kJRSUI_Key_size = 3,
  kJRSUI_Key_direction = 4, kJRSUI_Key_orientation = 5,
  kJRSUI_Key_verticalAlignment = 6, kJRSUI_Key_horizontalAlignment = 7,
  kJRSUI_Key_position = 8, kJRSUI_Key_pressedPart = 9,
  kJRSUI_Key_variant = 10, kJRSUI_Key_windowType = 11,
  kJRSUI_Key_focused = 12, kJRSUI_Key_indicatorOnly = 13,
  kJRSUI_Key_noIndicator = 14, kJRSUI_Key_nothingToScroll = 15,
  kJRSUI_Key_arrowsOnly = 16, kJRSUI_Key_frameOnly = 17,
  kJRSUI_Key_segmentTrailingSeparator = 18, kJRSUI_Key_maximumValue = 19,
  kJRSUI_Key_value = 20, kJRSUI_Key_animationStartTime = 21,
  kJRSUI_Key_animationTime = 22, kJRSUI_Key_animationFrame = 23,
  kJRSUI_Key_thumbProportion = 24, kJRSUI_Key_thumbStart = 25,
  kJRSUI_Key_windowFrameDrawClipped = 26,
  kJRSUI_Key_windowFrameDrawTitleSeparator = 27,
  kJRSUI_Key_windowTitleBarHeight = 28,
  kJRSUI_Key_segmentLeadingSeparator = 29,
  kJRSUI_Key_presentationState = 30,
  kJRSUI_Key_userInterfaceLayoutDirection = 31
};

enum {
  kJRSUI_Widget_background = 1, kJRSUI_Widget_buttonBevel = 2,
  kJRSUI_Widget_buttonBevelInset = 3, kJRSUI_Widget_buttonBevelRound = 4,
  kJRSUI_Widget_buttonCheckBox = 5, kJRSUI_Widget_buttonComboBox = 6,
  kJRSUI_Widget_buttonComboBoxInset = 7, kJRSUI_Widget_buttonDisclosure = 8,
  kJRSUI_Widget_buttonListHeader = 9, kJRSUI_Widget_buttonLittleArrows = 10,
  kJRSUI_Widget_buttonPopDown = 11, kJRSUI_Widget_buttonPopDownInset = 12,
  kJRSUI_Widget_buttonPopDownSquare = 13, kJRSUI_Widget_buttonPopUp = 14,
  kJRSUI_Widget_buttonPopUpInset = 15, kJRSUI_Widget_buttonPopUpSquare = 16,
  kJRSUI_Widget_buttonPush = 17, kJRSUI_Widget_buttonPushScope = 18,
  kJRSUI_Widget_buttonPushScope2 = 19, kJRSUI_Widget_buttonPushTextured = 20,
  kJRSUI_Widget_buttonPushInset = 21, kJRSUI_Widget_buttonPushInset2 = 22,
  kJRSUI_Widget_buttonRadio = 23, kJRSUI_Widget_buttonRound = 24,
  kJRSUI_Widget_buttonRoundHelp = 25, kJRSUI_Widget_buttonRoundInset = 26,
  kJRSUI_Widget_buttonRoundInset2 = 27,
  kJRSUI_Widget_buttonSearchFieldCancel = 28,
  kJRSUI_Widget_buttonSearchFieldFind = 29,
  kJRSUI_Widget_buttonSegmented = 30,
  kJRSUI_Widget_buttonSegmentedInset = 31,
  kJRSUI_Widget_buttonSegmentedInset2 = 32,
  kJRSUI_Widget_buttonSegmentedSCurve = 33,
  kJRSUI_Widget_buttonSegmentedTextured = 34,
  kJRSUI_Widget_buttonSegmentedToolbar = 35, kJRSUI_Widget_dial = 36,
  kJRSUI_Widget_disclosureTriangle = 37, kJRSUI_Widget_dividerGrabber = 38,
  kJRSUI_Widget_dividerSeparatorBar = 39, kJRSUI_Widget_dividerSplitter = 40,
  kJRSUI_Widget_focus = 41, kJRSUI_Widget_frameGroupBox = 42,
  kJRSUI_Widget_frameGroupBoxSecondary = 43, kJRSUI_Widget_frameListBox = 44,
  kJRSUI_Widget_framePlacard = 45, kJRSUI_Widget_frameTextField = 46,
  kJRSUI_Widget_frameTextFieldRound = 47, kJRSUI_Widget_frameWell = 48,
  kJRSUI_Widget_growBox = 49, kJRSUI_Widget_growBoxTextured = 50,
  kJRSUI_Widget_gradient = 51, kJRSUI_Widget_menu = 52,
  kJRSUI_Widget_menuItem = 53, kJRSUI_Widget_menuBar = 54,
  kJRSUI_Widget_menuTitle = 55, kJRSUI_Widget_progressBar = 56,
  kJRSUI_Widget_progressIndeterminateBar = 57,
  kJRSUI_Widget_progressRelevance = 58, kJRSUI_Widget_progressSpinner = 59,
  kJRSUI_Widget_scrollBar = 60, kJRSUI_Widget_scrollColumnSizer = 61,
  kJRSUI_Widget_slider = 62, kJRSUI_Widget_sliderThumb = 63,
  kJRSUI_Widget_synchronization = 64, kJRSUI_Widget_tab = 65,
  kJRSUI_Widget_titleBarCloseBox = 66,
  kJRSUI_Widget_titleBarCollapseBox = 67,
  kJRSUI_Widget_titleBarZoomBox = 68,
  kJRSUI_Widget_titleBarToolbarButton = 69,
  kJRSUI_Widget_toolbarItemWell = 70, kJRSUI_Widget_windowFrame = 71
};

enum { kJRSUI_State_active = 1, kJRSUI_State_inactive = 2,
  kJRSUI_State_disabled = 3, kJRSUI_State_pressed = 4,
  kJRSUI_State_pulsed = 5, kJRSUI_State_rollover = 6, kJRSUI_State_drag = 7 };
enum { kJRSUI_Size_mini = 1, kJRSUI_Size_small = 2,
  kJRSUI_Size_regular = 3, kJRSUI_Size_large = 4 };
enum { kJRSUI_Direction_none = 1, kJRSUI_Direction_up = 2,
  kJRSUI_Direction_down = 3, kJRSUI_Direction_left = 4,
  kJRSUI_Direction_right = 5, kJRSUI_Direction_north = 6,
  kJRSUI_Direction_south = 7, kJRSUI_Direction_east = 8,
  kJRSUI_Direction_west = 9 };
enum { kJRSUI_Orientation_horizontal = 1, kJRSUI_Orientation_vertical = 2 };
enum { kJRSUI_AlignmentHorizontal_left = 1,
  kJRSUI_AlignmentHorizontal_center = 2, kJRSUI_AlignmentHorizontal_right = 3 };
enum { kJRSUI_AlignmentVertical_top = 1, kJRSUI_AlignmentVertical_center = 2,
  kJRSUI_AlignmentVertical_bottom = 3 };
enum { kJRSUI_SegmentPosition_first = 1, kJRSUI_SegmentPosition_middle = 2,
  kJRSUI_SegmentPosition_last = 3, kJRSUI_SegmentPosition_only = 4 };
enum { kJRSUI_ScrollBarPart_none = 1, kJRSUI_ScrollBarPart_thumb = 2,
  kJRSUI_ScrollBarPart_arrowMin = 3, kJRSUI_ScrollBarPart_arrowMax = 4,
  kJRSUI_ScrollBarPart_arrowMaxInside = 5,
  kJRSUI_ScrollBarPart_arrowMinInside = 6,
  kJRSUI_ScrollBarPart_trackMin = 7, kJRSUI_ScrollBarPart_trackMax = 8 };
enum { kJRSUI_Variant_menuGlyph = 1, kJRSUI_Variant_menuPopup = 2,
  kJRSUI_Variant_menuPulldown = 3, kJRSUI_Variant_menuHierarchical = 4,
  kJRSUI_Variant_gradientListBackgroundEven = 5,
  kJRSUI_Variant_gradientListBackgroundOdd = 6,
  kJRSUI_Variant_gradientSideBar = 7,
  kJRSUI_Variant_gradientSideBarSelection = 8,
  kJRSUI_Variant_gradientSideBarFocusedSelection = 9 };
enum { kJRSUI_WindowType_document = 1, kJRSUI_WindowType_utility = 2,
  kJRSUI_WindowType_titlelessUtility = 3 };
enum { kJRSUI_PresentationState_activeKey = 1,
  kJRSUI_PresentationState_activeMain = 2,
  kJRSUI_PresentationState_inactive = 3 };
enum { kJRSUI_UserInterfaceLayoutDirection_leftToRight = 1,
  kJRSUI_UserInterfaceLayoutDirection_rightToLeft = 2 };
enum { kJRSUI_PartHit_unknown = -1, kJRSUI_PartHit_none = 0,
  kJRSUI_PartHit_hit = 1, kJRSUI_PartHit_thumb = 2,
  kJRSUI_PartHit_trackMin = 3, kJRSUI_PartHit_trackMax = 4,
  kJRSUI_PartHit_arrowMin = 5, kJRSUI_PartHit_arrowMax = 6,
  kJRSUI_PartHit_arrowMaxInside = 7, kJRSUI_PartHit_arrowMinInside = 8 };

JRSUIRendererRef JRSUIRendererCreate(void);
JRSUIControlRef JRSUIControlCreate(Boolean isFlipped);
void JRSUIControlRelease(JRSUIControlRef control);
void JRSUIControlDraw(JRSUIRendererRef renderer, JRSUIControlRef control,
  CGContextRef context, CGRect bounds);
CFTypeRef JRSUIGetKey(JRSUIKey value);
void JRSUIControlSetValueByKey(JRSUIControlRef control, CFTypeRef key, CFTypeRef value);
void JRSUIControlSetWidget(JRSUIControlRef control, JRSUIWidget value);
void JRSUIControlSetState(JRSUIControlRef control, JRSUIState value);
void JRSUIControlSetSize(JRSUIControlRef control, JRSUISize value);
void JRSUIControlSetDirection(JRSUIControlRef control, JRSUIDirection value);
void JRSUIControlSetOrientation(JRSUIControlRef control, JRSUIOrintation value);
void JRSUIControlSetAlignmentVertical(JRSUIControlRef control, JRSUIAlignmentHorizontal value);
void JRSUIControlSetAlignmentHorizontal(JRSUIControlRef control, JRSUIAlignmentVertical value);
void JRSUIControlSetSegmentPosition(JRSUIControlRef control, JRSUISegmentPosition value);
void JRSUIControlSetScrollBarPart(JRSUIControlRef control, JRSUIScrollBarPart value);
void JRSUIControlSetVariant(JRSUIControlRef control, JRSUIVariant value);
void JRSUIControlSetWindowType(JRSUIControlRef control, JRSUIWindowType value);
void JRSUIControlSetShowArrows(JRSUIControlRef control, Boolean value);
void JRSUIControlSetAnimating(JRSUIControlRef control, Boolean value);
Boolean JRSUIControlShouldScrollToClick(void);
CGRect JRSUIControlGetScrollBarPartBounds(JRSUIControlRef control, CGRect frame,
  JRSUIScrollBarPart part);
CGFloat JRSUIControlGetScrollBarOffsetFor(JRSUIControlRef control, CGRect frame,
  CGFloat offset, CGFloat visibleAmount, CGFloat extent);
JRSUIPartHit JRSUIControlGetHitPart(JRSUIRendererRef renderer,
  JRSUIControlRef control, CGRect bounds, CGPoint point);

JRSFontRenderingStyle JRSFontGetRenderingStyleForHints(jint fmHint, jint aaHint);
JRSFontRenderingStyle JRSFontAlignStyleForFractionalMeasurement(JRSFontRenderingStyle style);
bool JRSFontStyleUsesFractionalMetrics(JRSFontRenderingStyle style);
void JRSFontSetRenderingStyleOnContext(CGContextRef context, JRSFontRenderingStyle style);
CTFontRef JRSFontCreateFallbackFontForCharacters(CTFontRef font,
  const UTF16Char *characters, CFIndex length);
CGRect JRSFontGetBoundingBoxesForGlyphsAndStyle(CTFontRef font,
  const CGAffineTransform *transform, JRSFontRenderingStyle style,
  const CGGlyph glyphs[], size_t count, CGRect boxes[]);

void JRSAccessibilityUnregisterUniqueIdForUIElement(id element);

@protocol JRSMenuDelegate <NSObject>
@optional
- (void)handleJavaMouseEvent:(NSEvent *)event;
- (void)handleJavaMenuItemTargetedAtIndex:(NSUInteger)menuIndex rect:(NSRect)rect;
@end

@interface NSMenu (JavaRuntimeSupport)
+ (NSMenu *)javaMenuWithTitle:(NSString *)title;
- (void)setJavaMenuDelegate:(id<JRSMenuDelegate>)delegate;
- (BOOL)isJavaMenu;
@end

@interface NSEvent (JavaRuntimeSupport)
- (unichar)deadKeyCharacter;
- (BOOL)willBeHandledByComplexInputMethod;
@end

@interface JRSDrag : NSObject
+ (NSDragOperation)currentAllowableActions;
+ (NSUInteger)currentModifiers;
@end

@interface JRSInputMethodController : NSObject
+ (JRSInputMethodController *)controller;
- (NSArray *)availableInputMethodLocales;
- (NSString *)currentInputMethodName;
- (NSString *)currentInputMethodLocale;
- (void)setCurrentInputMethodForLocale:(NSString *)locale;
@end

#define JRSAppNameKey @"JRSAppNameKey"
#define JRSAppIsCommandLineKey @"JRSAppIsCommandLineKey"
#define JRSAppIsUIElementKey @"JRSAppIsUIElementKey"
#define JRSAppIsBackgroundOnlyKey @"JRSAppIsBackgroundOnlyKey"

@interface JRSAppKitAWT : NSObject
+ (id<NSApplicationDelegate>)awtAppDelegate;
+ (void)registerAWTAppWithOptions:(NSDictionary *)options;
+ (BOOL)markAppIsDaemon;
@end

#endif
