#import <JavaRuntimeSupport/JavaRuntimeSupport.h>

#define AOS_ASSERT(name, value) _Static_assert(name == value, #name " ABI")

AOS_ASSERT(kJRSUI_Key_value, 20);
AOS_ASSERT(kJRSUI_Key_thumbProportion, 24);
AOS_ASSERT(kJRSUI_Key_thumbStart, 25);
AOS_ASSERT(kJRSUI_Key_animationFrame, 23);
AOS_ASSERT(kJRSUI_Key_windowTitleBarHeight, 28);

AOS_ASSERT(kJRSUI_Widget_background, 1);
AOS_ASSERT(kJRSUI_Widget_buttonBevel, 2);
AOS_ASSERT(kJRSUI_Widget_buttonBevelInset, 3);
AOS_ASSERT(kJRSUI_Widget_buttonBevelRound, 4);
AOS_ASSERT(kJRSUI_Widget_buttonCheckBox, 5);
AOS_ASSERT(kJRSUI_Widget_buttonComboBox, 6);
AOS_ASSERT(kJRSUI_Widget_buttonComboBoxInset, 7);
AOS_ASSERT(kJRSUI_Widget_buttonDisclosure, 8);
AOS_ASSERT(kJRSUI_Widget_buttonListHeader, 9);
AOS_ASSERT(kJRSUI_Widget_buttonLittleArrows, 10);
AOS_ASSERT(kJRSUI_Widget_buttonPopDown, 11);
AOS_ASSERT(kJRSUI_Widget_buttonPopDownInset, 12);
AOS_ASSERT(kJRSUI_Widget_buttonPopDownSquare, 13);
AOS_ASSERT(kJRSUI_Widget_buttonPopUp, 14);
AOS_ASSERT(kJRSUI_Widget_buttonPopUpInset, 15);
AOS_ASSERT(kJRSUI_Widget_buttonPopUpSquare, 16);
AOS_ASSERT(kJRSUI_Widget_buttonPush, 17);
AOS_ASSERT(kJRSUI_Widget_buttonPushScope, 18);
AOS_ASSERT(kJRSUI_Widget_buttonPushScope2, 19);
AOS_ASSERT(kJRSUI_Widget_buttonPushTextured, 20);
AOS_ASSERT(kJRSUI_Widget_buttonPushInset, 21);
AOS_ASSERT(kJRSUI_Widget_buttonPushInset2, 22);
AOS_ASSERT(kJRSUI_Widget_buttonRadio, 23);
AOS_ASSERT(kJRSUI_Widget_buttonRound, 24);
AOS_ASSERT(kJRSUI_Widget_buttonRoundHelp, 25);
AOS_ASSERT(kJRSUI_Widget_buttonRoundInset, 26);
AOS_ASSERT(kJRSUI_Widget_buttonRoundInset2, 27);
AOS_ASSERT(kJRSUI_Widget_buttonSearchFieldCancel, 28);
AOS_ASSERT(kJRSUI_Widget_buttonSearchFieldFind, 29);
AOS_ASSERT(kJRSUI_Widget_buttonSegmented, 30);
AOS_ASSERT(kJRSUI_Widget_buttonSegmentedInset, 31);
AOS_ASSERT(kJRSUI_Widget_buttonSegmentedInset2, 32);
AOS_ASSERT(kJRSUI_Widget_buttonSegmentedSCurve, 33);
AOS_ASSERT(kJRSUI_Widget_buttonSegmentedTextured, 34);
AOS_ASSERT(kJRSUI_Widget_buttonSegmentedToolbar, 35);
AOS_ASSERT(kJRSUI_Widget_dial, 36);
AOS_ASSERT(kJRSUI_Widget_disclosureTriangle, 37);
AOS_ASSERT(kJRSUI_Widget_dividerGrabber, 38);
AOS_ASSERT(kJRSUI_Widget_dividerSeparatorBar, 39);
AOS_ASSERT(kJRSUI_Widget_dividerSplitter, 40);
AOS_ASSERT(kJRSUI_Widget_focus, 41);
AOS_ASSERT(kJRSUI_Widget_frameGroupBox, 42);
AOS_ASSERT(kJRSUI_Widget_frameGroupBoxSecondary, 43);
AOS_ASSERT(kJRSUI_Widget_frameListBox, 44);
AOS_ASSERT(kJRSUI_Widget_framePlacard, 45);
AOS_ASSERT(kJRSUI_Widget_frameTextField, 46);
AOS_ASSERT(kJRSUI_Widget_frameTextFieldRound, 47);
AOS_ASSERT(kJRSUI_Widget_frameWell, 48);
AOS_ASSERT(kJRSUI_Widget_growBox, 49);
AOS_ASSERT(kJRSUI_Widget_growBoxTextured, 50);
AOS_ASSERT(kJRSUI_Widget_gradient, 51);
AOS_ASSERT(kJRSUI_Widget_menu, 52);
AOS_ASSERT(kJRSUI_Widget_menuItem, 53);
AOS_ASSERT(kJRSUI_Widget_menuBar, 54);
AOS_ASSERT(kJRSUI_Widget_menuTitle, 55);
AOS_ASSERT(kJRSUI_Widget_progressBar, 56);
AOS_ASSERT(kJRSUI_Widget_progressIndeterminateBar, 57);
AOS_ASSERT(kJRSUI_Widget_progressRelevance, 58);
AOS_ASSERT(kJRSUI_Widget_progressSpinner, 59);
AOS_ASSERT(kJRSUI_Widget_scrollBar, 60);
AOS_ASSERT(kJRSUI_Widget_scrollColumnSizer, 61);
AOS_ASSERT(kJRSUI_Widget_slider, 62);
AOS_ASSERT(kJRSUI_Widget_sliderThumb, 63);
AOS_ASSERT(kJRSUI_Widget_synchronization, 64);
AOS_ASSERT(kJRSUI_Widget_tab, 65);
AOS_ASSERT(kJRSUI_Widget_titleBarCloseBox, 66);
AOS_ASSERT(kJRSUI_Widget_titleBarCollapseBox, 67);
AOS_ASSERT(kJRSUI_Widget_titleBarZoomBox, 68);
AOS_ASSERT(kJRSUI_Widget_titleBarToolbarButton, 69);
AOS_ASSERT(kJRSUI_Widget_toolbarItemWell, 70);
AOS_ASSERT(kJRSUI_Widget_windowFrame, 71);

AOS_ASSERT(kJRSUI_State_active, 1); AOS_ASSERT(kJRSUI_State_inactive, 2);
AOS_ASSERT(kJRSUI_State_disabled, 3); AOS_ASSERT(kJRSUI_State_pressed, 4);
AOS_ASSERT(kJRSUI_State_pulsed, 5); AOS_ASSERT(kJRSUI_State_rollover, 6);
AOS_ASSERT(kJRSUI_State_drag, 7);
AOS_ASSERT(kJRSUI_Size_mini, 1); AOS_ASSERT(kJRSUI_Size_small, 2);
AOS_ASSERT(kJRSUI_Size_regular, 3); AOS_ASSERT(kJRSUI_Size_large, 4);
AOS_ASSERT(kJRSUI_Direction_none, 1); AOS_ASSERT(kJRSUI_Direction_up, 2);
AOS_ASSERT(kJRSUI_Direction_down, 3); AOS_ASSERT(kJRSUI_Direction_left, 4);
AOS_ASSERT(kJRSUI_Direction_right, 5); AOS_ASSERT(kJRSUI_Direction_north, 6);
AOS_ASSERT(kJRSUI_Direction_south, 7); AOS_ASSERT(kJRSUI_Direction_east, 8);
AOS_ASSERT(kJRSUI_Direction_west, 9);
AOS_ASSERT(kJRSUI_Orientation_horizontal, 1); AOS_ASSERT(kJRSUI_Orientation_vertical, 2);
AOS_ASSERT(kJRSUI_AlignmentHorizontal_left, 1);
AOS_ASSERT(kJRSUI_AlignmentHorizontal_center, 2);
AOS_ASSERT(kJRSUI_AlignmentHorizontal_right, 3);
AOS_ASSERT(kJRSUI_AlignmentVertical_top, 1);
AOS_ASSERT(kJRSUI_AlignmentVertical_center, 2);
AOS_ASSERT(kJRSUI_AlignmentVertical_bottom, 3);
AOS_ASSERT(kJRSUI_SegmentPosition_first, 1); AOS_ASSERT(kJRSUI_SegmentPosition_middle, 2);
AOS_ASSERT(kJRSUI_SegmentPosition_last, 3); AOS_ASSERT(kJRSUI_SegmentPosition_only, 4);
AOS_ASSERT(kJRSUI_ScrollBarPart_none, 1); AOS_ASSERT(kJRSUI_ScrollBarPart_thumb, 2);
AOS_ASSERT(kJRSUI_ScrollBarPart_arrowMin, 3); AOS_ASSERT(kJRSUI_ScrollBarPart_arrowMax, 4);
AOS_ASSERT(kJRSUI_ScrollBarPart_arrowMaxInside, 5);
AOS_ASSERT(kJRSUI_ScrollBarPart_arrowMinInside, 6);
AOS_ASSERT(kJRSUI_ScrollBarPart_trackMin, 7); AOS_ASSERT(kJRSUI_ScrollBarPart_trackMax, 8);
AOS_ASSERT(kJRSUI_Variant_menuGlyph, 1); AOS_ASSERT(kJRSUI_Variant_menuPopup, 2);
AOS_ASSERT(kJRSUI_Variant_menuPulldown, 3); AOS_ASSERT(kJRSUI_Variant_menuHierarchical, 4);
AOS_ASSERT(kJRSUI_Variant_gradientListBackgroundEven, 5);
AOS_ASSERT(kJRSUI_Variant_gradientListBackgroundOdd, 6);
AOS_ASSERT(kJRSUI_Variant_gradientSideBar, 7);
AOS_ASSERT(kJRSUI_Variant_gradientSideBarSelection, 8);
AOS_ASSERT(kJRSUI_Variant_gradientSideBarFocusedSelection, 9);
AOS_ASSERT(kJRSUI_WindowType_document, 1); AOS_ASSERT(kJRSUI_WindowType_utility, 2);
AOS_ASSERT(kJRSUI_WindowType_titlelessUtility, 3);

@interface AOSJRSMenuDelegate : NSObject <JRSMenuDelegate>
@end
@implementation AOSJRSMenuDelegate
@end

int main(void) {
  JRSUIRendererRef renderer = JRSUIRendererCreate();
  JRSUIControlRef control = JRSUIControlCreate(false);
  CGRect frame = CGRectZero;
  JRSUIControlDraw(renderer, control, NULL, frame);
  JRSUIControlSetValueByKey(control, JRSUIGetKey(kJRSUI_Key_value), NULL);
  JRSUIControlSetWidget(control, kJRSUI_Widget_background);
  JRSUIControlSetState(control, kJRSUI_State_active);
  JRSUIControlSetSize(control, kJRSUI_Size_regular);
  JRSUIControlSetDirection(control, kJRSUI_Direction_none);
  JRSUIControlSetOrientation(control, kJRSUI_Orientation_horizontal);
  JRSUIControlSetAlignmentVertical(control, kJRSUI_AlignmentHorizontal_left);
  JRSUIControlSetAlignmentHorizontal(control, kJRSUI_AlignmentVertical_top);
  JRSUIControlSetSegmentPosition(control, kJRSUI_SegmentPosition_only);
  JRSUIControlSetScrollBarPart(control, kJRSUI_ScrollBarPart_thumb);
  JRSUIControlSetVariant(control, kJRSUI_Variant_menuGlyph);
  JRSUIControlSetWindowType(control, kJRSUI_WindowType_document);
  JRSUIControlSetShowArrows(control, true);
  JRSUIControlSetAnimating(control, false);
  CGRect partBounds = JRSUIControlGetScrollBarPartBounds(control, frame, kJRSUI_ScrollBarPart_thumb);
  CGFloat offset = JRSUIControlGetScrollBarOffsetFor(control, frame, 0, 1, 1);
  JRSUIPartHit hit = JRSUIControlGetHitPart(renderer, control, frame, CGPointMake(0, 0));
  Boolean scroll = JRSUIControlShouldScrollToClick();
  JRSFontRenderingStyle style = JRSFontGetRenderingStyleForHints(0, 0);
  style = JRSFontAlignStyleForFractionalMeasurement(style);
  JRSFontSetRenderingStyleOnContext(NULL, style);
  UTF16Char character = 0;
  CTFontRef font = JRSFontCreateFallbackFontForCharacters(NULL, &character, 1);
  CGGlyph glyph = 0;
  CGRect box = CGRectZero;
  CGRect bounds = JRSFontGetBoundingBoxesForGlyphsAndStyle(font, NULL, style, &glyph, 1, &box);
  NSMenu *menu = [NSMenu javaMenuWithTitle:JRSAppNameKey];
  [menu setJavaMenuDelegate:[[AOSJRSMenuDelegate alloc] init]];
  BOOL javaMenu = [menu isJavaMenu];
  JRSAccessibilityUnregisterUniqueIdForUIElement(nil);
  JRSUIControlRelease(control);
  return partBounds.size.width == offset || bounds.size.height == hit || scroll ||
    !JRSFontStyleUsesFractionalMetrics(style) || !javaMenu ||
    JRSAppIsCommandLineKey == JRSAppIsUIElementKey || JRSAppIsBackgroundOnlyKey == nil;
}
