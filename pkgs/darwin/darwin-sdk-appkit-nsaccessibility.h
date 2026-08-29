#ifndef _AOS_APPKIT_NSACCESSIBILITY_H_
#define _AOS_APPKIT_NSACCESSIBILITY_H_

/*
 * Minimal public AppKit accessibility surface used by the Darwin JDK build.
 * Signatures are consumer-derived and verified against Apple's public SDK ABI.
 */
#import <AppKit/AppKit.h>

@protocol NSAccessibility <NSObject>
- (NSInteger)accessibilityColumnCount;
- (BOOL)isAccessibilitySelectorAllowed:(SEL)selector;
@end

typedef NS_ENUM(NSInteger, NSAccessibilityOrientation) {
  NSAccessibilityOrientationUnknown = 0,
  NSAccessibilityOrientationVertical = 1,
  NSAccessibilityOrientationHorizontal = 2,
};

typedef NSString *NSAccessibilityAttributeName;
typedef NSString *NSAccessibilityParameterizedAttributeName;
typedef NSString *NSAccessibilityActionName;
typedef NSString *NSAccessibilityNotificationName;
typedef NSString *NSAccessibilityRole;
typedef NSString *NSAccessibilitySubrole;

extern NSAccessibilityAttributeName const NSAccessibilityColumnCountAttribute;
extern NSAccessibilityAttributeName const NSAccessibilityInsertionPointLineNumberAttribute;
extern NSAccessibilityAttributeName const NSAccessibilityNumberOfCharactersAttribute;
extern NSAccessibilityAttributeName const NSAccessibilityRowCountAttribute;
extern NSAccessibilityAttributeName const NSAccessibilitySelectedTextAttribute;
extern NSAccessibilityAttributeName const NSAccessibilitySelectedTextRangeAttribute;
extern NSAccessibilityAttributeName const NSAccessibilityVisibleCharacterRangeAttribute;
extern NSAccessibilityParameterizedAttributeName const NSAccessibilityBoundsForRangeParameterizedAttribute;
extern NSAccessibilityParameterizedAttributeName const NSAccessibilityLineForIndexParameterizedAttribute;
extern NSAccessibilityParameterizedAttributeName const NSAccessibilityRangeForIndexParameterizedAttribute;
extern NSAccessibilityParameterizedAttributeName const NSAccessibilityRangeForLineParameterizedAttribute;
extern NSAccessibilityParameterizedAttributeName const NSAccessibilityRangeForPositionParameterizedAttribute;
extern NSAccessibilityParameterizedAttributeName const NSAccessibilityStringForRangeParameterizedAttribute;
extern NSAccessibilityActionName const NSAccessibilityDecrementAction;
extern NSAccessibilityActionName const NSAccessibilityIncrementAction;
extern NSAccessibilityActionName const NSAccessibilityShowMenuAction;
extern NSAccessibilityNotificationName const NSAccessibilityRowCollapsedNotification;
extern NSAccessibilityNotificationName const NSAccessibilityRowExpandedNotification;
extern NSAccessibilityNotificationName const NSAccessibilitySelectedCellsChangedNotification;
extern NSAccessibilityNotificationName const NSAccessibilityTitleChangedNotification;
extern NSAccessibilityRole const NSAccessibilityCellRole;
extern NSAccessibilityRole const NSAccessibilityGridRole;
extern NSAccessibilityRole const NSAccessibilityMenuBarItemRole;
extern NSAccessibilityRole const NSAccessibilityOutlineRole;
extern NSAccessibilitySubrole const NSAccessibilityOutlineRowSubrole;
extern NSAccessibilitySubrole const NSAccessibilityTabButtonSubrole;
extern NSAccessibilitySubrole const NSAccessibilityTableRowSubrole;
extern NSAccessibilitySubrole const NSAccessibilityUnknownSubrole;

@protocol NSAccessibilityElement <NSObject>
@end

@protocol NSAccessibilityRow;

@protocol NSAccessibilityButton <NSAccessibilityElement>
- (NSString *)accessibilityLabel;
@end

@protocol NSAccessibilityCheckBox <NSAccessibilityButton>
- (NSNumber *)accessibilityValue;
@end

@protocol NSAccessibilityGroup <NSAccessibilityElement>
@end

@protocol NSAccessibilityProgressIndicator <NSAccessibilityGroup>
@end

@protocol NSAccessibilityImage <NSAccessibilityElement>
- (NSString *)accessibilityLabel;
@end

@protocol NSAccessibilityTable <NSAccessibilityGroup>
- (NSString *)accessibilityLabel;
- (NSArray<id<NSAccessibilityRow>> *)accessibilityRows;
- (NSArray<id<NSAccessibilityRow>> *)accessibilitySelectedRows;
@end

@protocol NSAccessibilityList <NSAccessibilityTable>
@end

@protocol NSAccessibilityOutline <NSAccessibilityTable>
@end

@protocol NSAccessibilityRow <NSAccessibilityGroup>
@end

@protocol NSAccessibilityRadioButton <NSAccessibilityButton>
- (NSNumber *)accessibilityValue;
@end

@protocol NSAccessibilitySlider <NSAccessibilityElement>
- (NSString *)accessibilityLabel;
- (id)accessibilityValue;
@end

@protocol NSAccessibilityStaticText <NSAccessibilityElement>
- (NSString *)accessibilityValue;
@end

@protocol NSAccessibilityNavigableStaticText <NSAccessibilityStaticText>
@end

@protocol NSAccessibilityStepper <NSAccessibilityElement>
- (NSString *)accessibilityLabel;
- (id)accessibilityValue;
@end

@interface NSAccessibilityElement : NSObject <NSAccessibility>
@end

#endif
