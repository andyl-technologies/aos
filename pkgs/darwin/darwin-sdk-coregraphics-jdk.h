#ifndef _AOS_COREGRAPHICS_JDK_SURFACE_H_
#define _AOS_COREGRAPHICS_JDK_SURFACE_H_

/*
 * Public CoreGraphics ABI used by the IcedTea JDK 8 macOS implementation.
 * This minimal surface is independently authored from the release-active
 * consumers and verified against Apple's published CoreGraphics ABI.
 */
#include <CoreGraphics/CGBitmapContext.h>
#include <CoreGraphics/CGColor.h>
#include <CoreGraphics/CGContext.h>
#include <CoreGraphics/CGDirectDisplay.h>
#include <CoreGraphics/CGEvent.h>
#include <CoreGraphics/CGFont.h>
#include <CoreGraphics/CGImage.h>
#include <CoreGraphics/CGPath.h>
#include <CoreGraphics/CGRemoteOperation.h>
#include <CoreGraphics/CGWindow.h>

typedef uint16_t CGCharCode;
typedef struct CGFunction *CGFunctionRef;
typedef struct CGGradient *CGGradientRef;
typedef struct CGPattern *CGPatternRef;
typedef struct CGShading *CGShadingRef;
typedef uint32_t CGGradientDrawingOptions;
typedef enum CGPatternTiling { kCGPatternTilingNoDistortion = 0 } CGPatternTiling;

enum { kCGGradientDrawsAfterEndLocation = 1U << 1 };

typedef void (*CGFunctionEvaluateCallback)(void *, const CGFloat *, CGFloat *);
typedef void (*CGFunctionReleaseInfoCallback)(void *);
typedef struct CGFunctionCallbacks {
  unsigned int version;
  CGFunctionEvaluateCallback evaluate;
  CGFunctionReleaseInfoCallback releaseInfo;
} CGFunctionCallbacks;

typedef void (*CGPatternDrawPatternCallback)(void *, CGContextRef);
typedef void (*CGPatternReleaseInfoCallback)(void *);
typedef struct CGPatternCallbacks {
  unsigned int version;
  CGPatternDrawPatternCallback drawPattern;
  CGPatternReleaseInfoCallback releaseInfo;
} CGPatternCallbacks;

typedef uint32_t CGDisplayChangeSummaryFlags;
typedef void (*CGDisplayReconfigurationCallBack)(
  CGDirectDisplayID, CGDisplayChangeSummaryFlags, void *);
enum {
  kCGDisplayBeginConfigurationFlag = 1U << 0,
  kCGDisplayRemoveFlag = 1U << 5
};

typedef uint32_t CGEventField;
typedef int32_t CGEventSourceStateID;
typedef uint64_t CGEventFlags;
typedef uint32_t CGScrollEventUnit;
enum {
  kCGEventLeftMouseDown = 1,
  kCGEventLeftMouseUp = 2,
  kCGEventRightMouseDown = 3,
  kCGEventRightMouseUp = 4,
  kCGEventLeftMouseDragged = 6,
  kCGEventRightMouseDragged = 7,
  kCGEventOtherMouseDown = 25,
  kCGEventOtherMouseUp = 26,
  kCGEventOtherMouseDragged = 27,
  kCGMouseButtonRight = 1,
  kCGMouseButtonCenter = 2,
  kCGMouseEventNumber = 0,
  kCGMouseEventClickState = 1,
  kCGEventSourceStateCombinedSessionState = 0,
  kCGEventSourceStatePrivate = -1,
  kCGEventSourceStateHIDSystemState = 1,
  kCGEventFlagMaskSecondaryFn = 0x00800000,
  kCGScrollEventUnitLine = 1,
  kCGSessionEventTap = 1
};

typedef uint32_t CGWindowID;
typedef uint32_t CGWindowListOption;
typedef uint32_t CGWindowImageOption;
typedef int32_t CGWindowLevel;
typedef int32_t CGWindowLevelKey;
enum {
  kCGNullWindowID = 0,
  kCGNormalWindowLevelKey = 4,
  kCGFloatingWindowLevelKey = 5,
  kCGPopUpMenuWindowLevelKey = 11,
  kCGWindowListOptionOnScreenOnly = 1,
  kCGWindowListExcludeDesktopElements = 16,
  kCGWindowImageDefault = 0,
  kCGWindowImageBestResolution = 1U << 3
};

enum { kCGBitmapByteOrderMask = 0x7000 };

CGAffineTransform CGAffineTransformConcat(CGAffineTransform, CGAffineTransform);
CGAffineTransform CGAffineTransformInvert(CGAffineTransform);
CGAffineTransform CGAffineTransformMakeScale(CGFloat, CGFloat);
CGError CGBeginDisplayConfiguration(CGDisplayConfigRef *);
CGContextRef CGBitmapContextCreate(void *, size_t, size_t, size_t, size_t, CGColorSpaceRef, CGBitmapInfo);
CGColorRef CGColorCreate(CGColorSpaceRef, const CGFloat[]);
void CGColorRelease(CGColorRef);
CGColorSpaceRef CGColorSpaceCreateDeviceRGB(void);
CGColorSpaceRef CGColorSpaceCreatePattern(CGColorSpaceRef);
CGColorSpaceRef CGColorSpaceCreateWithName(CFStringRef);
void CGColorSpaceRelease(CGColorSpaceRef);
CGError CGCompleteDisplayConfiguration(CGDisplayConfigRef, CGConfigureOption);
CGError CGConfigureDisplayWithDisplayMode(CGDisplayConfigRef, CGDirectDisplayID, CGDisplayModeRef, CFDictionaryRef);
void CGContextAddCurveToPoint(CGContextRef, CGFloat, CGFloat, CGFloat, CGFloat, CGFloat, CGFloat);
void CGContextAddEllipseInRect(CGContextRef, CGRect);
void CGContextAddLineToPoint(CGContextRef, CGFloat, CGFloat);
void CGContextAddQuadCurveToPoint(CGContextRef, CGFloat, CGFloat, CGFloat, CGFloat);
void CGContextAddRect(CGContextRef, CGRect);
void CGContextBeginPath(CGContextRef);
void CGContextClip(CGContextRef);
void CGContextClipToRect(CGContextRef, CGRect);
void CGContextClosePath(CGContextRef);
void CGContextConcatCTM(CGContextRef, CGAffineTransform);
void CGContextDrawImage(CGContextRef, CGRect, CGImageRef);
void CGContextDrawLinearGradient(CGContextRef, CGGradientRef, CGPoint, CGPoint, CGGradientDrawingOptions);
void CGContextDrawRadialGradient(CGContextRef, CGGradientRef, CGPoint, CGFloat, CGPoint, CGFloat, CGGradientDrawingOptions);
void CGContextDrawShading(CGContextRef, CGShadingRef);
void CGContextEOClip(CGContextRef);
void CGContextEOFillPath(CGContextRef);
void CGContextFillEllipseInRect(CGContextRef, CGRect);
void CGContextFillPath(CGContextRef);
void CGContextFillRect(CGContextRef, CGRect);
void CGContextFlush(CGContextRef);
CGAffineTransform CGContextGetCTM(CGContextRef);
CGRect CGContextGetClipBoundingBox(CGContextRef);
CGAffineTransform CGContextGetTextMatrix(CGContextRef);
bool CGContextIsPathEmpty(CGContextRef);
void CGContextMoveToPoint(CGContextRef, CGFloat, CGFloat);
void CGContextRelease(CGContextRef);
void CGContextRestoreGState(CGContextRef);
void CGContextSaveGState(CGContextRef);
void CGContextScaleCTM(CGContextRef, CGFloat, CGFloat);
void CGContextSetAlpha(CGContextRef, CGFloat);
void CGContextSetBlendMode(CGContextRef, CGBlendMode);
void CGContextSetFillColorSpace(CGContextRef, CGColorSpaceRef);
void CGContextSetFillColorWithColor(CGContextRef, CGColorRef);
void CGContextSetFillPattern(CGContextRef, CGPatternRef, const CGFloat[]);
void CGContextSetFont(CGContextRef, CGFontRef);
void CGContextSetFontSize(CGContextRef, CGFloat);
void CGContextSetInterpolationQuality(CGContextRef, CGInterpolationQuality);
void CGContextSetLineCap(CGContextRef, CGLineCap);
void CGContextSetLineDash(CGContextRef, CGFloat, const CGFloat[], size_t);
void CGContextSetLineJoin(CGContextRef, CGLineJoin);
void CGContextSetLineWidth(CGContextRef, CGFloat);
void CGContextSetMiterLimit(CGContextRef, CGFloat);
void CGContextSetPatternPhase(CGContextRef, CGSize);
void CGContextSetRGBFillColor(CGContextRef, CGFloat, CGFloat, CGFloat, CGFloat);
void CGContextSetRGBStrokeColor(CGContextRef, CGFloat, CGFloat, CGFloat, CGFloat);
void CGContextSetShouldAntialias(CGContextRef, bool);
void CGContextSetStrokeColorSpace(CGContextRef, CGColorSpaceRef);
void CGContextSetStrokeColorWithColor(CGContextRef, CGColorRef);
void CGContextSetTextMatrix(CGContextRef, CGAffineTransform);
void CGContextShowGlyphsAtPoint(CGContextRef, CGFloat, CGFloat, const CGGlyph[], size_t);
void CGContextShowGlyphsWithAdvances(CGContextRef, const CGGlyph[], const CGSize[], size_t);
void CGContextStrokeEllipseInRect(CGContextRef, CGRect);
void CGContextStrokeLineSegments(CGContextRef, const CGPoint[], size_t);
void CGContextStrokePath(CGContextRef);
void CGContextStrokeRect(CGContextRef, CGRect);
void CGContextTranslateCTM(CGContextRef, CGFloat, CGFloat);
CGDataProviderRef CGDataProviderCreateWithData(void *, const void *, size_t, CGDataProviderReleaseDataCallback);
void CGDataProviderRelease(CGDataProviderRef);
CGRect CGDisplayBounds(CGDirectDisplayID);
CGError CGDisplayCapture(CGDirectDisplayID);
CFArrayRef CGDisplayCopyAllDisplayModes(CGDirectDisplayID, CFDictionaryRef);
CGDisplayModeRef CGDisplayCopyDisplayMode(CGDirectDisplayID);
CGDirectDisplayID CGDisplayMirrorsDisplay(CGDirectDisplayID);
CFStringRef CGDisplayModeCopyPixelEncoding(CGDisplayModeRef);
size_t CGDisplayModeGetHeight(CGDisplayModeRef);
double CGDisplayModeGetRefreshRate(CGDisplayModeRef);
size_t CGDisplayModeGetWidth(CGDisplayModeRef);
void CGDisplayModeRelease(CGDisplayModeRef);
CGDisplayModeRef CGDisplayModeRetain(CGDisplayModeRef);
CGError CGDisplayRegisterReconfigurationCallback(CGDisplayReconfigurationCallBack, void *);
CGError CGDisplayRelease(CGDirectDisplayID);
CGError CGDisplayRemoveReconfigurationCallback(CGDisplayReconfigurationCallBack, void *);
CGSize CGDisplayScreenSize(CGDirectDisplayID);
CGError CGEnableEventStateCombining(boolean_t);
CGEventRef CGEventCreate(CGEventSourceRef);
CGEventRef CGEventCreateKeyboardEvent(CGEventSourceRef, CGKeyCode, bool);
CGEventRef CGEventCreateMouseEvent(CGEventSourceRef, CGEventType, CGPoint, CGMouseButton);
CGEventRef CGEventCreateScrollWheelEvent(CGEventSourceRef, CGScrollEventUnit, uint32_t, int32_t, ...);
CGPoint CGEventGetLocation(CGEventRef);
void CGEventPost(CGEventTapLocation, CGEventRef);
void CGEventPostToPSN(void *, CGEventRef);
void CGEventSetIntegerValueField(CGEventRef, CGEventField, int64_t);
bool CGEventSourceButtonState(CGEventSourceStateID, CGMouseButton);
int CGFontGetAscent(CGFontRef);
int CGFontGetDescent(CGFontRef);
int CGFontGetLeading(CGFontRef);
int CGFontGetUnitsPerEm(CGFontRef);
void CGFontRelease(CGFontRef);
CGFunctionRef CGFunctionCreate(void *, size_t, const CGFloat *, size_t, const CGFloat *, const CGFunctionCallbacks *);
void CGFunctionRelease(CGFunctionRef);
CGError CGGetOnlineDisplayList(uint32_t, CGDirectDisplayID *, uint32_t *);
CGGradientRef CGGradientCreateWithColorComponents(CGColorSpaceRef, const CGFloat[], const CGFloat[], size_t);
void CGGradientRelease(CGGradientRef);
CGImageRef CGImageCreate(size_t, size_t, size_t, size_t, size_t, CGColorSpaceRef, CGBitmapInfo, CGDataProviderRef, const CGFloat[], bool, CGColorRenderingIntent);
CGImageRef CGImageCreateWithImageInRect(CGImageRef, CGRect);
void CGImageRelease(CGImageRef);
CGDirectDisplayID CGMainDisplayID(void);
void CGPathApply(CGPathRef, void *, CGPathApplierFunction);
void CGPathRelease(CGPathRef);
CGPatternRef CGPatternCreate(void *, CGRect, CGAffineTransform, CGFloat, CGFloat, CGPatternTiling, bool, const CGPatternCallbacks *);
void CGPatternRelease(CGPatternRef);
CGRect CGRectApplyAffineTransform(CGRect, CGAffineTransform);
bool CGRectContainsPoint(CGRect, CGPoint);
bool CGRectMakeWithDictionaryRepresentation(CFDictionaryRef, CGRect *);
CGError CGSetLocalEventsFilterDuringSuppressionState(CGEventFilterMask, CGEventSuppressionState);
CGError CGSetLocalEventsSuppressionInterval(CFTimeInterval);
CGShadingRef CGShadingCreateAxial(CGColorSpaceRef, CGPoint, CGPoint, CGFunctionRef, bool, bool);
void CGShadingRelease(CGShadingRef);
int32_t CGShieldingWindowLevel(void);
CGWindowLevel CGWindowLevelForKey(CGWindowLevelKey);
CFArrayRef CGWindowListCopyWindowInfo(CGWindowListOption, CGWindowID);
CGImageRef CGWindowListCreateImage(CGRect, CGWindowListOption, CGWindowID, CGWindowImageOption);
CGAffineTransform CGAffineTransformScale(CGAffineTransform, CGFloat, CGFloat);
CGBitmapInfo CGBitmapContextGetBitmapInfo(CGContextRef);
size_t CGDisplayModeGetPixelWidth(CGDisplayModeRef);
void CGEventSetFlags(CGEventRef, CGEventFlags);
CGEventSourceRef CGEventSourceCreate(CGEventSourceStateID);
CGEventFlags CGEventSourceFlagsState(CGEventSourceStateID);
void CGRestorePermanentDisplayConfiguration(void);
#ifdef __OBJC__
@protocol MTLDevice;
id<MTLDevice> CGDirectDisplayCopyCurrentMetalDevice(CGDirectDisplayID);
#endif

#endif
