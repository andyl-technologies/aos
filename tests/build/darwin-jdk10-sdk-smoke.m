#import <AppKit/NSOpenGL.h>
#import <Foundation/Foundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <CoreText/CoreText.h>

_Static_assert(NSOpenGLPFAScreenMask == 84, "NSOpenGL screen-mask attribute");
_Static_assert(kCTFontUIFontUserFixedPitch == 1, "fixed-pitch UI font");
_Static_assert(kCTRunStatusNoStatus == 0, "CoreText run status");
_Static_assert(kCTRunStatusRightToLeft == 1U << 0, "right-to-left run");
_Static_assert(kCTRunStatusNonMonotonic == 1U << 1, "non-monotonic run");
_Static_assert(kCTRunStatusHasNonIdentityMatrix == 1U << 2, "transformed run");
_Static_assert(kLigaturesType == 1, "ligature feature type");
_Static_assert(kItalicCJKRomanType == 32, "CJK italic feature type");
_Static_assert(kCommonLigaturesOnSelector == 2, "common ligatures selector");
_Static_assert(kExpertCharactersSelector == 10, "expert character selector");
_Static_assert(kCJKItalicRomanOffSelector == 3, "CJK italic selector");

#define AOS_FUNCTION(name) ((const void *)&name)
static const void *aos_jdk10_functions[] = {
  AOS_FUNCTION(NSLog),
  AOS_FUNCTION(NSSearchPathForDirectoriesInDomains),
  AOS_FUNCTION(CFStringCreateWithFileSystemRepresentation),
  AOS_FUNCTION(CFStringGetFileSystemRepresentation),
  AOS_FUNCTION(CFStringGetMaximumSizeOfFileSystemRepresentation),
  AOS_FUNCTION(CGFontCreateWithDataProvider),
  AOS_FUNCTION(CGFontRetain),
  AOS_FUNCTION(CGFontCopyPostScriptName),
  AOS_FUNCTION(CGFontCopyTableForTag),
  AOS_FUNCTION(CGDisplayIDToOpenGLDisplayMask),
  AOS_FUNCTION(CTFontGetSize),
  AOS_FUNCTION(CTFontDescriptorCreateWithNameAndSize),
  AOS_FUNCTION(CTFontDescriptorCreateWithAttributes),
  AOS_FUNCTION(CTFontCopyPostScriptName),
  AOS_FUNCTION(CTFontCreateWithGraphicsFont),
  AOS_FUNCTION(CTGetCoreTextVersion),
  AOS_FUNCTION(CTFontCopyAttribute),
  AOS_FUNCTION(CTFontCreateCopyWithAttributes),
  AOS_FUNCTION(CTFontCopyName),
  AOS_FUNCTION(CTLineGetGlyphRuns),
  AOS_FUNCTION(CTLineGetTrailingWhitespaceWidth),
  AOS_FUNCTION(CTRunGetGlyphCount),
  AOS_FUNCTION(CTRunGetAttributes),
  AOS_FUNCTION(CTRunGetStatus),
  AOS_FUNCTION(CTRunGetGlyphsPtr),
  AOS_FUNCTION(CTRunGetGlyphs),
  AOS_FUNCTION(CTRunGetPositionsPtr),
  AOS_FUNCTION(CTRunGetPositions),
  AOS_FUNCTION(CTRunGetStringIndicesPtr),
  AOS_FUNCTION(CTRunGetStringIndices),
  AOS_FUNCTION(CTRunGetStringRange),
  AOS_FUNCTION(CTRunGetTypographicBounds),
};
#undef AOS_FUNCTION

static const void *aos_jdk10_data[] = {
  &kCTFontCascadeListAttribute,
  &kCTFontURLAttribute,
  &kCTFontFeatureTypeIdentifierKey,
  &kCTFontFeatureSelectorIdentifierKey,
  &kCTFontFeatureSettingsAttribute,
  &kCTVerticalFormsAttributeName,
  &kCTLanguageAttributeName,
  &kCTFontAttributeName,
  &kCTKernAttributeName,
  &kCTTypesetterOptionForcedEmbeddingLevel,
  &kCTFontPostScriptNameKey,
};

int main(void) {
  return aos_jdk10_functions[0] == NULL || aos_jdk10_data[0] == NULL;
}
