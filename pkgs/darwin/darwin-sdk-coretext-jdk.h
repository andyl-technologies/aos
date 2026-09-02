#ifndef _AOS_CORETEXT_H_
#define _AOS_CORETEXT_H_

/* Minimal public CoreText ABI exercised by IcedTea JDK 8. */
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <MacTypes.h>
#include <stdint.h>

typedef const struct __CTFont *CTFontRef;
typedef const struct __CTFontDescriptor *CTFontDescriptorRef;
typedef const struct __CTTypesetter *CTTypesetterRef;
typedef const struct __CTLine *CTLineRef;
typedef const struct __CTRun *CTRunRef;
typedef uint32_t CTFontUIFontType;
typedef uint32_t CTFontOrientation;
typedef FourCharCode CTFontTableTag;
typedef uint32_t CTFontTableOptions;
typedef uint32_t CTFontSymbolicTraits;
typedef uint32_t CTFontManagerScope;
typedef uint32_t CTRunStatus;

enum {
  kCTFontUIFontSystem = 2,
  kCTFontUIFontEmphasizedSystem = 3,
  kCTFontUIFontUserFixedPitch = 1,
  kCTFontOrientationDefault = 0,
  kCTFontDefaultOrientation = kCTFontOrientationDefault,
  kCTFontTableOptionNoOptions = 0,
  kCTFontManagerScopeProcess = 1,
  kCTRunStatusNoStatus = 0,
  kCTRunStatusRightToLeft = 1U << 0,
  kCTRunStatusNonMonotonic = 1U << 1,
  kCTRunStatusHasNonIdentityMatrix = 1U << 2
};

CF_EXTERN_C_BEGIN

extern const CFStringRef kCTFontCascadeListAttribute;
extern const CFStringRef kCTFontURLAttribute;
extern const CFStringRef kCTFontFeatureTypeIdentifierKey;
extern const CFStringRef kCTFontFeatureSelectorIdentifierKey;
extern const CFStringRef kCTFontFeatureSettingsAttribute;
extern const CFStringRef kCTVerticalFormsAttributeName;
extern const CFStringRef kCTLanguageAttributeName;
extern const CFStringRef kCTFontAttributeName;
extern const CFStringRef kCTKernAttributeName;
extern const CFStringRef kCTTypesetterOptionForcedEmbeddingLevel;
extern const CFStringRef kCTFontPostScriptNameKey;
extern const CFStringRef kCTFontFamilyNameAttribute;
extern const CFStringRef kCTFontNameAttribute;
extern const CFStringRef kCTForegroundColorFromContextAttributeName;

CGFontRef CTFontCopyGraphicsFont(
  CTFontRef font,
  CTFontDescriptorRef *attributes
);
CTFontRef CTFontCreateUIFontForLanguage(
  CTFontUIFontType uiType,
  CGFloat size,
  CFStringRef language
);
CTFontDescriptorRef CTFontCopyFontDescriptor(CTFontRef font);
CFTypeRef CTFontDescriptorCopyAttribute(
  CTFontDescriptorRef descriptor,
  CFStringRef attribute
);
bool CTFontGetGlyphsForCharacters(
  CTFontRef font,
  const UniChar characters[],
  CGGlyph glyphs[],
  CFIndex count
);
double CTFontGetAdvancesForGlyphs(
  CTFontRef font,
  CTFontOrientation orientation,
  const CGGlyph glyphs[],
  CGSize advances[],
  CFIndex count
);
CTTypesetterRef CTTypesetterCreateWithAttributedStringAndOptions(
  CFAttributedStringRef string,
  CFDictionaryRef options
);
CTTypesetterRef CTTypesetterCreateWithAttributedString(
  CFAttributedStringRef string
);
CTLineRef CTTypesetterCreateLine(CTTypesetterRef typesetter, CFRange stringRange);
void CTLineDraw(CTLineRef line, CGContextRef context);
CFArrayRef CTFontCopyAvailableTables(CTFontRef font, CTFontTableOptions options);
CFDataRef CTFontCopyTable(
  CTFontRef font,
  CTFontTableTag table,
  CTFontTableOptions options
);
CFStringRef CTFontCopyFullName(CTFontRef font);
CFArrayRef CTFontCopyDefaultCascadeListForLanguages(
  CTFontRef font,
  CFArrayRef languagePrefList
);
CGPathRef CTFontCreatePathForGlyph(
  CTFontRef font,
  CGGlyph glyph,
  const CGAffineTransform *matrix
);
CTFontRef CTFontCreateCopyWithSymbolicTraits(
  CTFontRef font,
  CGFloat size,
  const CGAffineTransform *matrix,
  CTFontSymbolicTraits value,
  CTFontSymbolicTraits mask
);
void CTFontDrawGlyphs(
  CTFontRef font,
  const CGGlyph glyphs[],
  const CGPoint positions[],
  size_t count,
  CGContextRef context
);
bool CTFontManagerRegisterFontsForURL(
  CFURLRef fontURL,
  CTFontManagerScope scope,
  CFErrorRef *error
);
CGFloat CTFontGetSize(CTFontRef font);
CTFontDescriptorRef CTFontDescriptorCreateWithNameAndSize(
  CFStringRef name,
  CGFloat size
);
CTFontDescriptorRef CTFontDescriptorCreateWithAttributes(CFDictionaryRef attributes);
CFStringRef CTFontCopyPostScriptName(CTFontRef font);
CTFontRef CTFontCreateWithGraphicsFont(
  CGFontRef graphicsFont,
  CGFloat size,
  const CGAffineTransform *matrix,
  CTFontDescriptorRef attributes
);
uint32_t CTGetCoreTextVersion(void);
CFTypeRef CTFontCopyAttribute(CTFontRef font, CFStringRef attribute);
CTFontRef CTFontCreateCopyWithAttributes(
  CTFontRef font,
  CGFloat size,
  const CGAffineTransform *matrix,
  CTFontDescriptorRef attributes
);
CFStringRef CTFontCopyName(CTFontRef font, CFStringRef nameKey);
CFArrayRef CTLineGetGlyphRuns(CTLineRef line);
double CTLineGetTrailingWhitespaceWidth(CTLineRef line);
CFIndex CTRunGetGlyphCount(CTRunRef run);
CFDictionaryRef CTRunGetAttributes(CTRunRef run);
CTRunStatus CTRunGetStatus(CTRunRef run);
const CGGlyph *CTRunGetGlyphsPtr(CTRunRef run);
void CTRunGetGlyphs(CTRunRef run, CFRange range, CGGlyph buffer[]);
const CGPoint *CTRunGetPositionsPtr(CTRunRef run);
void CTRunGetPositions(CTRunRef run, CFRange range, CGPoint buffer[]);
const CFIndex *CTRunGetStringIndicesPtr(CTRunRef run);
void CTRunGetStringIndices(CTRunRef run, CFRange range, CFIndex buffer[]);
CFRange CTRunGetStringRange(CTRunRef run);
double CTRunGetTypographicBounds(
  CTRunRef run,
  CFRange range,
  CGFloat *ascent,
  CGFloat *descent,
  CGFloat *leading
);

CF_EXTERN_C_END

enum {
  kLigaturesType = 1,
  kLetterCaseType = 3,
  kVerticalSubstitutionType = 4,
  kNumberSpacingType = 6,
  kVerticalPositionType = 10,
  kFractionsType = 11,
  kTypographicExtrasType = 14,
  kMathematicalExtrasType = 15,
  kStyleOptionsType = 19,
  kCharacterShapeType = 20,
  kNumberCaseType = 21,
  kTextSpacingType = 22,
  kTransliterationType = 23,
  kRubyKanaType = 28,
  kItalicCJKRomanType = 32,
  kCommonLigaturesOnSelector = 2,
  kCommonLigaturesOffSelector = 3,
  kRareLigaturesOnSelector = 4,
  kRareLigaturesOffSelector = 5,
  kSubstituteVerticalFormsOnSelector = 0,
  kSubstituteVerticalFormsOffSelector = 1,
  kMonospacedNumbersSelector = 0,
  kProportionalNumbersSelector = 1,
  kNormalPositionSelector = 0,
  kSuperiorsSelector = 1,
  kInferiorsSelector = 2,
  kOrdinalsSelector = 3,
  kNoFractionsSelector = 0,
  kDiagonalFractionsSelector = 2,
  kSlashedZeroOnSelector = 4,
  kSlashedZeroOffSelector = 5,
  kNoStyleOptionsSelector = 0,
  kTitlingCapsSelector = 4,
  kTraditionalCharactersSelector = 0,
  kSimplifiedCharactersSelector = 1,
  kJIS1978CharactersSelector = 2,
  kJIS1983CharactersSelector = 3,
  kJIS1990CharactersSelector = 4,
  kExpertCharactersSelector = 10,
  kLowerCaseNumbersSelector = 0,
  kUpperCaseNumbersSelector = 1,
  kProportionalTextSelector = 0,
  kMonospacedTextSelector = 1,
  kHalfWidthTextSelector = 2,
  kNoTransliterationSelector = 0,
  kHanjaToHangulSelector = 1,
  kRubyKanaOnSelector = 2,
  kRubyKanaOffSelector = 3,
  kCJKItalicRomanOnSelector = 2,
  kCJKItalicRomanOffSelector = 3
};

#endif
