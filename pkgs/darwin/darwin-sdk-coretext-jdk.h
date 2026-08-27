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
typedef uint32_t CTFontUIFontType;
typedef uint32_t CTFontOrientation;
typedef FourCharCode CTFontTableTag;
typedef uint32_t CTFontTableOptions;
typedef uint32_t CTFontSymbolicTraits;
typedef uint32_t CTFontManagerScope;

enum {
  kCTFontUIFontSystem = 2,
  kCTFontUIFontEmphasizedSystem = 3,
  kCTFontOrientationDefault = 0,
  kCTFontDefaultOrientation = kCTFontOrientationDefault,
  kCTFontTableOptionNoOptions = 0,
  kCTFontManagerScopeProcess = 1
};

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

#endif
