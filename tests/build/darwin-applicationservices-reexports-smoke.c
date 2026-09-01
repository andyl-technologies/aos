/* Prove the public ApplicationServices umbrella carries CoreText and CarbonCore. */

#include <ApplicationServices/ApplicationServices.h>

#define AOS_FUNCTION(name) ((const void *)&name)
const void *aos_application_services_functions[] = {
  AOS_FUNCTION(CTFontCopyAvailableTables),
  AOS_FUNCTION(CTFontCopyDefaultCascadeListForLanguages),
  AOS_FUNCTION(CTFontCopyFontDescriptor),
  AOS_FUNCTION(CTFontCopyFullName),
  AOS_FUNCTION(CTFontCopyGraphicsFont),
  AOS_FUNCTION(CTFontCopyTable),
  AOS_FUNCTION(CTFontCreateCopyWithSymbolicTraits),
  AOS_FUNCTION(CTFontCreatePathForGlyph),
  AOS_FUNCTION(CTFontCreateUIFontForLanguage),
  AOS_FUNCTION(CTFontDescriptorCopyAttribute),
  AOS_FUNCTION(CTFontDrawGlyphs),
  AOS_FUNCTION(CTFontGetAdvancesForGlyphs),
  AOS_FUNCTION(CTFontGetGlyphsForCharacters),
  AOS_FUNCTION(CTFontManagerRegisterFontsForURL),
  AOS_FUNCTION(CTLineDraw),
  AOS_FUNCTION(CTTypesetterCreateLine),
  AOS_FUNCTION(CTTypesetterCreateWithAttributedString),
  AOS_FUNCTION(FSFindFolder),
  AOS_FUNCTION(FSRefMakePath),
};
#undef AOS_FUNCTION

const void *aos_application_services_data[] = {
  &kCTFontFamilyNameAttribute,
  &kCTFontNameAttribute,
  &kCTForegroundColorFromContextAttributeName,
};

int main(void) {
  return aos_application_services_functions[0] == NULL ||
    aos_application_services_data[0] == NULL;
}
