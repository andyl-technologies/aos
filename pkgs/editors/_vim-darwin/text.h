/* Public CoreServices encoding ABI used by Vim's macOS filename conversion. */
#ifndef AOS_VIM_DARWIN_TEXT_H
#define AOS_VIM_DARWIN_TEXT_H

#include <CoreServices/CoreServices.h>

typedef UInt32 TextEncoding;
typedef struct OpaqueTECObjectRef *TECObjectRef;
typedef unsigned char *TextPtr;
typedef const unsigned char *ConstTextPtr;
typedef struct OpaqueLocaleRef *LocaleRef;
typedef UInt32 LocalePartMask;

enum {
    kTextEncodingUnicodeDefault = 0x100,
    kTextEncodingDefaultVariant = 0,
    kUnicode16BitFormat = 0,
    kUnicodeUTF8Format = 2,
    kUnicodeCanonicalCompVariant = 3,
    kUnicodeHFSPlusCompVariant = 9,
    kLocaleLanguageMask = 1U << 0,
    kLocaleLanguageVariantMask = 1U << 1,
    kLocaleRegionMask = 1U << 4,
    kLocaleRegionVariantMask = 1U << 5
};

TextEncoding CreateTextEncoding(UInt32 base, UInt32 variant, UInt32 format);
OSStatus TECCreateConverter(TECObjectRef *converter, TextEncoding input, TextEncoding output);
OSStatus TECDisposeConverter(TECObjectRef converter);
OSStatus TECConvertText(TECObjectRef converter, ConstTextPtr input, ByteCount inputLength,
                        ByteCount *inputRead, TextPtr output, ByteCount outputLength,
                        ByteCount *outputWritten);
OSStatus TECFlushText(TECObjectRef converter, TextPtr output, ByteCount outputLength,
                      ByteCount *outputWritten);

OSStatus LocaleRefGetPartString(LocaleRef locale, LocalePartMask parts,
                                ByteCount maximumLength, char *output);

#endif
