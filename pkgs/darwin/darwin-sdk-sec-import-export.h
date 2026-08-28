#ifndef _SECURITY_SECIMPORTEXPORT_H_
#define _SECURITY_SECIMPORTEXPORT_H_
#include <Security/SecBase.h>
#include <Security/SecAccess.h>
#include <Security/SecKeychain.h>
#include <Security/cssmtype.h>

__BEGIN_DECLS

typedef CF_ENUM(uint32_t, SecExternalFormat) {
  kSecFormatUnknown = 0,
  kSecFormatOpenSSL = 1,
  kSecFormatSSH = 2,
  kSecFormatBSAFE = 3,
  kSecFormatRawKey = 4,
  kSecFormatWrappedPKCS8 = 5,
  kSecFormatWrappedOpenSSL = 6,
  kSecFormatWrappedSSH = 7,
  kSecFormatWrappedLSH = 8,
  kSecFormatX509Cert = 9,
  kSecFormatPEMSequence = 10,
  kSecFormatPKCS7 = 11,
  kSecFormatPKCS12 = 12,
  kSecFormatNetscapeCertSequence = 13,
  kSecFormatSSHv2 = 14
};

typedef CF_ENUM(uint32_t, SecExternalItemType) {
  kSecItemTypeUnknown = 0,
  kSecItemTypePrivateKey = 1,
  kSecItemTypePublicKey = 2,
  kSecItemTypeSessionKey = 3,
  kSecItemTypeCertificate = 4,
  kSecItemTypeAggregate = 5
};

typedef CF_OPTIONS(uint32_t, SecItemImportExportFlags) {
  kSecItemPemArmour = 0x00000001
};

typedef CF_OPTIONS(uint32_t, SecKeyImportExportFlags) {
  kSecKeyImportOnlyOne = 0x00000001,
  kSecKeySecurePassphrase = 0x00000002,
  kSecKeyNoAccessControl = 0x00000004
};

#define SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION 0

typedef struct {
  uint32_t version;
  SecKeyImportExportFlags flags;
  CFTypeRef __nullable passphrase;
  CFStringRef __nullable alertTitle;
  CFStringRef __nullable alertPrompt;
  SecAccessRef __nullable accessRef;
  CSSM_KEYUSE keyUsage;
  CSSM_KEYATTR_FLAGS keyAttributes;
} SecKeyImportExportParameters;

typedef struct {
  uint32_t version;
  SecKeyImportExportFlags flags;
  CFTypeRef __nullable passphrase;
  CFStringRef __nullable alertTitle;
  CFStringRef __nullable alertPrompt;
  SecAccessRef __nullable accessRef;
  CFArrayRef __nullable keyUsage;
  CFArrayRef __nullable keyAttributes;
} SecItemImportExportKeyParameters;

extern const CFStringRef kSecImportItemIdentity;

OSStatus SecKeychainItemExport(
  CFTypeRef keychainItemOrArray,
  SecExternalFormat outputFormat,
  SecItemImportExportFlags flags,
  const SecKeyImportExportParameters * __nullable keyParams,
  CFDataRef * __nonnull exportedData
);

OSStatus SecKeychainItemImport(
  CFDataRef importedData,
  CFStringRef __nullable fileNameOrExtension,
  SecExternalFormat * __nullable inputFormat,
  SecExternalItemType * __nullable itemType,
  SecItemImportExportFlags flags,
  const SecKeyImportExportParameters * __nullable keyParams,
  SecKeychainRef __nullable importKeychain,
  CFArrayRef * __nullable outItems
);

OSStatus SecItemImport(
  CFDataRef importedData,
  CFStringRef __nullable fileNameOrExtension,
  SecExternalFormat * __nullable inputFormat,
  SecExternalItemType * __nullable itemType,
  SecItemImportExportFlags flags,
  const SecItemImportExportKeyParameters * __nullable keyParams,
  SecKeychainRef __nullable importKeychain,
  CFArrayRef * __nullable outItems
);

__END_DECLS
#endif
