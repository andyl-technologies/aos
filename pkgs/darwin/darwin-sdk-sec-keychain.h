#ifndef _SECURITY_SECKEYCHAIN_H_
#define _SECURITY_SECKEYCHAIN_H_
#include <Security/SecBase.h>
__BEGIN_DECLS
typedef struct __SecKeychain *SecKeychainRef;
typedef struct __SecKeychainItem *SecKeychainItemRef;
typedef struct __SecKeychainSearch *SecKeychainSearchRef;
typedef FourCharCode SecItemClass;
enum {
  kSecCertificateItemClass = 'cert',
  kSecModDateItemAttr = 'mdat',
  kSecLabelItemAttr = 'labl'
};
OSStatus SecKeychainOpen(const char *pathName, SecKeychainRef *keychain);
OSStatus SecKeychainCopyDefault(SecKeychainRef *keychain);
OSStatus SecKeychainAddGenericPassword(
  SecKeychainRef keychain,
  UInt32 serviceNameLength,
  const char *serviceName,
  UInt32 accountNameLength,
  const char *accountName,
  UInt32 passwordLength,
  const void *passwordData,
  SecKeychainItemRef *itemRef
);
OSStatus SecKeychainFindGenericPassword(
  CFTypeRef keychainOrArray,
  UInt32 serviceNameLength,
  const char *serviceName,
  UInt32 accountNameLength,
  const char *accountName,
  UInt32 *passwordLength,
  void **passwordData,
  SecKeychainItemRef *itemRef
);
OSStatus SecKeychainItemModifyAttributesAndData(
  SecKeychainItemRef itemRef,
  const SecKeychainAttributeList *attributeList,
  UInt32 length,
  const void *data
);
OSStatus SecKeychainItemDelete(SecKeychainItemRef itemRef);
OSStatus SecKeychainItemFreeContent(SecKeychainAttributeList *attributeList, void *data);
OSStatus SecKeychainItemCopyContent(
  SecKeychainItemRef itemRef,
  SecItemClass *itemClass,
  SecKeychainAttributeList *attributeList,
  UInt32 *length,
  void **outData
);
OSStatus SecKeychainItemModifyContent(
  SecKeychainItemRef itemRef,
  const SecKeychainAttributeList *attributeList,
  UInt32 length,
  const void *data
);
OSStatus SecKeychainSearchCreateFromAttributes(
  SecKeychainRef keychain,
  SecItemClass itemClass,
  const SecKeychainAttributeList *attributeList,
  SecKeychainSearchRef *searchRef
);
OSStatus SecKeychainSearchCopyNext(
  SecKeychainSearchRef searchRef,
  SecKeychainItemRef *itemRef
);
__END_DECLS
#endif
