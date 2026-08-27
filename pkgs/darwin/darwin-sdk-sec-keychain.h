#ifndef _SECURITY_SECKEYCHAIN_H_
#define _SECURITY_SECKEYCHAIN_H_
#include <Security/SecBase.h>
__BEGIN_DECLS
typedef struct __SecKeychain *SecKeychainRef;
typedef struct __SecKeychainItem *SecKeychainItemRef;
typedef struct SecKeychainAttributeList SecKeychainAttributeList;
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
__END_DECLS
#endif
