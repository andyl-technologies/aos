#ifndef _SECURITY_SECIDENTITYSEARCH_H_
#define _SECURITY_SECIDENTITYSEARCH_H_
#include <Security/SecBase.h>
#include <Security/cssmtype.h>
typedef struct OpaqueSecIdentitySearchRef *SecIdentitySearchRef;
__BEGIN_DECLS
OSStatus SecIdentitySearchCreate(
  CFTypeRef keychainOrArray,
  CSSM_KEYUSE keyUsage,
  SecIdentitySearchRef *searchRef
);
OSStatus SecIdentitySearchCopyNext(
  SecIdentitySearchRef searchRef,
  SecIdentityRef *identity
);
__END_DECLS
#endif
