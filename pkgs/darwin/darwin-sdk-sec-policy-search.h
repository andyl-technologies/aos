#ifndef _SECURITY_SECPOLICYSEARCH_H_
#define _SECURITY_SECPOLICYSEARCH_H_
#include <Security/SecBase.h>
#include <Security/cssmtype.h>
typedef struct OpaquePolicySearchRef *SecPolicySearchRef;
__BEGIN_DECLS
OSStatus SecPolicySearchCreate(
  CSSM_CERT_TYPE certType,
  const CSSM_OID *policyOID,
  const CSSM_DATA *value,
  SecPolicySearchRef *searchRef
);
OSStatus SecPolicySearchCopyNext(SecPolicySearchRef searchRef, SecPolicyRef *policyRef);
__END_DECLS
#endif
