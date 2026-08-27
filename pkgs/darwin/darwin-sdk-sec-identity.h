#ifndef _SECURITY_SECIDENTITY_H_
#define _SECURITY_SECIDENTITY_H_
#include <Security/SecBase.h>
__BEGIN_DECLS
OSStatus SecIdentityCopyCertificate(SecIdentityRef identityRef, SecCertificateRef *certificateRef);
OSStatus SecIdentityCopyPrivateKey(SecIdentityRef identityRef, SecKeyRef *privateKeyRef);
__END_DECLS
#endif
