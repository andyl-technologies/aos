#ifndef _SECURITY_SECKEY_H_
#define _SECURITY_SECKEY_H_
#include <Security/SecBase.h>
__BEGIN_DECLS

CFDataRef __nullable SecKeyCopyExternalRepresentation(
  SecKeyRef key,
  CFErrorRef * __nullable error
);

__END_DECLS
#endif
