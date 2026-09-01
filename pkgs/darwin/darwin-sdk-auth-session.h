#if !defined(__AuthSession__)
#define __AuthSession__ 1
#include <Security/SecBase.h>
__BEGIN_DECLS
typedef UInt32 SecuritySessionId;
CF_ENUM(SecuritySessionId) {
  callerSecuritySession = ((SecuritySessionId)-1)
};
typedef CF_OPTIONS(UInt32, SessionAttributeBits) {
  sessionHasGraphicAccess = 0x0010
};
OSStatus SessionGetInfo(
  SecuritySessionId session,
  SecuritySessionId * __nullable sessionId,
  SessionAttributeBits * __nullable attributes
);
__END_DECLS
#endif
