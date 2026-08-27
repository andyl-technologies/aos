#ifndef _CSSMTYPE_H
#define _CSSMTYPE_H 1
#include <stdint.h>

typedef int32_t CSSM_RETURN;
typedef uint32_t CSSM_CERT_TYPE;
typedef struct {
  uint32_t Length;
  uint8_t *Data;
} CSSM_DATA;
typedef CSSM_DATA CSSM_OID;

enum {
  CSSM_CERT_X_509v3 = 0x03
};

typedef uint32_t CSSM_KEYATTR_FLAGS;
enum {
  CSSM_KEYATTR_RETURN_DEFAULT = 0x00000000
};

typedef uint32_t CSSM_KEYUSE;
enum {
  CSSM_KEYUSE_ANY = 0x80000000
};

#endif
