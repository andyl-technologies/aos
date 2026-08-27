#ifndef _CSSMTYPE_H
#define _CSSMTYPE_H 1
#include <stdint.h>

typedef uint32_t CSSM_KEYATTR_FLAGS;
enum {
  CSSM_KEYATTR_RETURN_DEFAULT = 0x00000000
};

typedef uint32_t CSSM_KEYUSE;
enum {
  CSSM_KEYUSE_ANY = 0x80000000
};

#endif
