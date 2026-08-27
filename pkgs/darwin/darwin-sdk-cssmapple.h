#ifndef _CSSMAPPLE_H_
#define _CSSMAPPLE_H_
#include <Security/cssmtype.h>
typedef uint32_t CSSM_TP_APPLE_CERT_STATUS;
typedef struct {
  uint32_t DLHandle;
  uint32_t DBHandle;
} CSSM_DL_DB_HANDLE;
typedef struct cssm_db_unique_record *CSSM_DB_UNIQUE_RECORD_PTR;
typedef struct {
  CSSM_TP_APPLE_CERT_STATUS StatusBits;
  uint32_t NumStatusCodes;
  CSSM_RETURN *StatusCodes;
  uint32_t Index;
  CSSM_DL_DB_HANDLE DlDbHandle;
  CSSM_DB_UNIQUE_RECORD_PTR UniqueRecord;
} CSSM_TP_APPLE_EVIDENCE_INFO;
__BEGIN_DECLS
void cssmPerror(const char *how, CSSM_RETURN error);
__END_DECLS
#endif
