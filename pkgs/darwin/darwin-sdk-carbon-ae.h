#ifndef _AOS_CARBON_AE_H_
#define _AOS_CARBON_AE_H_

typedef ResType DescType;
typedef OSType AEKeyword;
typedef OSType AEEventClass;
typedef OSType AEEventID;
typedef Handle AEDataStorage;

typedef struct AEDesc {
  DescType descriptorType;
  AEDataStorage dataHandle;
} AEDesc;

enum {
  kInternetEventClass = 'GURL',
  kAEGetURL = 'GURL'
};

#endif
