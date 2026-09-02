#ifndef _AOS_CARBON_AE_H_
#define _AOS_CARBON_AE_H_

typedef ResType DescType;
typedef OSType AEKeyword;
typedef OSType AEEventClass;
typedef OSType AEEventID;
typedef Handle AEDataStorage;
typedef SInt64 LongDateTime;

typedef struct AEDesc {
  DescType descriptorType;
  AEDataStorage dataHandle;
} AEDesc;

enum {
  typeAEList = 'list',
  typeAERecord = 'reco',
  typeNull = 'null',
  typeTrue = 'true',
  typeFalse = 'fals',
  typeBoolean = 'bool',
  typeSInt16 = 'shor',
  typeSInt32 = 'long',
  typeUInt32 = 'magn',
  typeSInt64 = 'comp',
  typeIEEE32BitFloatingPoint = 'sing',
  typeIEEE64BitFloatingPoint = 'doub',
  type128BitFloatingPoint = 'ldbl',
  typeUnicodeText = 'utxt',
  typeText = 'TEXT',
  typeUTF8Text = 'utf8',
  typeCString = 'cstr',
  typeChar = 'TEXT',
  typeTIFF = 'TIFF',
  typeJPEG = 'JPEG',
  typeGIF = 'GIFf',
  typePict = 'PICT',
  typeIconFamily = 'icns',
  typeIconAndMask = 'ICN#',
  typeVersion = 'vers',
  typeLongDateTime = 'ldt ',
  typeType = 'type',
  typeKernelProcessID = 'kpid',
  keyASUserRecordFields = 'usrf',
  keyASSubroutineName = 'snam',
  keyDirectObject = '----',
  keyAESearchText = 'stxt',
  kASAppleScriptSuite = 'ascr',
  kASSubroutineEvent = 'psbr',
  kInternetEventClass = 'GURL',
  kAEGetURL = 'GURL'
};

enum {
  kAutoGenerateReturnID = -1,
  kAnyTransactionID = 0
};

Size AEGetDescDataSize(const AEDesc *theAEDesc);
OSErr AEGetDescData(const AEDesc *theAEDesc, void *dataPtr, Size maximumSize);

#endif
