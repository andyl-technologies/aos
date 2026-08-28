#ifndef _AOS_CORE_SERVICES_JDK_H_
#define _AOS_CORE_SERVICES_JDK_H_

CF_EXTERN_C_BEGIN
typedef SInt16 FSVolumeRefNum;
typedef struct FSRef FSRef;

CFStringRef CSCopyMachineName(void);
extern const CFStringRef kUTTypeJPEG;
OSStatus FSFindFolder(
  FSVolumeRefNum vRefNum,
  OSType folderType,
  Boolean createFolder,
  FSRef *foundRef
);
OSStatus FSRefMakePath(const FSRef *ref, UInt8 *path, UInt32 maxPathSize);
CF_EXTERN_C_END

#endif
