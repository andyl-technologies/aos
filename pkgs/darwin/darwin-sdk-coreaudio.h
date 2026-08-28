#ifndef _AOS_DARWIN_COREAUDIO_H_
#define _AOS_DARWIN_COREAUDIO_H_

#include <CoreAudio/CoreAudioTypes.h>

#if defined(__cplusplus)
extern "C" {
#endif

UInt64 AudioGetCurrentHostTime(void);
UInt64 AudioConvertHostTimeToNanos(UInt64 hostTime);
OSStatus AudioObjectGetPropertyDataSize(AudioObjectID, const AudioObjectPropertyAddress *, UInt32, const void *, UInt32 *);
OSStatus AudioObjectGetPropertyData(AudioObjectID, const AudioObjectPropertyAddress *, UInt32, const void *, UInt32 *, void *);
OSStatus AudioObjectSetPropertyData(AudioObjectID, const AudioObjectPropertyAddress *, UInt32, const void *, UInt32, const void *);
OSStatus AudioObjectAddPropertyListener(AudioObjectID, const AudioObjectPropertyAddress *, AudioObjectPropertyListenerProc, void *);
OSStatus AudioObjectRemovePropertyListener(AudioObjectID, const AudioObjectPropertyAddress *, AudioObjectPropertyListenerProc, void *);
OSStatus AudioDeviceCreateIOProcID(AudioObjectID, AudioDeviceIOProc, void *, AudioDeviceIOProcID *);
OSStatus AudioDeviceDestroyIOProcID(AudioObjectID, AudioDeviceIOProcID);
OSStatus AudioDeviceStart(AudioObjectID, AudioDeviceIOProcID);
OSStatus AudioDeviceStop(AudioObjectID, AudioDeviceIOProcID);

#if defined(__cplusplus)
}
#endif

#endif
