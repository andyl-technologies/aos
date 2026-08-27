#ifndef _AOS_DARWIN_COREAUDIO_H_
#define _AOS_DARWIN_COREAUDIO_H_

#include <CoreAudio/CoreAudioTypes.h>

UInt64 AudioGetCurrentHostTime(void);
UInt64 AudioConvertHostTimeToNanos(UInt64 hostTime);
OSStatus AudioObjectGetPropertyDataSize(AudioObjectID, const AudioObjectPropertyAddress *, UInt32, const void *, UInt32 *);
OSStatus AudioObjectGetPropertyData(AudioObjectID, const AudioObjectPropertyAddress *, UInt32, const void *, UInt32 *, void *);
OSStatus AudioObjectSetPropertyData(AudioObjectID, const AudioObjectPropertyAddress *, UInt32, const void *, UInt32, const void *);
OSStatus AudioObjectAddPropertyListener(AudioObjectID, const AudioObjectPropertyAddress *, AudioObjectPropertyListenerProc, void *);
OSStatus AudioObjectRemovePropertyListener(AudioObjectID, const AudioObjectPropertyAddress *, AudioObjectPropertyListenerProc, void *);

#endif
