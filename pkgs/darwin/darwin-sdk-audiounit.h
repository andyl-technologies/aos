#ifndef _AOS_DARWIN_AUDIOUNIT_H_
#define _AOS_DARWIN_AUDIOUNIT_H_

#include <CoreAudio/CoreAudioTypes.h>

#if defined(__cplusplus)
extern "C" {
#endif

AudioComponent AudioComponentFindNext(AudioComponent, const AudioComponentDescription *);
OSStatus AudioComponentInstanceNew(AudioComponent, AudioComponentInstance *);
OSStatus AudioComponentInstanceDispose(AudioComponentInstance);
OSStatus AudioUnitInitialize(AudioUnit);
OSStatus AudioUnitGetProperty(AudioUnit, AudioUnitPropertyID, AudioUnitScope, AudioUnitElement, void *, UInt32 *);
OSStatus AudioUnitSetProperty(AudioUnit, AudioUnitPropertyID, AudioUnitScope, AudioUnitElement, const void *, UInt32);
OSStatus AudioUnitRender(AudioUnit, AudioUnitRenderActionFlags *, const AudioTimeStamp *, UInt32, UInt32, AudioBufferList *);
OSStatus AudioOutputUnitStart(AudioUnit);
OSStatus AudioOutputUnitStop(AudioUnit);

#if defined(__cplusplus)
}
#endif

#endif
