#ifndef _AOS_DARWIN_AUDIOTOOLBOX_H_
#define _AOS_DARWIN_AUDIOTOOLBOX_H_

#include <AudioUnit/AudioUnit.h>

#if defined(__cplusplus)
extern "C" {
#endif

OSStatus AudioConverterNew(const AudioStreamBasicDescription *, const AudioStreamBasicDescription *, AudioConverterRef *);
OSStatus AudioConverterDispose(AudioConverterRef);
OSStatus AudioConverterReset(AudioConverterRef);
OSStatus AudioConverterGetProperty(AudioConverterRef, AudioConverterPropertyID, UInt32 *, void *);
OSStatus AudioConverterFillComplexBuffer(AudioConverterRef, AudioConverterComplexInputDataProc, void *, UInt32 *, AudioBufferList *, AudioStreamPacketDescription *);

#if defined(__cplusplus)
}
#endif

#endif
