/* Prove Apple's public audio C APIs retain C linkage for C++ consumers. */

#include <AudioToolbox/AudioToolbox.h>
#include <AudioUnit/AudioUnit.h>
#include <CoreAudio/CoreAudio.h>

#define AOS_FUNCTION(name) ((const void *)&name)
const void *aos_audio_c_functions[] = {
  AOS_FUNCTION(AudioComponentFindNext),
  AOS_FUNCTION(AudioComponentInstanceDispose),
  AOS_FUNCTION(AudioComponentInstanceNew),
  AOS_FUNCTION(AudioConverterDispose),
  AOS_FUNCTION(AudioConverterFillComplexBuffer),
  AOS_FUNCTION(AudioConverterGetProperty),
  AOS_FUNCTION(AudioConverterNew),
  AOS_FUNCTION(AudioConverterReset),
  AOS_FUNCTION(AudioObjectAddPropertyListener),
  AOS_FUNCTION(AudioObjectGetPropertyData),
  AOS_FUNCTION(AudioObjectGetPropertyDataSize),
  AOS_FUNCTION(AudioObjectRemovePropertyListener),
  AOS_FUNCTION(AudioObjectSetPropertyData),
  AOS_FUNCTION(AudioOutputUnitStart),
  AOS_FUNCTION(AudioOutputUnitStop),
  AOS_FUNCTION(AudioUnitGetProperty),
  AOS_FUNCTION(AudioUnitInitialize),
  AOS_FUNCTION(AudioUnitRender),
  AOS_FUNCTION(AudioUnitSetProperty),
};
#undef AOS_FUNCTION

int main() {
  return aos_audio_c_functions[0] == nullptr;
}
