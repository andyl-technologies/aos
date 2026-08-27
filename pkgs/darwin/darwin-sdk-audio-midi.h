#ifndef _AOS_DARWIN_AUDIO_MIDI_H_
#define _AOS_DARWIN_AUDIO_MIDI_H_

#include <CoreFoundation/CoreFoundation.h>
#include <MacTypes.h>

typedef unsigned long ByteCount;
typedef unsigned long ItemCount;
typedef UInt32 AudioObjectID;
typedef UInt32 AudioClassID;
typedef AudioObjectID AudioDeviceID;
typedef AudioObjectID AudioStreamID;
typedef UInt32 AudioObjectPropertySelector;
typedef UInt32 AudioObjectPropertyScope;
typedef UInt32 AudioObjectPropertyElement;
typedef UInt32 AudioUnitPropertyID;
typedef UInt32 AudioUnitScope;
typedef UInt32 AudioUnitElement;
typedef UInt32 AudioUnitRenderActionFlags;
typedef UInt32 AudioTimeStampFlags;
typedef UInt32 SMPTETimeType;
typedef UInt32 SMPTETimeFlags;
typedef UInt32 AudioFormatID;
typedef UInt32 AudioFormatFlags;
typedef UInt32 AudioConverterPropertyID;

typedef struct OpaqueAudioComponent *AudioComponent;
typedef struct ComponentInstanceRecord *AudioComponentInstance;
typedef AudioComponentInstance AudioUnit;
typedef struct OpaqueAudioConverter *AudioConverterRef;

typedef struct AudioObjectPropertyAddress {
  AudioObjectPropertySelector mSelector;
  AudioObjectPropertyScope mScope;
  AudioObjectPropertyElement mElement;
} AudioObjectPropertyAddress;

typedef struct AudioStreamBasicDescription {
  Float64 mSampleRate;
  AudioFormatID mFormatID;
  AudioFormatFlags mFormatFlags;
  UInt32 mBytesPerPacket;
  UInt32 mFramesPerPacket;
  UInt32 mBytesPerFrame;
  UInt32 mChannelsPerFrame;
  UInt32 mBitsPerChannel;
  UInt32 mReserved;
} AudioStreamBasicDescription;

typedef struct AudioBuffer {
  UInt32 mNumberChannels;
  UInt32 mDataByteSize;
  void *mData;
} AudioBuffer;

typedef struct AudioBufferList {
  UInt32 mNumberBuffers;
  AudioBuffer mBuffers[1];
} AudioBufferList;

typedef struct AudioStreamPacketDescription {
  SInt64 mStartOffset;
  UInt32 mVariableFramesInPacket;
  UInt32 mDataByteSize;
} AudioStreamPacketDescription;

typedef struct SMPTETime {
  SInt16 mSubframes;
  SInt16 mSubframeDivisor;
  UInt32 mCounter;
  SMPTETimeType mType;
  SMPTETimeFlags mFlags;
  SInt16 mHours;
  SInt16 mMinutes;
  SInt16 mSeconds;
  SInt16 mFrames;
} SMPTETime;

typedef struct AudioTimeStamp {
  Float64 mSampleTime;
  UInt64 mHostTime;
  Float64 mRateScalar;
  UInt64 mWordClockTime;
  SMPTETime mSMPTETime;
  AudioTimeStampFlags mFlags;
  UInt32 mReserved;
} AudioTimeStamp;

typedef struct AudioComponentDescription {
  OSType componentType;
  OSType componentSubType;
  OSType componentManufacturer;
  UInt32 componentFlags;
  UInt32 componentFlagsMask;
} AudioComponentDescription;

typedef OSStatus (*AudioObjectPropertyListenerProc)(
  AudioObjectID,
  UInt32,
  const AudioObjectPropertyAddress *,
  void *
);
typedef OSStatus (*AURenderCallback)(
  void *,
  AudioUnitRenderActionFlags *,
  const AudioTimeStamp *,
  UInt32,
  UInt32,
  AudioBufferList *
);
typedef struct AURenderCallbackStruct {
  AURenderCallback inputProc;
  void *inputProcRefCon;
} AURenderCallbackStruct;
typedef OSStatus (*AudioConverterComplexInputDataProc)(
  AudioConverterRef,
  UInt32 *,
  AudioBufferList *,
  AudioStreamPacketDescription **,
  void *
);
typedef struct AudioConverterPrimeInfo {
  UInt32 leadingFrames;
  UInt32 trailingFrames;
} AudioConverterPrimeInfo;

enum {
  kAudioBooleanControlPropertyValue = 1650685548,
  kAudioControlPropertyElement = 1667591277,
  kAudioControlPropertyScope = 1668506480,
  kAudioConverterPrimeInfo = 1886546285,
  kAudioDevicePropertyActualSampleRate = 1634955892,
  kAudioDevicePropertyBufferFrameSize = 1718839674,
  kAudioDevicePropertyDeviceHasChanged = 1684629094,
  kAudioDevicePropertyDeviceName = 1851878757,
  kAudioDevicePropertyNominalSampleRate = 1853059700,
  kAudioDevicePropertyScopeInput = 1768845428,
  kAudioDevicePropertyScopeOutput = 1869968496,
  kAudioDevicePropertyStreamConfiguration = 1936482681,
  kAudioDevicePropertyStreams = 1937009955,
  kAudioFormatFlagIsBigEndian = 2,
  kAudioFormatFlagIsFloat = 1,
  kAudioFormatFlagIsNonInterleaved = 32,
  kAudioFormatFlagIsPacked = 8,
  kAudioFormatFlagIsSignedInteger = 4,
  kAudioFormatFlagsNativeEndian = 0,
  kAudioFormatLinearPCM = 1819304813,
  kAudioHardwareBadPropertySizeError = 561211770,
  kAudioHardwarePropertyDefaultInputDevice = 1682533920,
  kAudioHardwarePropertyDefaultOutputDevice = 1682929012,
  kAudioHardwarePropertyDevices = 1684370979,
  kAudioHardwarePropertyRunLoop = 1919839344,
  kAudioHardwareUnknownPropertyError = 2003332927,
  kAudioLevelControlPropertyScalarValue = 1818456950,
  kAudioMuteControlClassID = 1836414053,
  kAudioObjectPropertyClass = 1668047219,
  kAudioObjectPropertyElementMaster = 0,
  kAudioObjectPropertyElementName = 1818454126,
  kAudioObjectPropertyManufacturer = 1819107691,
  kAudioObjectPropertyName = 1819173229,
  kAudioObjectPropertyOwnedObjects = 1870098020,
  kAudioObjectPropertyScopeGlobal = 1735159650,
  kAudioObjectSystemObject = 1,
  kAudioOutputUnitProperty_CurrentDevice = 2000,
  kAudioOutputUnitProperty_EnableIO = 2003,
  kAudioOutputUnitProperty_SetInputCallback = 2005,
  kAudioStreamPropertyTerminalType = 1952805485,
  kAudioUnitManufacturer_Apple = 1634758764,
  kAudioUnitProperty_SetRenderCallback = 23,
  kAudioUnitProperty_StreamFormat = 8,
  kAudioUnitScope_Global = 0,
  kAudioUnitScope_Input = 1,
  kAudioUnitScope_Output = 2,
  kAudioUnitSubType_DefaultOutput = 1684366880,
  kAudioUnitSubType_HALOutput = 1634230636,
  kAudioUnitType_Output = 1635086197,
  kAudioVolumeControlClassID = 1986817381,
};

#endif
