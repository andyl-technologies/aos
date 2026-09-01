#ifndef _AOS_COREMIDI_H_
#define _AOS_COREMIDI_H_

#include <CoreFoundation/CoreFoundation.h>
#include <MacTypes.h>

typedef unsigned long ByteCount;
typedef unsigned long ItemCount;
typedef UInt32 MIDIObjectRef;
typedef UInt32 MIDIClientRef;
typedef UInt32 MIDIPortRef;
typedef UInt32 MIDIEndpointRef;
typedef UInt64 MIDITimeStamp;
typedef SInt32 MIDINotificationMessageID;

typedef struct MIDINotification {
  MIDINotificationMessageID messageID;
  ByteCount messageSize;
} MIDINotification;
typedef struct MIDIPacket {
  MIDITimeStamp timeStamp;
  UInt16 length;
  Byte data[256];
} __attribute__((packed, aligned(4))) MIDIPacket;
typedef struct MIDIPacketList {
  UInt32 numPackets;
  MIDIPacket packet[1];
} __attribute__((packed, aligned(4))) MIDIPacketList;
#if defined(__arm__) || defined(__arm64__)
static inline MIDIPacket *MIDIPacketNext(const MIDIPacket *packet) {
  return (MIDIPacket *)(((uintptr_t)(&packet->data[packet->length]) + 3) & ~((uintptr_t)3));
}
#else
static inline MIDIPacket *MIDIPacketNext(const MIDIPacket *packet) {
  return (MIDIPacket *)&packet->data[packet->length];
}
#endif
typedef void (*MIDINotifyProc)(const MIDINotification *, void *);
typedef void (*MIDIReadProc)(const MIDIPacketList *, void *, void *);

enum {
  kMIDIInvalidClient = -10830,
  kMIDIInvalidPort = -10831,
  kMIDIWrongEndpointType = -10832,
  kMIDINoConnection = -10833,
  kMIDIUnknownEndpoint = -10834,
  kMIDIUnknownProperty = -10835,
  kMIDIWrongPropertyType = -10836,
  kMIDINoCurrentSetup = -10837,
  kMIDIMessageSendErr = -10838,
  kMIDIServerStartErr = -10839,
  kMIDISetupFormatErr = -10840,
  kMIDIWrongThread = -10841,
  kMIDIObjectNotFound = -10842,
  kMIDIIDNotUnique = -10843,
};

extern const CFStringRef kMIDIPropertyDisplayName;
extern const CFStringRef kMIDIPropertyDriverVersion;
extern const CFStringRef kMIDIPropertyManufacturer;
extern const CFStringRef kMIDIPropertyName;
extern const CFStringRef kMIDIPropertyUniqueID;
OSStatus MIDIClientCreate(CFStringRef, MIDINotifyProc, void *, MIDIClientRef *);
OSStatus MIDIInputPortCreate(MIDIClientRef, CFStringRef, MIDIReadProc, void *, MIDIPortRef *);
OSStatus MIDIOutputPortCreate(MIDIClientRef, CFStringRef, MIDIPortRef *);
OSStatus MIDIPortConnectSource(MIDIPortRef, MIDIEndpointRef, void *);
OSStatus MIDIPortDisconnectSource(MIDIPortRef, MIDIEndpointRef);
ItemCount MIDIGetNumberOfSources(void);
ItemCount MIDIGetNumberOfDestinations(void);
MIDIEndpointRef MIDIGetSource(ItemCount);
MIDIEndpointRef MIDIGetDestination(ItemCount);
OSStatus MIDIObjectGetIntegerProperty(MIDIObjectRef, CFStringRef, SInt32 *);
OSStatus MIDIObjectGetStringProperty(MIDIObjectRef, CFStringRef, CFStringRef *);
OSStatus MIDISend(MIDIPortRef, MIDIEndpointRef, const MIDIPacketList *);
OSStatus MIDIFlushOutput(MIDIEndpointRef);
MIDIPacket *MIDIPacketListInit(MIDIPacketList *);
MIDIPacket *MIDIPacketListAdd(MIDIPacketList *, ByteCount, MIDIPacket *, MIDITimeStamp, ByteCount, const Byte *);

#endif
