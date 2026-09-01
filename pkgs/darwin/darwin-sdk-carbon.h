#ifndef __CARBON__
#define __CARBON__

#include <CoreServices/CoreServices.h>
#include <ApplicationServices/ApplicationServices.h>
#include <Carbon/AEDataModel.h>
#include <Carbon/JDKSurface.h>

typedef UInt32 ProcessApplicationTransformState;
enum {
  kCurrentProcess = 2,
  kProcessTransformToForegroundApplication = 1
};
OSStatus TransformProcessType(
  const ProcessSerialNumber *psn,
  ProcessApplicationTransformState transformState
);

enum {
  kTemporaryFolderType = 'temp',
  kChewableItemsFolderType = 'flnt'
};
OSStatus FSFindFolder(
  SInt16 vRefNum,
  OSType folderType,
  Boolean createFolder,
  FSRef *foundRef
);
OSStatus FSRefMakePath(const FSRef *ref, UInt8 *path, UInt32 maxPathSize);
OSStatus UCConvertCFAbsoluteTimeToLongDateTime(
  CFAbsoluteTime inTime,
  LongDateTime *outTime
);
OSStatus UCConvertLongDateTimeToCFAbsoluteTime(
  LongDateTime inTime,
  CFAbsoluteTime *outTime
);

enum {
  kVK_ANSI_A = 0x00, kVK_ANSI_S = 0x01, kVK_ANSI_D = 0x02,
  kVK_ANSI_F = 0x03, kVK_ANSI_H = 0x04, kVK_ANSI_G = 0x05,
  kVK_ANSI_Z = 0x06, kVK_ANSI_X = 0x07, kVK_ANSI_C = 0x08,
  kVK_ANSI_V = 0x09, kVK_ANSI_B = 0x0b, kVK_ANSI_Q = 0x0c,
  kVK_ANSI_W = 0x0d, kVK_ANSI_E = 0x0e, kVK_ANSI_R = 0x0f,
  kVK_ANSI_Y = 0x10, kVK_ANSI_T = 0x11, kVK_ANSI_1 = 0x12,
  kVK_ANSI_2 = 0x13, kVK_ANSI_3 = 0x14, kVK_ANSI_4 = 0x15,
  kVK_ANSI_6 = 0x16, kVK_ANSI_5 = 0x17, kVK_ANSI_Equal = 0x18,
  kVK_ANSI_9 = 0x19, kVK_ANSI_7 = 0x1a, kVK_ANSI_Minus = 0x1b,
  kVK_ANSI_8 = 0x1c, kVK_ANSI_0 = 0x1d,
  kVK_ANSI_RightBracket = 0x1e, kVK_ANSI_O = 0x1f,
  kVK_ANSI_U = 0x20, kVK_ANSI_LeftBracket = 0x21,
  kVK_ANSI_I = 0x22, kVK_ANSI_P = 0x23, kVK_ANSI_L = 0x25,
  kVK_ANSI_J = 0x26, kVK_ANSI_Quote = 0x27, kVK_ANSI_K = 0x28,
  kVK_ANSI_Semicolon = 0x29, kVK_ANSI_Backslash = 0x2a,
  kVK_ANSI_Comma = 0x2b, kVK_ANSI_Slash = 0x2c,
  kVK_ANSI_N = 0x2d, kVK_ANSI_M = 0x2e,
  kVK_ANSI_Period = 0x2f, kVK_ANSI_Grave = 0x32,
  kVK_ANSI_KeypadDecimal = 0x41, kVK_ANSI_KeypadMultiply = 0x43,
  kVK_ANSI_KeypadPlus = 0x45, kVK_ANSI_KeypadClear = 0x47,
  kVK_ANSI_KeypadDivide = 0x4b, kVK_ANSI_KeypadEnter = 0x4c,
  kVK_ANSI_KeypadMinus = 0x4e, kVK_ANSI_KeypadEquals = 0x51,
  kVK_ANSI_Keypad0 = 0x52, kVK_ANSI_Keypad1 = 0x53,
  kVK_ANSI_Keypad2 = 0x54, kVK_ANSI_Keypad3 = 0x55,
  kVK_ANSI_Keypad4 = 0x56, kVK_ANSI_Keypad5 = 0x57,
  kVK_ANSI_Keypad6 = 0x58, kVK_ANSI_Keypad7 = 0x59,
  kVK_ANSI_Keypad8 = 0x5b, kVK_ANSI_Keypad9 = 0x5c
};

enum {
  kVK_Return = 0x24, kVK_Tab = 0x30, kVK_Space = 0x31,
  kVK_Delete = 0x33, kVK_RightCommand = 0x36,
  kVK_Command = 0x37, kVK_Shift = 0x38, kVK_CapsLock = 0x39,
  kVK_Option = 0x3a, kVK_Control = 0x3b, kVK_RightShift = 0x3c,
  kVK_RightOption = 0x3d, kVK_RightControl = 0x3e,
  kVK_F5 = 0x60, kVK_F6 = 0x61, kVK_F7 = 0x62,
  kVK_F3 = 0x63, kVK_F8 = 0x64, kVK_F9 = 0x65,
  kVK_F11 = 0x67, kVK_F13 = 0x69, kVK_F14 = 0x6b,
  kVK_F10 = 0x6d, kVK_F12 = 0x6f, kVK_F15 = 0x71,
  kVK_Help = 0x72, kVK_Home = 0x73, kVK_PageUp = 0x74,
  kVK_ForwardDelete = 0x75, kVK_F4 = 0x76, kVK_End = 0x77,
  kVK_F2 = 0x78, kVK_PageDown = 0x79, kVK_F1 = 0x7a,
  kVK_LeftArrow = 0x7b, kVK_RightArrow = 0x7c,
  kVK_DownArrow = 0x7d, kVK_UpArrow = 0x7e,
  kVK_Escape = 0x35
};

enum {
  kVK_JIS_Yen = 0x5d, kVK_JIS_Underscore = 0x5e,
  kVK_JIS_KeypadComma = 0x5f, kVK_JIS_Eisu = 0x66,
  kVK_JIS_Kana = 0x68
};

#endif
