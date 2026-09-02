/* Prove that CoreServices carries its canonical nested LaunchServices ABI. */

#include <CoreServices/CoreServices.h>

int main(void) {
  CFStringRef identifier = UTTypeCreatePreferredIdentifierForTag(
    kUTTagClassMIMEType,
    CFSTR("application/xml"),
    NULL
  );
  CFStringRef extension = UTTypeCopyPreferredTagWithClass(
    identifier,
    kUTTagClassFilenameExtension
  );

  if (extension != NULL) {
    CFRelease(extension);
  }
  if (identifier != NULL) {
    CFRelease(identifier);
  }
  return identifier == NULL || extension == NULL;
}
