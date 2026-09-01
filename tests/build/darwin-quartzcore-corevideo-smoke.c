/* Prove QuartzCore carries its canonical CoreVideo reexport. */

#include <CoreVideo/CoreVideo.h>

#define AOS_FUNCTION(name) ((const void *)&name)
const void *aos_quartzcore_corevideo_functions[] = {
  AOS_FUNCTION(CVDisplayLinkCreateWithActiveCGDisplays),
  AOS_FUNCTION(CVDisplayLinkIsRunning),
  AOS_FUNCTION(CVDisplayLinkRelease),
  AOS_FUNCTION(CVDisplayLinkSetOutputCallback),
  AOS_FUNCTION(CVDisplayLinkStart),
  AOS_FUNCTION(CVDisplayLinkStop),
};
#undef AOS_FUNCTION

int main(void) {
  return aos_quartzcore_corevideo_functions[0] == NULL;
}
