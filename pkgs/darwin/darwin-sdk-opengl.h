#ifndef _AOS_OPENGL_H_
#define _AOS_OPENGL_H_

#include <stdint.h>
#include <IOSurface/IOSurface.h>

typedef uint32_t GLenum;
typedef int32_t GLint;
typedef int32_t GLsizei;

#ifndef GL_TEXTURE_2D
#define GL_TEXTURE_2D 0x0de1
#endif
#ifndef GL_RGB
#define GL_RGB 0x1907
#endif
#ifndef GL_RGBA
#define GL_RGBA 0x1908
#endif

typedef struct _CGLContextObject *CGLContextObj;
typedef enum _CGLError {
  kCGLNoError = 0,
  kCGLBadConnection = 10017,
} CGLError;

#endif
