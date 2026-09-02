#ifndef _AOS_OPENGL_H_
#define _AOS_OPENGL_H_

#include <stdint.h>
#include <IOSurface/IOSurface.h>

typedef uint32_t GLenum;
typedef uint32_t GLuint;
typedef uint32_t GLbitfield;
typedef int32_t GLint;
typedef int32_t GLsizei;
typedef float GLfloat;
typedef float GLclampf;

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
typedef struct _CGLPixelFormatObject *CGLPixelFormatObj;
typedef enum _CGLError {
  kCGLNoError = 0,
  kCGLBadConnection = 10017,
} CGLError;

CGLError CGLCreateContext(CGLPixelFormatObj, CGLContextObj, CGLContextObj *);
CGLPixelFormatObj CGLRetainPixelFormat(CGLPixelFormatObj);
CGLError CGLSetCurrentContext(CGLContextObj);
void glBegin(GLenum);
void glBindTexture(GLenum, GLuint);
void glClear(GLbitfield);
void glClearColor(GLclampf, GLclampf, GLclampf, GLclampf);
void glDisable(GLenum);
void glEnable(GLenum);
void glEnd(void);
void glTexCoord2f(GLfloat, GLfloat);
void glTexEnvf(GLenum, GLenum, GLfloat);
void glVertex2f(GLfloat, GLfloat);
void glViewport(GLint, GLint, GLsizei, GLsizei);

#endif
