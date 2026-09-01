#ifndef _AOS_APPKIT_NSOPENGL_H_
#define _AOS_APPKIT_NSOPENGL_H_

#import <Foundation/Foundation.h>
#include <OpenGL/OpenGL.h>

@class NSView;

typedef uint32_t NSOpenGLPixelFormatAttribute;
enum {
  NSOpenGLPFADoubleBuffer = 5,
  NSOpenGLPFAColorSize = 8,
  NSOpenGLPFAAlphaSize = 11,
  NSOpenGLPFADepthSize = 12,
  NSOpenGLPFARendererID = 70,
  NSOpenGLPFAAccelerated = 73,
  NSOpenGLPFAClosestPolicy = 74,
  NSOpenGLPFAWindow = 80,
  NSOpenGLPFAScreenMask = 84,
  NSOpenGLPFAPixelBuffer = 90,
  NSOpenGLPFAAllowOfflineRenderers = 96,
};

typedef enum {
  NSOpenGLCPSwapInterval = 222,
} NSOpenGLContextParameter;

@interface NSOpenGLPixelFormat : NSObject
- (id)initWithAttributes:(const NSOpenGLPixelFormatAttribute *)attributes;
- (void)getValues:(GLint *)values
      forAttribute:(NSOpenGLPixelFormatAttribute)attribute
   forVirtualScreen:(GLint)screen;
@end

@interface NSOpenGLPixelBuffer : NSObject
- (id)initWithTextureTarget:(GLenum)target
      textureInternalFormat:(GLenum)format
         textureMaxMipMapLevel:(GLint)maxLevel
                  pixelsWide:(GLsizei)width
                  pixelsHigh:(GLsizei)height;
- (GLsizei)pixelsWide;
- (GLsizei)pixelsHigh;
@end

@interface NSOpenGLContext : NSObject
- (id)initWithFormat:(NSOpenGLPixelFormat *)format
        shareContext:(NSOpenGLContext *)share;
- (void)setView:(NSView *)view;
- (NSView *)view;
- (void)clearDrawable;
- (void)update;
- (void)flushBuffer;
- (void)makeCurrentContext;
+ (void)clearCurrentContext;
+ (NSOpenGLContext *)currentContext;
- (void)setValues:(const GLint *)values forParameter:(NSOpenGLContextParameter)parameter;
- (GLint)currentVirtualScreen;
- (void)setPixelBuffer:(NSOpenGLPixelBuffer *)pixelBuffer
            cubeMapFace:(GLenum)face
            mipMapLevel:(GLint)level
   currentVirtualScreen:(GLint)screen;
- (void)setTextureImageToPixelBuffer:(NSOpenGLPixelBuffer *)pixelBuffer
                         colorBuffer:(GLenum)colorBuffer;
@end

#endif
