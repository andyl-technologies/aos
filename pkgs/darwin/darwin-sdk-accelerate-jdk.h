#ifndef _AOS_ACCELERATE_H_
#define _AOS_ACCELERATE_H_

/*
 * Minimal vImage ABI used by the IcedTea JDK 8 macOS font and image paths.
 * Signatures and values are verified against Apple's public vImage headers;
 * this is an independently authored declaration surface, not an SDK copy.
 */
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef unsigned long vImagePixelCount;
typedef struct vImage_Buffer {
  void *data;
  vImagePixelCount height;
  vImagePixelCount width;
  size_t rowBytes;
} vImage_Buffer;

typedef ssize_t vImage_Error;
typedef uint32_t vImage_Flags;
typedef uint8_t Pixel_8;
typedef float Pixel_F;
typedef Pixel_8 Pixel_8888[4];

enum {
  kvImageNoError = 0,
  kvImageNoFlags = 0,
  kvImageDoNotTile = 16
};

vImage_Error vImageBufferFill_ARGB8888(
  const vImage_Buffer *dest,
  const Pixel_8888 color,
  vImage_Flags flags
);
vImage_Error vImageLookupTable_Planar8toPlanarF(
  const vImage_Buffer *src,
  const vImage_Buffer *dest,
  const Pixel_F table[256],
  vImage_Flags flags
);

#endif
