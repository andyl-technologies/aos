#include <cgif.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct output {
    uint8_t bytes[256];
    size_t length;
};

static int write_output(void *context, const uint8_t *bytes, size_t length) {
    struct output *output = context;
    if (length > sizeof(output->bytes) - output->length) return -1;
    memcpy(output->bytes + output->length, bytes, length);
    output->length += length;
    return 0;
}

int main(int argc, char **argv) {
    uint8_t palette[] = {255, 0, 0};
    uint8_t pixel[] = {0};
    struct output output = {0};
    CGIF_Config config = {
        .pGlobalPalette = palette,
        .width = 1,
        .height = 1,
        .numGlobalPaletteEntries = 1,
        .pWriteFn = write_output,
        .pContext = &output,
    };

    if (argc > 1) {
        config.pWriteFn = NULL;
        config.path = "unavailable/image.gif";
        CGIF *invalid = cgif_newgif(&config);
        if (invalid != NULL) {
            cgif_close(invalid);
            return 1;
        }
        puts("cgif rejected unavailable output path");
        return 0;
    }

    CGIF *gif = cgif_newgif(&config);
    if (gif == NULL) return 2;

    CGIF_FrameConfig frame = {.pImageData = pixel};
    int frame_result = cgif_addframe(gif, &frame);
    int close_result = cgif_close(gif);
    if (frame_result != CGIF_OK || close_result != CGIF_OK) return 3;
    if (output.length < 14 || memcmp(output.bytes, "GIF89a", 6) != 0) return 4;
    if (output.bytes[output.length - 1] != ';') return 5;
    puts("cgif encoded one-pixel GIF");
    return 0;
}
