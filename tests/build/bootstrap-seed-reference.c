/* SPDX-License-Identifier: Apache-2.0 */

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

static int hex_nibble(int byte)
{
    if (byte >= '0' && byte <= '9')
        return byte - '0';
    if (byte >= 'A' && byte <= 'F')
        return byte - 'A' + 10;
    if (byte >= 'a' && byte <= 'f')
        return byte - 'a' + 10;
    return -1;
}

static int is_separator(int byte)
{
    return byte == ' ' || byte == '\t' || byte == '\n' || byte == '\r';
}

int main(int argc, char **argv)
{
    FILE *input = NULL;
    FILE *output = NULL;
    int output_fd = -1;
    int high_nibble = -1;
    int in_comment = 0;
    int status = 1;

    if (argc != 3)
        return 1;

    input = fopen(argv[1], "rb");
    if (input == NULL)
        return 1;

    output_fd = open(argv[2], O_WRONLY | O_CREAT | O_EXCL, 0700);
    if (output_fd < 0)
        goto close_input;
    if (fchmod(output_fd, 0700) != 0)
        goto remove_output;

    output = fdopen(output_fd, "wb");
    if (output == NULL)
        goto remove_output;

    for (;;) {
        int byte = fgetc(input);
        int nibble;

        if (byte == EOF)
            break;

        if (in_comment) {
            if (byte == '\n')
                in_comment = 0;
            continue;
        }

        if (byte == '#' || byte == ';') {
            in_comment = 1;
            continue;
        }

        nibble = hex_nibble(byte);
        if (nibble >= 0) {
            if (high_nibble < 0) {
                high_nibble = nibble;
            } else {
                if (fputc((high_nibble << 4) | nibble, output) == EOF)
                    goto close_output;
                high_nibble = -1;
            }
            continue;
        }

        if (!is_separator(byte))
            goto close_output;
    }

    if (ferror(input) || high_nibble >= 0)
        goto close_output;
    if (fflush(output) != 0 || fsync(output_fd) != 0)
        goto close_output;
    if (fclose(output) != 0) {
        output = NULL;
        goto remove_output;
    }
    output = NULL;
    status = 0;
    goto close_input;

close_output:
    if (output != NULL) {
        fclose(output);
        output = NULL;
    }
remove_output:
    unlink(argv[2]);
close_input:
    if (input != NULL)
        fclose(input);
    return status;
}
