# SPDX-License-Identifier: Apache-2.0
"""Exercise the actual guest UART emitter with bounded host-side I/O models."""

import argparse
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    source = args.source.read_text()
    signature = "static int emit_serial_readiness(void) {"
    start = source.index(signature)
    position = source.index("{", start)
    depth = 1
    end = position + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    body = source[start:end]

    model = r'''
    #include <assert.h>
    #include <stddef.h>
    #include <string.h>

    static unsigned mode;
    static unsigned polls;
    static unsigned char output[128];
    static unsigned output_length;

    static unsigned char inb(unsigned short port) {
      if (port == 0x3fb) {
        return mode == 1 ? 0x80 : 0;
      }
      assert(port == 0x3fd);
      ++polls;
      return mode == 2 || (mode == 3 && polls <= 3) ? 0 : 0x20;
    }

    static void outb(unsigned char value, unsigned short port) {
      assert(port == 0x3f8 && output_length < sizeof(output));
      output[output_length++] = value;
    }
    ''' + body + r'''

    int main(void) {
      static const unsigned char expected[] = "\nCRUCIBLE_TCG_BOOT_READY_V1\n";

      mode = 1;
      assert(emit_serial_readiness() == -1 && output_length == 0 && polls == 0);

      mode = 2;
      assert(emit_serial_readiness() == -1 && output_length == 0);
      assert(polls == (1u << 20));

      mode = 3;
      polls = 0;
      assert(emit_serial_readiness() == 0);
      assert(output_length == sizeof(expected) - 1);
      assert(memcmp(output, expected, output_length) == 0);
      assert(polls == output_length + 3);
      return 0;
    }
    '''
    with tempfile.TemporaryDirectory(prefix="tcg-uart-test-") as temporary:
        directory = Path(temporary)
        fixture = directory / "uart-test.c"
        binary = directory / "uart-test"
        fixture.write_text(model)
        subprocess.run([args.cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                        str(fixture), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=5)
    print("PASS: DLAB rejection, bounded THRE failure, exact eventual-ready token")


if __name__ == "__main__":
    main()
