##! Exercises compression packages through their public data APIs.
{testing}: {
  zlib = testing.mkQualificationPackageProbe {
    name = "zlib";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "zlib";
      primary = {
        input = "A fixed byte string to compress and recover through the public zlib API.";
        operation = "Compile and run a consumer that compresses and decompresses the input.";
        expected = "The recovered bytes equal the original bytes and the consumer prints the fixed success line.";
        files."round-trip.c" = ''
          #include <stdio.h>
          #include <string.h>
          #include <zlib.h>

          int main(void) {
              const char input[] = "AOS package qualification";
              unsigned char compressed[128];
              unsigned char recovered[sizeof(input)];
              uLongf compressed_size = sizeof(compressed);
              uLongf recovered_size = sizeof(recovered);

              if (compress(compressed, &compressed_size,
                           (const Bytef *)input, sizeof(input)) != Z_OK) {
                  return 2;
              }
              if (uncompress(recovered, &recovered_size,
                             compressed, compressed_size) != Z_OK) {
                  return 3;
              }
              if (recovered_size != sizeof(input)
                  || memcmp(recovered, input, sizeof(input)) != 0) {
                  return 4;
              }

              return puts("zlib round trip passed") == EOF;
          }
        '';
        steps = [
          {
            argv = [
              "@cc@"
              "round-trip.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lz"
              "-o"
              "zlib-round-trip"
            ];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@work@/primary/zlib-round-trip"];
            exit_code = 0;
            stdout.exact = "zlib round trip passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "A byte sequence that is not a zlib stream.";
        operation = "Compile and run a consumer that passes the invalid stream to uncompress.";
        expected = "The public API returns Z_DATA_ERROR and the consumer exits with the fixed rejection status and diagnostic.";
        files."reject-invalid.c" = ''
          #include <stdio.h>
          #include <zlib.h>

          int main(void) {
              const unsigned char invalid[] = "not a zlib stream";
              unsigned char output[128];
              uLongf output_size = sizeof(output);
              int result = uncompress(output, &output_size, invalid, sizeof(invalid));

              if (result != Z_DATA_ERROR) {
                  return 2;
              }

              fputs("zlib rejected invalid stream\n", stderr);
              return 7;
          }
        '';
        steps = [
          {
            argv = [
              "@cc@"
              "reject-invalid.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lz"
              "-o"
              "zlib-reject-invalid"
            ];
            exit_code = 0;
            stdout.exact = "";
            stderr.exact = "";
          }
          {
            argv = ["@work@/bad-input/zlib-reject-invalid"];
            exit_code = 7;
            stdout.exact = "";
            stderr.exact = "zlib rejected invalid stream\n";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
