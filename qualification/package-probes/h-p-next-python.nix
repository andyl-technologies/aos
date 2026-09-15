##! Exercises the PE parser through a synthetic local executable image.
{testing}: {
  "python3-pefile" = testing.mkQualificationPackageProbe {
    name = "python3-pefile";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "python3-pefile";
      primary = {
        input = "A minimal PE32 image with an i386 machine header and image base 0x400000.";
        operation = "Construct and parse the image through pefile.PE.";
        expected = "The parsed file and optional headers expose the encoded values.";
        files."probe.py" = ''
          import glob
          import struct
          import sys

          locations = glob.glob("@out@/lib/python*/site-packages")
          if len(locations) != 1:
              raise RuntimeError("package does not expose one site-packages directory")
          sys.path.insert(0, locations[0])

          import pefile

          image = bytearray(0x178)
          image[0:2] = b"MZ"
          struct.pack_into("<I", image, 0x3C, 0x80)
          image[0x80:0x84] = b"PE\0\0"
          struct.pack_into("<HHIIIHH", image, 0x84, 0x14C, 0, 0, 0, 0, 0xE0, 0x0102)

          optional = 0x98
          struct.pack_into("<H", image, optional, 0x10B)
          struct.pack_into("<I", image, optional + 16, 0x1000)
          struct.pack_into("<I", image, optional + 28, 0x400000)
          struct.pack_into("<I", image, optional + 32, 0x1000)
          struct.pack_into("<I", image, optional + 36, 0x200)
          struct.pack_into("<I", image, optional + 56, 0x1000)
          struct.pack_into("<I", image, optional + 60, 0x200)
          struct.pack_into("<H", image, optional + 68, 3)
          struct.pack_into("<I", image, optional + 92, 16)

          parsed = pefile.PE(data=bytes(image), fast_load=False)
          assert parsed.FILE_HEADER.Machine == 0x14C
          assert parsed.OPTIONAL_HEADER.ImageBase == 0x400000
          assert len(parsed.sections) == 0
          print("python3-pefile primary passed")
        '';
        steps = [
          {
            argv = ["@python@" "probe.py"];
            exit_code = 0;
            stdout.exact = "python3-pefile primary passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "Bytes that contain neither a DOS header nor a PE header.";
        operation = "Parse the malformed image through pefile.PE.";
        expected = "Pefile raises PEFormatError.";
        files."probe.py" = ''
          import glob
          import sys

          locations = glob.glob("@out@/lib/python*/site-packages")
          if len(locations) != 1:
              raise RuntimeError("package does not expose one site-packages directory")
          sys.path.insert(0, locations[0])

          import pefile

          try:
              pefile.PE(data=b"not a portable executable")
          except pefile.PEFormatError:
              print("python3-pefile rejected invalid input", file=sys.stderr)
              raise SystemExit(7)
          raise RuntimeError("pefile accepted malformed input")
        '';
        steps = [
          {
            argv = ["@python@" "probe.py"];
            exit_code = 7;
            stdout.exact = "";
            stderr.exact = "python3-pefile rejected invalid input\n";
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };
}
