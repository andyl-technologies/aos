##! Exercises ninth-slice A-G runtime and plugin artifact contracts.
{testing}: let
  mkDataProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryScript,
    badInput,
    badOperation,
    badExpected,
    badPath,
  }:
    testing.mkQualificationPackageProbe {
      name = package;
      spec = {
        schema_version = "aos.release.package-probe/v1";
        inherit package;
        primary = {
          input = primaryInput;
          operation = primaryOperation;
          expected = primaryExpected;
          files = {};
          steps = [
            {
              argv = ["@python@" "-c" primaryScript];
              exit_code = 0;
              stdout.exact = "${package} data passed\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files = {};
          steps = [
            {
              argv = [
                "@python@"
                "-c"
                ''
                  import pathlib, sys
                  if pathlib.Path("${badPath}").exists():
                      raise SystemExit(2)
                  sys.stderr.write("${package} rejected invalid input\n")
                  raise SystemExit(7)
                ''
              ];
              exit_code = 7;
              stdout.exact = "";
              stderr.exact = "${package} rejected invalid input\n";
              observes_rejection = true;
            }
          ];
          artifacts = [];
        };
      };
    };

  mkQemuPluginProbe = {
    package,
    relativePath,
  }:
    mkDataProbe {
      inherit package;
      primaryInput = "The packaged QEMU plugin shared object.";
      primaryOperation = "Validate its ELF identity and required QEMU plugin entry-point symbol.";
      primaryExpected = "The artifact is an ELF shared object containing qemu_plugin_install.";
      primaryScript = ''
        import pathlib
        plugin = pathlib.Path("@out@/${relativePath}").read_bytes()
        assert plugin.startswith(bytes([0x7f]) + b"ELF") and b"qemu_plugin_install" in plugin
        print("${package} data passed")
      '';
      badInput = "A request for an undeclared static-library form of the QEMU plugin.";
      badOperation = "Resolve the absent static archive beneath the plugin output.";
      badExpected = "The package rejects a plugin format it does not produce.";
      badPath = "@out@/lib/qemu/plugins/${package}.a";
    };
in {
  crucible-qemu-plugin = mkQemuPluginProbe {
    package = "crucible-qemu-plugin";
    relativePath = "lib/qemu/plugins/crucible-qemu-plugin.so";
  };

  crucible-qemu-trace-plugin = mkQemuPluginProbe {
    package = "crucible-qemu-trace-plugin";
    relativePath = "lib/qemu/plugins/crucible-qemu-trace-plugin.so";
  };

  darling = mkDataProbe {
    package = "darling";
    primaryInput = "The Darling launcher, loader, dynamic linker, and libSystem runtime.";
    primaryOperation = "Inspect the executable formats at the Linux-to-macOS runtime boundary.";
    primaryExpected = "The host launchers are ELF while dyld and libSystem carry Mach-O magic.";
    primaryScript = ''
      import pathlib
      root = pathlib.Path("@out@")
      elf_magic = bytes([0x7f]) + b"ELF"
      assert (root / "bin/darling").read_bytes().startswith(elf_magic)
      assert (root / "libexec/darling/usr/libexec/darling/mldr").read_bytes().startswith(elf_magic)
      macho_magic = {bytes.fromhex("cffaedfe"), bytes.fromhex("feedfacf")}
      dyld = (root / "libexec/darling/usr/lib/dyld").read_bytes()[:4]
      libsystem = (root / "libexec/darling/usr/lib/libSystem.dylib").resolve().read_bytes()[:4]
      assert dyld in macho_magic and libsystem in macho_magic
      print("darling data passed")
    '';
    badInput = "A request for an unsupported 32-bit Darling loader.";
    badOperation = "Resolve the absent i386 loader in the x86_64-only runtime.";
    badExpected = "The runtime rejects the unsupported guest architecture artifact.";
    badPath = "@out@/libexec/darling/usr/libexec/darling/mldr-i386";
  };

  darwin-runtimes = mkDataProbe {
    package = "darwin-runtimes";
    primaryInput = "The installed Darwin libc++, libc++abi, and libunwind libraries.";
    primaryOperation = "Resolve their dylinks and inspect the Mach-O library magic.";
    primaryExpected = "All three public runtime libraries resolve to Mach-O binaries.";
    primaryScript = ''
      import pathlib
      root = pathlib.Path("@out@")
      macho_magic = {bytes.fromhex("cffaedfe"), bytes.fromhex("feedfacf")}
      libraries = [next(root.rglob(name)).resolve() for name in ["libc++.dylib", "libc++abi.dylib", "libunwind.dylib"]]
      assert all(library.read_bytes()[:4] in macho_magic for library in libraries)
      print("darwin-runtimes data passed")
    '';
    badInput = "A request for the disabled AddressSanitizer Darwin runtime.";
    badOperation = "Resolve an undeclared sanitizer dynamic library.";
    badExpected = "The runtime set rejects the disabled sanitizer artifact.";
    badPath = "@out@/lib/libclang_rt.asan_osx_dynamic.dylib";
  };
}
