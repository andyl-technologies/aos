##! Exercises an eighth H-through-P slice through real runtime and library operations.
{testing}: let
  mkProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryFiles ? {},
    primaryScript,
    badInput,
    badOperation,
    badExpected,
    badFiles ? {},
    badScript,
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
          files = primaryFiles;
          steps = [
            {
              argv = ["@python@" "-c" primaryScript];
              exit_code = 0;
              stdout.exact = "${package} operation passed\n";
              stderr.exact = "";
            }
          ];
          artifacts = [];
        };
        bad_input = {
          input = badInput;
          operation = badOperation;
          expected = badExpected;
          files = badFiles;
          steps = [
            {
              argv = ["@python@" "-c" badScript];
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

  compile = source: output: libraries: ''
    import json, os, pathlib, subprocess
    closure = json.loads(os.environ["AOS_QUALIFICATION_PACKAGE_CLOSURE"])
    command = ["@cc@", ${builtins.toJSON source}]
    for root_text in closure:
        root = pathlib.Path(root_text)
        include = root / "include"
        library = root / "lib"
        if include.is_dir():
            command.append("-I" + str(include))
        if library.is_dir():
            command.extend(["-L" + str(library), "-Wl,-rpath," + str(library)])
    command.extend(${builtins.toJSON libraries} + ["-o", ${builtins.toJSON output}])
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 0, (result.returncode, result.stdout, result.stderr)
  '';

  reject = package: body: ''
    import sys
    ${body}
    sys.stderr.write("${package} rejected invalid input\n")
    raise SystemExit(7)
  '';

  javaClass = "yv66vgAAADEAHQoABgAPCQAQABEIABIKABMAFAcAFQcAFgEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAARtYWluAQAWKFtMamF2YS9sYW5nL1N0cmluZzspVgEAClNvdXJjZUZpbGUBABJRdWFsaWZpY2F0aW9uLmphdmEMAAcACAcAFwwAGAAZAQAJYW5zd2VyPTQyBwAaDAAbABwBAA1RdWFsaWZpY2F0aW9uAQAQamF2YS9sYW5nL09iamVjdAEAEGphdmEvbGFuZy9TeXN0ZW0BAANvdXQBABVMamF2YS9pby9QcmludFN0cmVhbTsBABNqYXZhL2lvL1ByaW50U3RyZWFtAQAHcHJpbnRsbgEAFShMamF2YS9sYW5nL1N0cmluZzspVgAhAAUABgAAAAAAAgABAAcACAABAAkAAAAdAAEAAQAAAAUqtwABsQAAAAEACgAAAAYAAQAAAAEACQALAAwAAQAJAAAAIQACAAEAAAAJsgACEgO2AASxAAAAAQAKAAAABgABAAAAAQABAA0AAAACAA4=";

  mkJamvmProbe = package:
    mkProbe {
      inherit package;
      primaryInput = "A Java 5 classfile whose main method prints answer=42.";
      primaryOperation = "Load and execute the class through the packaged JamVM runtime.";
      primaryExpected = "JamVM executes the bytecode and returns the fixed answer.";
      primaryFiles."Qualification.class.b64" = javaClass;
      primaryScript = ''
        import base64, pathlib, subprocess
        encoded = pathlib.Path("Qualification.class.b64").read_text()
        pathlib.Path("Qualification.class").write_bytes(base64.b64decode(encoded))
        result = subprocess.run(["@out@/bin/jamvm", "Qualification"], capture_output=True, text=True)
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert result.stdout == "answer=42\n" and result.stderr == ""
        print("${package} operation passed")
      '';
      badInput = "A classfile truncated inside its constant pool.";
      badOperation = "Attempt to load the malformed class through JamVM.";
      badExpected = "JamVM rejects the malformed constant pool before execution.";
      badFiles."Broken.class.b64" = "yv66vgAAADEAHQoABgAPCQ==";
      badScript = reject package ''
        import base64, pathlib, subprocess
        encoded = pathlib.Path("Broken.class.b64").read_text()
        pathlib.Path("Broken.class").write_bytes(base64.b64decode(encoded))
        result = subprocess.run(["@out@/bin/jamvm", "Broken"], capture_output=True, text=True)
        assert result.returncode != 0 and "ClassFormatError" in result.stderr
      '';
    };
in {
  jamvm-1_5 = mkJamvmProbe "jamvm-1_5";
  jamvm-2_0 = mkJamvmProbe "jamvm-2_0";

  jikes = mkProbe {
    package = "jikes";
    primaryInput = "A Java class with a constant answer and the compiler's minimal bootstrap types.";
    primaryOperation = "Compile the sources to Java 1.4 classfiles with Jikes.";
    primaryExpected = "Jikes emits a classfile containing the declared answer constant.";
    primaryFiles = {
      "java/lang/Object.java" = "package java.lang; public class Object {}\n";
      "java/lang/String.java" = "package java.lang; public final class String {}\n";
      "java/io/Serializable.java" = "package java.io; public interface Serializable {}\n";
      "Answer.java" = "public class Answer { public static final int VALUE = 42; }\n";
    };
    primaryScript = ''
      import pathlib, subprocess
      result = subprocess.run(["@out@/bin/jikes", "-bootclasspath", ".", "java/lang/Object.java", "java/lang/String.java", "java/io/Serializable.java", "Answer.java"], capture_output=True, text=True)
      assert result.returncode == 0, (result.stdout, result.stderr)
      classfile = pathlib.Path("Answer.class").read_bytes()
      assert classfile[:8] == bytes.fromhex("cafebabe00000030")
      assert b"VALUE" in classfile and bytes.fromhex("0000002a") in classfile
      print("jikes operation passed")
    '';
    badInput = "A Java class whose body is missing its closing brace.";
    badOperation = "Compile the malformed source with the same minimal bootstrap types.";
    badExpected = "Jikes reports a syntax error and does not emit the requested classfile.";
    badFiles = {
      "java/lang/Object.java" = "package java.lang; public class Object {}\n";
      "java/lang/String.java" = "package java.lang; public final class String {}\n";
      "java/io/Serializable.java" = "package java.io; public interface Serializable {}\n";
      "Broken.java" = "public class Broken {\n";
    };
    badScript = reject "jikes" ''
      import pathlib, subprocess
      result = subprocess.run(["@out@/bin/jikes", "-bootclasspath", ".", "java/lang/Object.java", "java/lang/String.java", "java/io/Serializable.java", "Broken.java"], capture_output=True, text=True)
      assert result.returncode != 0 and "Syntax Error" in (result.stdout + result.stderr)
      assert not pathlib.Path("Broken.class").exists()
    '';
  };

  libutempter = mkProbe {
    package = "libutempter";
    primaryInput = "A pseudoterminal master and an accounting helper that accepts the update.";
    primaryOperation = "Submit an add-record request through libutempter's public helper protocol.";
    primaryExpected = "Libutempter invokes the helper and reports a successful update.";
    primaryFiles."helper" = ''
      #!@bash@
      exit 0
    '';
    primaryFiles."primary.c" = ''
      #define _XOPEN_SOURCE 600
      #include <fcntl.h>
      #include <stdlib.h>
      #include <utempter.h>

      int main(void) {
          int descriptor = posix_openpt(O_RDWR | O_NOCTTY);
          if (descriptor < 0 || grantpt(descriptor) != 0 || unlockpt(descriptor) != 0) return 2;
          utempter_set_helper("@work@/primary/helper");
          return utempter_add_record(descriptor, "qualification") == 1 ? 0 : 3;
      }
    '';
    primaryScript = ''
      import pathlib, subprocess
      pathlib.Path("helper").chmod(0o755)
      ${compile "primary.c" "primary-check" ["-lutempter"]}
      result = subprocess.run(["./primary-check"], capture_output=True, text=True)
      assert result.returncode == 0, (result.stdout, result.stderr)
      print("libutempter operation passed")
    '';
    badInput = "A pseudoterminal master and an accounting helper that refuses the update.";
    badOperation = "Submit the add-record request and observe the helper failure through libutempter.";
    badExpected = "Libutempter reports that the accounting record was not added.";
    badFiles."helper" = ''
      #!@bash@
      exit 1
    '';
    badFiles."bad-input.c" = ''
      #define _XOPEN_SOURCE 600
      #include <fcntl.h>
      #include <stdlib.h>
      #include <utempter.h>

      int main(void) {
          int descriptor = posix_openpt(O_RDWR | O_NOCTTY);
          if (descriptor < 0 || grantpt(descriptor) != 0 || unlockpt(descriptor) != 0) return 2;
          utempter_set_helper("@work@/bad-input/helper");
          return utempter_add_record(descriptor, "qualification") == 0 ? 0 : 3;
      }
    '';
    badScript = reject "libutempter" ''
      import pathlib, subprocess
      pathlib.Path("helper").chmod(0o755)
      ${compile "bad-input.c" "bad-input-check" ["-lutempter"]}
      result = subprocess.run(["./bad-input-check"], capture_output=True, text=True)
      assert result.returncode == 0, (result.stdout, result.stderr)
    '';
  };

  libmpc = mkProbe {
    package = "libmpc";
    primaryInput = "The exact complex integer value 4-2i at 53-bit precision.";
    primaryOperation = "Initialize, assign, and compare the value through libmpc's exported ABI.";
    primaryExpected = "Libmpc preserves both integer components exactly.";
    primaryScript = ''
      import ctypes
      library = ctypes.CDLL("@out@/lib/libmpc.so")
      value = ctypes.create_string_buffer(256)
      library.mpc_init2.argtypes = [ctypes.c_void_p, ctypes.c_long]
      library.mpc_set_si_si.argtypes = [ctypes.c_void_p, ctypes.c_long, ctypes.c_long, ctypes.c_int]
      library.mpc_cmp_si_si.argtypes = [ctypes.c_void_p, ctypes.c_long, ctypes.c_long]
      library.mpc_clear.argtypes = [ctypes.c_void_p]
      library.mpc_init2(value, 53)
      assigned = library.mpc_set_si_si(value, 4, -2, 0)
      comparison = library.mpc_cmp_si_si(value, 4, -2)
      library.mpc_clear(value)
      assert assigned == 0 and comparison == 0
      print("libmpc operation passed")
    '';
    badInput = "The text not-a-number as a base-10 complex number.";
    badOperation = "Parse the malformed number through libmpc's exported ABI.";
    badExpected = "Libmpc returns its invalid-number status.";
    badScript = reject "libmpc" ''
      import ctypes
      library = ctypes.CDLL("@out@/lib/libmpc.so")
      value = ctypes.create_string_buffer(256)
      library.mpc_init2.argtypes = [ctypes.c_void_p, ctypes.c_long]
      library.mpc_set_str.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
      library.mpc_clear.argtypes = [ctypes.c_void_p]
      library.mpc_init2(value, 53)
      status = library.mpc_set_str(value, b"not-a-number", 10, 0)
      library.mpc_clear(value)
      assert status != 0
    '';
  };

  lm-sensors = mkProbe {
    package = "lm-sensors";
    primaryInput = "The canonical hwmon chip name coretemp-isa-0000.";
    primaryOperation = "Parse and release the chip name through libsensors.";
    primaryExpected = "Libsensors accepts the prefix, bus type, and hexadecimal address.";
    primaryFiles."primary.c" = ''
      #include <sensors/sensors.h>

      int main(void) {
          sensors_chip_name chip;
          int status = sensors_parse_chip_name("coretemp-isa-0000", &chip);
          if (status == 0) sensors_free_chip_name(&chip);
          return status == 0 ? 0 : 2;
      }
    '';
    primaryScript = ''
      import subprocess
      ${compile "primary.c" "primary-check" ["-lsensors"]}
      result = subprocess.run(["./primary-check"], capture_output=True, text=True)
      assert result.returncode == 0, (result.stdout, result.stderr)
      print("lm-sensors operation passed")
    '';
    badInput = "A chip name containing a slash where a bus description is required.";
    badOperation = "Parse the malformed name through libsensors.";
    badExpected = "Libsensors returns its chip-name parse error.";
    badFiles."bad-input.c" = ''
      #include <sensors/error.h>
      #include <sensors/sensors.h>

      int main(void) {
          sensors_chip_name chip;
          return sensors_parse_chip_name("bad/name", &chip) == -SENSORS_ERR_CHIP_NAME ? 0 : 2;
      }
    '';
    badScript = reject "lm-sensors" ''
      import subprocess
      ${compile "bad-input.c" "bad-input-check" ["-lsensors"]}
      result = subprocess.run(["./bad-input-check"], capture_output=True, text=True)
      assert result.returncode == 0, (result.stdout, result.stderr)
    '';
  };

  miniflare = mkProbe {
    package = "miniflare";
    primaryInput = "A local module Worker configuration and source file.";
    primaryOperation = "Generate project TypeScript declarations through the bundled Wrangler CLI.";
    primaryExpected = "Wrangler reads the configuration and emits declarations for the Worker module.";
    primaryFiles."wrangler.toml" = ''
      name = "qualification"
      main = "worker.js"
      compatibility_date = "2024-09-09"
    '';
    primaryFiles."worker.js" = ''
      export default { fetch() { return new Response("answer=42"); } };
    '';
    primaryScript = ''
      import os, pathlib, subprocess
      home = pathlib.Path("home")
      home.mkdir()
      environment = os.environ.copy()
      environment.update({"CI": "1", "HOME": str(home.resolve()), "WRANGLER_SEND_METRICS": "false"})
      result = subprocess.run(["@out@/bin/wrangler", "types", "output.d.ts", "--include-runtime", "false"], capture_output=True, text=True, env=environment)
      assert result.returncode == 0, (result.stdout, result.stderr)
      declarations = pathlib.Path("output.d.ts").read_text()
      assert 'mainModule: typeof import("./worker")' in declarations
      print("miniflare operation passed")
    '';
    badInput = "A Wrangler configuration containing an unterminated TOML array.";
    badOperation = "Attempt project type generation from the malformed configuration.";
    badExpected = "Wrangler rejects the invalid TOML before writing declarations.";
    badFiles."wrangler.toml" = "name = [\n";
    badFiles."worker.js" = "export default {};\n";
    badScript = reject "miniflare" ''
      import os, pathlib, subprocess
      home = pathlib.Path("home")
      home.mkdir()
      environment = os.environ.copy()
      environment.update({"CI": "1", "HOME": str(home.resolve()), "WRANGLER_SEND_METRICS": "false"})
      result = subprocess.run(["@out@/bin/wrangler", "types", "invalid.d.ts", "--include-runtime", "false"], capture_output=True, text=True, env=environment)
      assert result.returncode != 0 and "Invalid TOML document" in (result.stdout + result.stderr)
      assert not pathlib.Path("invalid.d.ts").exists()
    '';
  };
}
