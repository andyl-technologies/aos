##! Exercises additional A-G data, firmware, and system-tool packages.
{testing}: let
  mkPythonDataProbe = {
    package,
    primaryInput,
    primaryOperation,
    primaryExpected,
    primaryScript,
    badInput,
    badOperation,
    badExpected,
    badScript,
    primaryFiles ? {},
    badFiles ? {},
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
in {
  autoconf-archive = mkPythonDataProbe {
    package = "autoconf-archive";
    primaryInput = "The installed AX_PTHREAD Autoconf macro.";
    primaryOperation = "Parse its public macro declaration and required pthread link probes.";
    primaryExpected = "The archive supplies a nonempty AX_PTHREAD definition that tests pthread_create.";
    primaryScript = ''
      import pathlib, re
      source = pathlib.Path("@out@/share/aclocal/ax_pthread.m4").read_text()
      assert re.search(r"AC_DEFUN\s*\(\s*\[AX_PTHREAD\]", source)
      assert "pthread_create" in source
      print("autoconf-archive data passed")
    '';
    badInput = "A request for an AOS-specific macro that the archive does not define.";
    badOperation = "Search the installed macro catalog for that exact declaration.";
    badExpected = "The catalog lookup rejects the absent macro.";
    badScript = ''
      import pathlib, re, sys
      found = any(re.search(r"AC_DEFUN\s*\(\s*\[AX_AOS_NONEXISTENT\]", path.read_text(errors="replace")) for path in pathlib.Path("@out@/share/aclocal").glob("*.m4"))
      if found:
          raise SystemExit(2)
      sys.stderr.write("autoconf-archive rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  bash-completion = mkPythonDataProbe {
    package = "bash-completion";
    primaryInput = "The installed programmable-completion engine.";
    primaryOperation = "Load it in a clean Bash process and resolve its core completion helpers.";
    primaryExpected = "Bash loads the engine and exposes its command and word completion functions.";
    primaryScript = ''
      import subprocess
      script = 'source "@out@/share/bash-completion/bash_completion"; declare -F _init_completion >/dev/null; declare -F _command >/dev/null'
      result = subprocess.run(["@bash@", "--noprofile", "--norc", "-c", script], capture_output=True)
      assert result.returncode == 0, result.stderr
      print("bash-completion data passed")
    '';
    badInput = "A request for a completion helper that the installed engine does not define.";
    badOperation = "Load the engine and resolve the absent helper name.";
    badExpected = "Bash reports that the requested completion function is unavailable.";
    badScript = ''
      import subprocess, sys
      script = 'source "@out@/share/bash-completion/bash_completion"; declare -F _aos_nonexistent_completion'
      result = subprocess.run(["@bash@", "--noprofile", "--norc", "-c", script], capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      sys.stderr.write("bash-completion rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  ca-certificates = mkPythonDataProbe {
    package = "ca-certificates";
    primaryInput = "The package's canonical Mozilla CA bundle.";
    primaryOperation = "Load the bundle through Python's OpenSSL certificate-store API.";
    primaryExpected = "OpenSSL accepts the complete PEM stream and loads multiple trust anchors.";
    primaryScript = ''
      import ssl
      context = ssl.create_default_context(cafile="@out@/etc/ssl/certs/ca-certificates.crt")
      assert len(context.get_ca_certs()) > 100
      print("ca-certificates data passed")
    '';
    badInput = "A PEM file with a truncated certificate body.";
    badOperation = "Load the malformed file through the same OpenSSL certificate-store API.";
    badExpected = "OpenSSL rejects the malformed trust bundle.";
    badFiles."invalid.pem" = "-----BEGIN CERTIFICATE-----\ntruncated\n";
    badScript = ''
      import ssl, sys
      try:
          ssl.create_default_context(cafile="invalid.pem")
      except ssl.SSLError:
          sys.stderr.write("ca-certificates rejected invalid input\n")
          raise SystemExit(7)
      raise SystemExit(2)
    '';
  };

  efibootmgr = mkPythonDataProbe {
    package = "efibootmgr";
    primaryInput = "The packaged EFI boot-entry manager executable.";
    primaryOperation = "Request the tool's version without accessing EFI variables.";
    primaryExpected = "Efibootmgr identifies version 18 and returns success.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/sbin/efibootmgr", "--version"], capture_output=True, text=True)
      assert result.returncode == 0 and "18" in result.stdout
      print("efibootmgr data passed")
    '';
    badInput = "A boot-entry number containing non-hexadecimal characters.";
    badOperation = "Parse the invalid boot-number argument.";
    badExpected = "Efibootmgr rejects the malformed identifier before accessing firmware state.";
    badScript = ''
      import subprocess, sys
      result = subprocess.run(["@out@/sbin/efibootmgr", "--bootnum", "not-hex"], capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      sys.stderr.write("efibootmgr rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  efitools = testing.mkQualificationPackageProbe {
    name = "efitools";
    spec = {
      schema_version = "aos.release.package-probe/v1";
      package = "efitools";
      primary = {
        input = "A fixed X.509 certificate and a fixed EFI signature-owner GUID.";
        operation = "Encode the certificate as an EFI signature list, extract it, and compare the DER bytes.";
        expected = "Efitools preserves the exact certificate through the ESL round trip.";
        files."certificate.pem" = ''
          -----BEGIN CERTIFICATE-----
          MIICBDCCAW2gAwIBAgIUBpo7pnZgiu6BFkoZHAmIw523kQ0wDQYJKoZIhvcNAQEL
          BQAwFDESMBAGA1UEAwwJQU9TLVByb2JlMB4XDTI2MDkwODE4MTYwNloXDTM2MDkw
          NTE4MTYwNlowFDESMBAGA1UEAwwJQU9TLVByb2JlMIGfMA0GCSqGSIb3DQEBAQUA
          A4GNADCBiQKBgQDsf9H4+29Z0TBKfDviaHpzKyIddD0ft2CJjol2uiB9fa/EjshK
          YZ/tAQ+g2clVLsOotDsMvoCF5qxQBOmLpWU+d3Mm8cDjQemhsUofGvRQ0oDhBEO9
          ygfHoxTtgG+4NbmxftXuDZiA79t7lfl3KBxRwT5ychOkhOwxSjcLwKbV+wIDAQAB
          o1MwUTAdBgNVHQ4EFgQUD/NZzf0/C8lsVXxhdwMTGnv2XRowHwYDVR0jBBgwFoAU
          D/NZzf0/C8lsVXxhdwMTGnv2XRowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
          AQsFAAOBgQAQTRLXhUH8Io0qtbCmgqcajHBEgeQKV4pPLBeN1GCQFu+4AIvM9Rjo
          sGYYcv1gaqIJHJSe5fgFKnZFhC+eGqY4pP8HqBac7cRyS8Stj453UKwJtHuy/nie
          IPASYzJSUrk84YRHhkFTw7ZR388UUFbbh26TaH6OCa/g0njP2+gQDg==
          -----END CERTIFICATE-----
        '';
        steps = [
          {
            argv = ["@out@/bin/cert-to-efi-sig-list" "-g" "11111111-2222-3333-4444-555555555555" "certificate.pem" "certificate.esl"];
            exit_code = 0;
          }
          {
            argv = ["@out@/bin/sig-list-to-certs" "certificate.esl" "recovered"];
            exit_code = 0;
          }
          {
            argv = ["@python@" "-c" ''
              import pathlib, ssl
              expected = ssl.PEM_cert_to_DER_cert(pathlib.Path("certificate.pem").read_text())
              assert pathlib.Path("recovered-0.der").read_bytes() == expected
              print("efitools round trip passed")
            ''];
            exit_code = 0;
            stdout.exact = "efitools round trip passed\n";
            stderr.exact = "";
          }
        ];
        artifacts = [];
      };
      bad_input = {
        input = "An extraction request with neither an ESL path nor an output basename.";
        operation = "Invoke the EFI signature-list extractor without its required arguments.";
        expected = "Efitools rejects the incomplete request and prints its usage diagnostic.";
        files = {};
        steps = [
          {
            argv = ["@out@/bin/sig-list-to-certs"];
            exit_code = 1;
            observes_rejection = true;
          }
        ];
        artifacts = [];
      };
    };
  };

  ethtool = mkPythonDataProbe {
    package = "ethtool";
    primaryInput = "The packaged network-device inspection executable.";
    primaryOperation = "Request the tool's version without changing a device.";
    primaryExpected = "Ethtool identifies itself and returns success.";
    primaryScript = ''
      import subprocess
      result = subprocess.run(["@out@/sbin/ethtool", "--version"], capture_output=True, text=True)
      assert result.returncode == 0 and result.stdout.startswith("ethtool version ")
      print("ethtool data passed")
    '';
    badInput = "A command-line option that ethtool does not define.";
    badOperation = "Invoke ethtool with the unknown option.";
    badExpected = "Ethtool rejects the unrecognized option.";
    badScript = ''
      import subprocess, sys
      result = subprocess.run(["@out@/sbin/ethtool", "--aos-invalid-option"], capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      sys.stderr.write("ethtool rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  gsettings-desktop-schemas = mkPythonDataProbe {
    package = "gsettings-desktop-schemas";
    primaryInput = "The installed desktop-interface GSettings schema XML.";
    primaryOperation = "Parse the schema catalog and locate its color-scheme key.";
    primaryExpected = "The catalog contains org.gnome.desktop.interface with a typed color-scheme key.";
    primaryScript = ''
      import pathlib, xml.etree.ElementTree as ET
      roots = [ET.parse(path).getroot() for path in pathlib.Path("@out@/share/glib-2.0/schemas").glob("*.xml")]
      schemas = [schema for root in roots for schema in root.findall("schema")]
      interface = next(schema for schema in schemas if schema.get("id") == "org.gnome.desktop.interface")
      color_scheme = next(key for key in interface.findall("key") if key.get("name") == "color-scheme")
      assert color_scheme.get("type") == "s" and color_scheme.find("default") is not None
      print("gsettings-desktop-schemas data passed")
    '';
    badInput = "A request for a schema ID absent from the installed catalog.";
    badOperation = "Resolve the nonexistent schema through the parsed catalog.";
    badExpected = "The catalog lookup rejects the unknown schema ID.";
    badScript = ''
      import pathlib, sys, xml.etree.ElementTree as ET
      ids = {schema.get("id") for path in pathlib.Path("@out@/share/glib-2.0/schemas").glob("*.xml") for schema in ET.parse(path).getroot().findall("schema")}
      if "org.aos.nonexistent" in ids:
          raise SystemExit(2)
      sys.stderr.write("gsettings-desktop-schemas rejected invalid input\n")
      raise SystemExit(7)
    '';
  };

  gnu-efi = mkPythonDataProbe {
    package = "gnu-efi";
    primaryInput = "A C translation unit using GNU-EFI's public GUID and status types.";
    primaryOperation = "Compile it against the installed architecture headers and inspect both static libraries.";
    primaryExpected = "The headers compile and libefi plus libgnuefi are valid Unix archives.";
    primaryFiles."consumer.c" = ''
      #include <efi.h>

      EFI_STATUS qualification(EFI_GUID *guid) {
          return guid == 0 ? EFI_INVALID_PARAMETER : EFI_SUCCESS;
      }
    '';
    primaryScript = ''
      import pathlib, subprocess
      include = pathlib.Path("@out@/include/efi")
      architecture = next(path.parent for path in include.glob("*/efibind.h"))
      result = subprocess.run(["@cc@", "-I" + str(include), "-I" + str(architecture), "-c", "consumer.c", "-o", "consumer.o"], capture_output=True)
      assert result.returncode == 0, result.stderr
      assert pathlib.Path("@out@/lib/libefi.a").read_bytes()[:8] == b"!<arch>\n"
      assert pathlib.Path("@out@/lib/libgnuefi.a").read_bytes()[:8] == b"!<arch>\n"
      print("gnu-efi data passed")
    '';
    badInput = "A C translation unit requesting an EFI type that does not exist.";
    badOperation = "Compile it against the same installed headers.";
    badExpected = "The compiler rejects the unknown firmware type.";
    badFiles."invalid.c" = "#include <efi.h>\nAOS_MISSING_EFI_TYPE value;\n";
    badScript = ''
      import pathlib, subprocess, sys
      include = pathlib.Path("@out@/include/efi")
      architecture = next(path.parent for path in include.glob("*/efibind.h"))
      result = subprocess.run(["@cc@", "-I" + str(include), "-I" + str(architecture), "-c", "invalid.c", "-o", "invalid.o"], capture_output=True)
      if result.returncode == 0:
          raise SystemExit(2)
      sys.stderr.write("gnu-efi rejected invalid input\n")
      raise SystemExit(7)
    '';
  };
}
