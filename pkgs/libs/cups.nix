##! CUPS — Common UNIX Printing System (headers for compilation)
{
  lib,
  mkDerivation,
  fetchurl,
}: let
  version = "2.4.19";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "cups";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "The public API returns the expected value and the consumer prints the fixed success line.";
        "files" = {
          "primary.c" = "#include <stdio.h>\n#include <string.h>\n#include <cups/http.h>\n\nint main(void) {\n    char scheme[16], username[16], host[64], resource[64];\n    int port = 0;\n    http_uri_status_t status = httpSeparateURI(\n        HTTP_URI_CODING_ALL,\n        \"ipp://printer.example:631/ipp/print\",\n        scheme, sizeof(scheme),\n        username, sizeof(username),\n        host, sizeof(host),\n        &port,\n        resource, sizeof(resource));\n    if (status != HTTP_URI_STATUS_OK\n        || strcmp(scheme, \"ipp\") != 0\n        || strcmp(host, \"printer.example\") != 0\n        || port != 631\n        || strcmp(resource, \"/ipp/print\") != 0) {\n        return 2;\n    }\n    return puts(\"cups api passed\") == EOF;\n}\n";
        };
        "input" = "An IPP printer URI containing a scheme, host, port, and resource.";
        "operation" = "Separate the URI into its components with libcups.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lcups"
              "-o"
              "primary"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "cups api passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "The public API rejects the malformed boundary and the consumer returns the fixed rejection status.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\n#include <cups/http.h>\n\nint main(void) {\n    char scheme[16], username[16], host[2], resource[64];\n    int port = 0;\n    http_uri_status_t status = httpSeparateURI(\n        HTTP_URI_CODING_ALL,\n        \"ipp://printer.example/ipp/print\",\n        scheme, sizeof(scheme),\n        username, sizeof(username),\n        host, sizeof(host),\n        &port,\n        resource, sizeof(resource));\n    if (status == HTTP_URI_STATUS_OK) {\n        return 2;\n    }\n    fputs(\"cups rejected invalid input\\n\", stderr);\n    return 7;\n}\n";
        };
        "input" = "A valid IPP URI and a destination buffer too small for its host.";
        "operation" = "Separate the URI into the undersized component buffers with libcups.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lcups"
              "-o"
              "bad-input"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "cups rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/OpenPrinting/cups/releases/download/v${version}/cups-${version}-source.tar.gz"
      ];
      hash = "sha256-ggmEsSpn+YcFeFquLdE0f+CsCXgoAB1Fg/9kV0rtY4k=";
    };

    buildDeps = [];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd cups-${version}
        '';
      }
      {
        name = "install";
        script = ''
          # Install public CUPS headers needed by OpenJDK and other packages
          mkdir -p $out/include/cups
          cp cups/*.h $out/include/cups/
        '';
      }
    ];

    meta = {
      description = "CUPS — Common UNIX Printing System (headers for compilation)";
      homepage = "https://openprinting.github.io/cups/";
      license = "Apache-2.0";
    };
  }
