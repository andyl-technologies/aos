##! inetutils — GNU network utility suite
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  ncurses,
  libxcrypt,
  perl,
}: let
  version = "2.8";
in
  mkDerivation {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "inetutils";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Ping reports one transmitted and one received packet.";
        "files" = {};
        "input" = "One ICMP echo request addressed to the IPv4 loopback interface.";
        "operation" = "Send and receive the request through GNU ping.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess\nresult = subprocess.run([\"@out@/bin/ping\", \"-c\", \"1\", \"127.0.0.1\"], capture_output=True, text=True)\nassert result.returncode == 0 and \"1 packets transmitted\" in result.stdout and \"1 packets received\" in result.stdout, (result.returncode, result.stdout, result.stderr)\nprint(\"inetutils operation passed\")\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "inetutils operation passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Ping rejects the unsupported option.";
        "files" = {};
        "input" = "A ping invocation containing an unsupported option.";
        "operation" = "Parse the invalid option without resolving or contacting a host.";
        "steps" = [
          {
            "argv" = [
              "@python@"
              "-c"
              "import subprocess, sys\nresult = subprocess.run([\"@out@/bin/ping\", \"--aos-invalid-option\"], capture_output=True, text=True)\nassert result.returncode != 0, (result.returncode, result.stdout, result.stderr)\nsys.stderr.write(\"inetutils rejected invalid input\\n\")\nraise SystemExit(7)\n"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "inetutils rejected invalid input\n";
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
        "https://ftpmirror.gnu.org/gnu/inetutils/inetutils-${version}.tar.gz"
        "https://ftp.gnu.org/gnu/inetutils/inetutils-${version}.tar.gz"
      ];
      hash = "sha256-V7PPT3dVWZKIHluioJpjsFqixWNCpg7UMFtfRZODkLU=";
    };

    buildDeps = [gnumake perl];
    runtimeDeps = [ncurses libxcrypt];
    propagatedDeps = [];
    abilities = ./_inetutils;
    configureFlags = "--with-ncurses-include-dir=${ncurses}/include";
    # Inetutils 2.8 adds -Wno-format, which conflicts with the stdenv's
    # mandatory -Wformat-security hardening. Keep format checking enabled.
    makeFlags = "WARN_CFLAGS=-Wformat";

    postPatch = ''
      # Store paths cannot carry effective setuid permissions. A system module
      # supplies the required ping privilege at activation time.
      sed -i 's/^SUIDMODE = -o root -m 4755$/SUIDMODE = -m 0755/' ping/Makefile.in
      sed -i 's/^SUIDMODE = -o root -m 4755$/SUIDMODE = -m 0755/' src/Makefile.in

      grep -rlZ -e '^#! */usr/bin/perl' -e '^#! */usr/bin/env perl' . \
        | while IFS= read -r -d "" file; do
          sed -i "1s|^#!.*|#!${perl}/bin/perl|" "$file"
        done
      grep -rlZ -e '^#! */bin/sh' -e '^#! */bin/bash' -e '^#! */usr/bin/env' . \
        | while IFS= read -r -d "" file; do
          sed -i "1s|^#!.*|#!$CONFIG_SHELL|" "$file"
        done
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-inetutils";
        tool = self;
        command = "ping --version && traceroute --version && telnet --version && ftp --version";
      };
    };

    meta = {
      description = "GNU collection of common network programs";
      homepage = "https://www.gnu.org/software/inetutils/";
      license = "GPL-3.0-or-later";
    };
  }
