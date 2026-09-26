##! Generate manual pages from command help output.
{
  lib,
  mkDerivation,
  fetchurl,
  buildPackages,
  perl,
  perl-locale-gettext,
  gettext,
}: let
  version = "1.49.3";
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
    pname = "help2man";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "The installed help2man command as a documented executable.";
        operation = "Generate a manual page from its help and version output.";
        expected = "The page contains a help2man title and NAME section.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import os
                import subprocess

                environment = os.environ.copy()
                environment["LC_ALL"] = "C"
                executable = "@out@/bin/help2man"
                result = subprocess.run(
                    [executable, "--no-info", executable],
                    capture_output=True,
                    text=True,
                    env=environment,
                )
                assert result.returncode == 0, result.stderr
                assert ".TH HELP2MAN" in result.stdout
                assert ".SH NAME" in result.stdout
                print("help2man generated manual page")
              ''
            ];
            exit_code = 0;
            stdout.exact = "help2man generated manual page\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A missing executable.";
        operation = "Request help and version output from that executable.";
        expected = "Help2man rejects the missing executable with status 127.";
        files = {};
        artifacts = [];
        steps = [
          {
            argv = [
              "@python@"
              "-c"
              ''
                import os
                import subprocess

                environment = os.environ.copy()
                environment["LC_ALL"] = "C"
                result = subprocess.run(
                    ["@out@/bin/help2man", "--no-info", "./qualification-missing"],
                    capture_output=True,
                    text=True,
                    env=environment,
                )
                assert result.returncode == 127, result.stderr
                assert "can't get `--help' info" in result.stderr
                print("help2man rejected missing executable")
              ''
            ];
            exit_code = 0;
            observes_rejection = true;
            stdout.exact = "help2man rejected missing executable\n";
            stderr.exact = "";
          }
        ];
      };
    };
    inherit version;
    src = fetchurl {
      urls = ["https://ftp.gnu.org/gnu/help2man/help2man-${version}.tar.xz"];
      hash = "0kzxla1w0w4z5la255lg9q51wy3qx8f1b0i6gbhaz9pcybg4yzjd";
    };

    buildDeps = [buildPackages.gnumake buildPackages.perl buildPackages.perl-locale-gettext buildPackages.gettext];
    runtimeDeps = [perl perl-locale-gettext gettext];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd help2man-${version}
        '';
      }
      {
        name = "configure";
        script = ''
          export PERL5LIB=${buildPackages.perl-locale-gettext}/lib/perl5
          $CONFIG_SHELL ./configure $configureFlags --prefix="$out" --enable-nls
        '';
      }
      {
        name = "build";
        script = ''
          make -j"$NIX_BUILD_CORES" SHELL="$CONFIG_SHELL"
        '';
      }
      {
        name = "install";
        script = ''
          make install SHELL="$CONFIG_SHELL"
          # Bind the installed script to its interpreter and translation module.
          sed -i '1c#!${perl}/bin/perl' "$out/bin/help2man"
          sed -i '2iuse lib "${perl-locale-gettext}/lib/perl5";' "$out/bin/help2man"
          mkdir -p "$out/share/licenses/help2man"
          cp COPYING "$out/share/licenses/help2man/"
        '';
      }
    ];

    meta = {
      description = "Manual page generator with translated help support";
      homepage = "https://www.gnu.org/software/help2man/";
      license = "GPL-3.0-or-later";
    };
  }
