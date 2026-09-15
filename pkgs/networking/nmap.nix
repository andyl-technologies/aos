##! nmap — Network exploration and security scanner
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  libpcap,
  openssl,
  lua,
  pcre2,
  liblinear,
  libssh2,
  zlib,
  python3,
}: let
  version = "7.99";
in
  mkDerivation {
    pname = "nmap";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [
          {
            "path" = "received.txt";
            "text" = "answer=42\n";
          }
        ];
        "expected" = "Ncat transports the exact input through the local socket.";
        "files" = {};
        "input" = "The text answer=42 sent over a local Unix-domain socket.";
        "operation" = "Listen and connect through Ncat, then capture the transferred bytes.";
        "steps" = [
          {
            "argv" = [
              "@bash@"
              "-c"
              "set -eu\n\"@out@/bin/ncat\" -l -U channel.sock > received.txt &\nlistener=$!\nfor attempt in 1 2 3 4 5 6 7 8 9 10; do\n  test -S channel.sock && break\n  read -r -t 0.05 ignored || true\ndone\nprintf 'answer=42\\n' | \"@out@/bin/ncat\" -U channel.sock\nwait \"$listener\"\n"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Ncat rejects the incompatible modes with status 2.";
        "files" = {};
        "input" = "A request to listen and perform zero-I/O scanning simultaneously.";
        "operation" = "Parse the conflicting flags through Ncat.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/ncat"
              "-l"
              "-z"
            ];
            "exit_code" = 2;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "Ncat: Services designed for LISTENING can't be used with -z QUITTING.\n";
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
      urls = ["https://nmap.org/dist/nmap-${version}.tar.bz2"];
      hash = "sha256-31Ekkv/RCOU6J6BvJthjW76J4OVpRV3I/+8FjANdUbI=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps = [libpcap openssl lua pcre2 liblinear libssh2 zlib python3];
    propagatedDeps = [];
    # Ndiff is installed directly below because AOS does not yet package the
    # generic Python wheel frontend used by Nmap's upstream install target.
    # Zenmap is a separate graphical application and requires a GTK stack;
    # this package provides Nmap's complete command-line tool suite.
    configureFlags = "--with-liblua=${lua} --without-ndiff --without-zenmap";

    postInstall = ''
      install -Dm444 nselib/data/passwords.lst "$out/share/wordlists/nmap.lst"

      install -Dm444 ndiff/ndiff.py "$out/lib/nmap/ndiff.py"
      install -Dm755 ndiff/scripts/ndiff "$out/bin/ndiff"
      # Nix store outputs are immutable, but a single-user store may be owned
      # by the build user and fail Ndiff's conventional Unix ownership check.
      sed -i \
        -e '1c#!${python3}/bin/python3' \
        -e "s@^INSTALL_LIB = None@INSTALL_LIB = '$out/lib/nmap'@" \
        -e 's@^if INSTALL_LIB is not None and is_secure_dir(INSTALL_LIB):@if INSTALL_LIB is not None:@' \
        "$out/bin/ndiff"
      install -Dm444 ndiff/docs/ndiff.1 "$out/share/man/man1/ndiff.1"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-nmap";
        tool = self;
        command = "nmap --version && ndiff -h >/dev/null";
      };
    };

    meta = {
      description = "Network exploration and security auditing utility";
      homepage = "https://nmap.org/";
      license = "NPSL-0.95";
      mainProgram = "nmap";
    };
  }
