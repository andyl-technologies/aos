##! nmap — Network exploration and security scanner
{
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
