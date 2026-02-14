# OpenSSH — Secure shell client and server
{
  mkDerivation,
  fetchurl,
  make,
  openssl,
  zlib,
}:

let
  version = "9.9p1";
in
mkDerivation {
  pname = "openssh";
  inherit version;

  src = fetchurl {
    urls = [
      "https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${version}.tar.gz"
    ];
    hash = "sha256-s0P7zb/4fxWxmG5uFdbU/Jp9NgZr5rf7UHCHuo+WbAI=";
  };

  buildDeps = [ make ];
  runtimeDeps = [
    openssl
    zlib
  ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd openssh-${version}
      '';
    }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --sysconfdir=$out/etc/ssh \
          --with-ssl-dir=${openssl} \
          --with-zlib=${zlib} \
          --with-privsep-path=$out/var/empty/sshd \
          --with-privsep-user=sshd \
          --without-pam \
          --disable-strip
      '';
    }
    {
      name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    {
      name = "install";
      script = ''
        # Strip setuid bits from install (not available in Nix sandbox)
        sed -i 's/-m 4711/-m 0755/g' Makefile
        make install
      '';
    }
  ];

  meta = {
    description = "OpenSSH — secure shell connectivity tools";
    homepage = "https://www.openssh.com";
    license = "BSD-2-Clause";
  };
}
