# OpenSSH — Secure shell client and server
{ mkDerivation, fetchurl, sources, versions, make, openssl, zlib }:

mkDerivation {
  name = "openssh-${versions.networking.openssh}";
  version = versions.networking.openssh;

  src = fetchurl {
    inherit (sources.openssh) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [ openssl zlib ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd openssh-${versions.networking.openssh}
      '';
    }
    { name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --sysconfdir=$out/etc/ssh \
          --with-ssl-dir=${openssl} \
          --with-zlib=${zlib} \
          --with-privsep-path=/var/empty/sshd \
          --with-privsep-user=sshd \
          --without-pam \
          --disable-strip
      '';
    }
    { name = "build";
      script = ''
        make -j$NIX_BUILD_CORES
      '';
    }
    { name = "install";
      script = ''
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
