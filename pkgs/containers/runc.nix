##! runc — OCI container runtime
{
  mkDerivation,
  fetchurl,
  make,
  pkg-config,
  libseccomp,
  libselinux,
}:

let
  version = "1.2.4";
in
mkDerivation {
  pname = "runc";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/opencontainers/runc/archive/v${version}/runc-${version}.tar.gz"
    ];
    hash = "sha256-l4XBRMl5dLUrYJG3p5FotzaB/1dLyEOLRPP1+MES8XE=";
  };

  buildDeps = [
    make
    pkg-config
  ];
  runtimeDeps = [
    libseccomp
    libselinux
  ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd runc-${version}
      '';
    }
    {
      name = "setup-gopath";
      script = ''
        export GOPATH=$TMPDIR/go
        mkdir -p $GOPATH/src/github.com/opencontainers
        ln -sf $PWD $GOPATH/src/github.com/opencontainers/runc
      '';
    }
    {
      name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=1
        export BUILDTAGS="seccomp selinux"
        export CGO_CFLAGS="-I${libseccomp}/include -I${libselinux}/include"
        export CGO_LDFLAGS="-L${libseccomp}/lib -L${libselinux}/lib"
        make SHELL="$CONFIG_SHELL" BUILDTAGS="$BUILDTAGS" \
          COMMIT=v${version} \
          static
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/sbin
        install -m 755 runc $out/sbin/runc
      '';
    }
  ];

  meta = {
    description = "runc — CLI tool for spawning and running OCI containers";
    homepage = "https://github.com/opencontainers/runc";
    license = "Apache-2.0";
  };
}
