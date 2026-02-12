# runc — OCI container runtime
{ mkDerivation, fetchurl, sources, versions, make, pkg-config,
  libseccomp, libselinux }:

mkDerivation {
  name = "runc-${versions.kubernetes.runc}";
  version = versions.kubernetes.runc;

  src = fetchurl {
    inherit (sources.runc) url hash;
  };

  buildDeps = [ make pkg-config ];
  runtimeDeps = [ libseccomp libselinux ];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd runc-${versions.kubernetes.runc}
      '';
    }
    { name = "setup-gopath";
      script = ''
        export GOPATH=$TMPDIR/go
        mkdir -p $GOPATH/src/github.com/opencontainers
        ln -sf $PWD $GOPATH/src/github.com/opencontainers/runc
      '';
    }
    { name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=1
        export BUILDTAGS="seccomp selinux"
        export CGO_CFLAGS="-I${libseccomp}/include -I${libselinux}/include"
        export CGO_LDFLAGS="-L${libseccomp}/lib -L${libselinux}/lib"
        make BUILDTAGS="$BUILDTAGS" \
          COMMIT=v${versions.kubernetes.runc} \
          static
      '';
    }
    { name = "install";
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
