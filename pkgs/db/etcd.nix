##! etcd — Distributed key-value store
{
  mkDerivation,
  fetchurl,
  fetchGoModules,
  buildPackages,
}: let
  version = "3.5.21";
  src = fetchurl {
    urls = [
      "https://github.com/etcd-io/etcd/archive/v${version}/etcd-${version}.tar.gz"
    ];
    hash = "sha256-dtf8r+T8yVf81FZxImuZLBbl9eckk13qnfAZCsKxNIE=";
  };

  serverModules = fetchGoModules {
    inherit src;
    name = "etcd-server-modules";
    sourceRoot = "etcd-${version}/server";
    hash = "sha256-WQERZkiUy6qjGtnLwdJBUEaX+JF55DjqZPnPIDSpK7A=";
  };

  etcdctlModules = fetchGoModules {
    inherit src;
    name = "etcdctl-modules";
    sourceRoot = "etcd-${version}/etcdctl";
    hash = "sha256-/14AOtsHbSHKpy7R2GsLxyaDGhqTHTVPEfA/IuwdEYc=";
  };

  etcdutlModules = fetchGoModules {
    inherit src;
    name = "etcdutl-modules";
    sourceRoot = "etcd-${version}/etcdutl";
    hash = "sha256-VpQYa5/CLyzE6vva78hahzKWqRVE3BB4nhHly9SnuXg=";
  };
in
  mkDerivation {
    pname = "etcd";
    inherit version;
    inherit src;

    # The published Go package is Darwin-hosted in a cross package set and
    # cannot execute on the Linux builder.  Go's native compiler emits the
    # selected Darwin target directly.
    buildDeps = [buildPackages.go];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd etcd-${version}
        '';
      }
      {
        name = "build";
        script = ''
          export GOCACHE=$TMPDIR/go-cache
          export CGO_ENABLED=0
          export GOPROXY=off
          if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
            export GOOS="$AOS_GOOS"
            export GOARCH="$AOS_GOARCH"
          fi
          mkdir -p "$GOCACHE" bin

          cd server
          GOPATH="${serverModules}" GOFLAGS="-trimpath -mod=readonly" \
            go build -ldflags "-s -w \
              -X go.etcd.io/etcd/api/v3/version.GitSHA=v${version}" \
            -o ../bin/etcd .
          cd ..

          cd etcdctl
          GOPATH="${etcdctlModules}" GOFLAGS="-trimpath -mod=readonly" \
            go build -ldflags "-s -w" -o ../bin/etcdctl .
          cd ..

          cd etcdutl
          GOPATH="${etcdutlModules}" GOFLAGS="-trimpath -mod=readonly" \
            go build -ldflags "-s -w" -o ../bin/etcdutl .
          cd ..
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          install -m 755 bin/etcd bin/etcdctl bin/etcdutl $out/bin/
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-etcd";
        tool = self;
        command = "etcd --version";
      };
    };

    meta = {
      description = "etcd — distributed reliable key-value store";
      homepage = "https://etcd.io";
      license = "Apache-2.0";
    };
  }
