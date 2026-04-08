##! nerdctl — Docker-compatible CLI for containerd
{
  mkGoPackage,
  fetchurl,
  fetchGoModules,
  bash,
  cni-plugins,
}:
let
  version = "2.2.1";
  src = fetchurl {
    urls = [
      "https://github.com/containerd/nerdctl/archive/v${version}/nerdctl-${version}.tar.gz"
    ];
    hash = "sha256-85w006KF4IfysoafBv6jQ9goWtm/uUF7nFtt1OeNb60=";
  };
in
mkGoPackage {
  pname = "nerdctl";
  inherit version src;

  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-TitWJFzldbNExet5WHAQMc+mDZzlI28fpAC8a1/0XVo=";
  };

  goPackage = "./cmd/nerdctl";
  goOutput = "nerdctl";
  ldflags = "-s -w -X github.com/containerd/nerdctl/v2/pkg/version.Version=v${version}";
  doCheck = false;

  runtimeDeps = [ cni-plugins ];

  postInstall = ''
        # Wrap nerdctl to set CNI_PATH
        mv "$out/bin/nerdctl" "$out/bin/.nerdctl-unwrapped"
        cat > "$out/bin/nerdctl" << WRAPPER
    #!${bash}/bin/bash
    export CNI_PATH="${cni-plugins}/bin"
    exec "\$(dirname "\$0")/.nerdctl-unwrapped" "\$@"
    WRAPPER
        chmod +x "$out/bin/nerdctl"
  '';

  checks =
    {
      testing,
      self,
      pkgs,
    }:
    {
      version = testing.mkToolCheck {
        pname = "tool-nerdctl";
        tool = self;
        command = "nerdctl --version";
      };
    };

  meta = {
    description = "nerdctl — Docker-compatible CLI for containerd";
    homepage = "https://github.com/containerd/nerdctl";
    license = "Apache-2.0";
  };
}
