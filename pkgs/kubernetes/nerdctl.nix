##! nerdctl — Docker-compatible CLI for containerd
{
  mkGoPackage,
  fetchurl,
  fetchGoModules,
  cni-plugins,
}:

let
  version = "1.7.7";
  src = fetchurl {
    urls = [
      "https://github.com/containerd/nerdctl/archive/v${version}/nerdctl-${version}.tar.gz"
    ];
    hash = "sha256-vN3y7jrSvIStxeIH+XFXmY/pc5EsfR3ZVAvUu0oHaY0=";
  };
in
mkGoPackage {
  pname = "nerdctl";
  inherit version src;

  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-D5X713LItdJ5KMomvi3JsrPzFQh8h+U/W4zC3K8d0b4=";
  };

  goPackage = "./cmd/nerdctl";
  goOutput = "nerdctl";
  ldflags = "-s -w -X github.com/containerd/nerdctl/pkg/version.Version=v${version}";
  doCheck = false;

  runtimeDeps = [ cni-plugins ];

  postInstall = ''
        # Wrap nerdctl to set CNI_PATH
        mv "$out/bin/nerdctl" "$out/bin/.nerdctl-unwrapped"
        cat > "$out/bin/nerdctl" << WRAPPER
    #!/bin/sh
    export CNI_PATH="${cni-plugins}/bin"
    exec "\$(dirname "\$0")/.nerdctl-unwrapped" "\$@"
    WRAPPER
        chmod +x "$out/bin/nerdctl"
  '';

  meta = {
    description = "nerdctl — Docker-compatible CLI for containerd";
    homepage = "https://github.com/containerd/nerdctl";
    license = "Apache-2.0";
  };
}
