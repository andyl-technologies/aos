##! docker-compose — Multi-container application CLI plugin
{
  mkGoPackage,
  fetchGoModules,
  fetchurl,
}: let
  # Compose 5.4 requires a Go patch release newer than the self-hosted AOS
  # toolchain; 5.3.1 retains the complete feature set on Go 1.26.0.
  version = "5.3.1";
  src = fetchurl {
    urls = ["https://github.com/docker/compose/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-GCPhsJxAgnef31zJ89hFO5Xbo9k5EFs5NmF1zhL9tsc=";
  };
  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-kg7iioXPoEonD7ZTfKMHFTUXiKgykM3rtgTFtW598xE=";
  };
in
  mkGoPackage {
    pname = "docker-compose";
    inherit version src goModules;
    goPackage = "./cmd";
    goOutput = "docker-compose";
    ldflags = "-s -w -X github.com/docker/compose/v5/internal.Version=${version}";
    doCheck = false;

    postInstall = ''
      mkdir -p "$out/libexec/docker/cli-plugins"
      ln -s "$out/bin/docker-compose" "$out/libexec/docker/cli-plugins/docker-compose"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-docker-compose";
        tool = self;
        command = "docker-compose version";
      };
    };

    meta = {
      description = "Defines and runs multi-container Docker applications";
      homepage = "https://github.com/docker/compose";
      license = "Apache-2.0";
      mainProgram = "docker-compose";
    };
  }
