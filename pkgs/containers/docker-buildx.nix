##! docker-buildx — Docker BuildKit CLI plugin
{
  mkGoPackage,
  fetchGoModules,
  fetchurl,
}: let
  version = "0.31.1";
  src = fetchurl {
    urls = ["https://github.com/docker/buildx/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-LyBpVUMFyWWd1KK06xDHrquX5S6Jz+7aB/DAxD0Z7oA=";
  };
  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-a7b0+AMgOja34Cl/Rck3JLY9MeZ5k6U+09b5LnnkoTo=";
  };
in
  mkGoPackage {
    pname = "docker-buildx";
    inherit version src goModules;
    goPackage = "./cmd/buildx";
    goOutput = "docker-buildx";
    ldflags = "-s -w -X github.com/docker/buildx/version.Package=github.com/docker/buildx -X github.com/docker/buildx/version.Version=v${version}";
    doCheck = false;

    postInstall = ''
      mkdir -p "$out/libexec/docker/cli-plugins"
      ln -s "$out/bin/docker-buildx" "$out/libexec/docker/cli-plugins/docker-buildx"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-docker-buildx";
        tool = self;
        command = "docker-buildx version";
      };
    };

    meta = {
      description = "Docker CLI plugin for extended BuildKit capabilities";
      homepage = "https://github.com/docker/buildx";
      license = "Apache-2.0";
      mainProgram = "docker-buildx";
    };
  }
