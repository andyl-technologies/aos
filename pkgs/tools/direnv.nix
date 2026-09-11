##! direnv — Per-directory environment manager
{
  mkGoPackage,
  fetchGoModules,
  fetchurl,
  bash,
}: let
  version = "2.37.1";
  src = fetchurl {
    urls = ["https://github.com/direnv/direnv/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-QUL7tmHzIYkT+sCNMnxBXoez5mvQlTGFKU/48yKOrSQ=";
  };
  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-ituvkJ3AAGxZPx6/3HXt9bKjmIFQ3AJ4p0nWGj/79pM=";
  };
in
  mkGoPackage {
    pname = "direnv";
    inherit version src goModules;
    goPackage = ".";
    goOutput = "direnv";
    doCheck = false;
    runtimeDeps = [bash];
    postInstall = ''
      # Loading an approved .envrc executes Bash as part of direnv's runtime.
      mkdir -p "$out/libexec"
      mv "$out/bin/direnv" "$out/libexec/direnv"
      cat > "$out/bin/direnv" <<EOF
      #!${bash}/bin/bash
      export PATH="${bash}/bin\''${PATH:+:}\$PATH"
      exec "$out/libexec/direnv" "\$@"
      EOF
      chmod +x "$out/bin/direnv"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-direnv";
        tool = self;
        command = "direnv version";
      };
    };
    meta = {
      description = "Loads and unloads environment variables by directory";
      homepage = "https://direnv.net/";
      license = "MIT";
      mainProgram = "direnv";
    };
  }
