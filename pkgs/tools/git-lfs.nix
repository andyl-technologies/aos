##! git-lfs — Git extension for large files
{
  mkGoPackage,
  fetchGoModules,
  fetchurl,
  bash,
  git,
}: let
  version = "3.8.0";
  src = fetchurl {
    urls = ["https://github.com/git-lfs/git-lfs/archive/refs/tags/v${version}.tar.gz"];
    hash = "sha256-oS7PwX6+4ALR9qzKeUQgKdQcv15bS6ngIkntlt4gMA8=";
  };
  goModules = fetchGoModules {
    inherit src;
    hash = "sha256-e/oSsIW+Qi67mpl6f22TjPxDpwqZ894w7hgtstarwdk=";
  };
in
  mkGoPackage {
    pname = "git-lfs";
    inherit version src goModules;
    goPackage = ".";
    goOutput = "git-lfs";
    ldflags = "-s -w -X github.com/git-lfs/git-lfs/v3/config.Vendor=${version}";
    doCheck = false;
    runtimeDeps = [bash git];
    postInstall = ''
      # LFS invokes Git for repository configuration and filter operations.
      mkdir -p "$out/libexec"
      mv "$out/bin/git-lfs" "$out/libexec/git-lfs"
      cat > "$out/bin/git-lfs" <<EOF
      #!${bash}/bin/bash
      export PATH="${git}/bin\''${PATH:+:}\$PATH"
      exec "$out/libexec/git-lfs" "\$@"
      EOF
      chmod +x "$out/bin/git-lfs"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-git-lfs";
        tool = self;
        command = "git-lfs version";
      };
    };
    meta = {
      description = "Git extension for versioning large files";
      homepage = "https://git-lfs.com/";
      license = "MIT";
      mainProgram = "git-lfs";
    };
  }
