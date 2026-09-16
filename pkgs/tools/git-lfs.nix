##! git-lfs — Git extension for large files
{
  lib,
  mkGoPackage,
  fetchGoModules,
  fetchurl,
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
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      role = "public-package";
    };
    pname = "git-lfs";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Git LFS emits the exact canonical pointer document.";
        "files" = {
          "object.bin" = "AOS large object\n";
        };
        "input" = "A fixed 17-byte object to encode as a Git LFS pointer.";
        "operation" = "Generate the pointer with git-lfs pointer --file.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/git-lfs"
              "pointer"
              "--file=object.bin"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "Git LFS pointer for object.bin\n\n";
            };
            "stdout" = {
              "exact" = "version https://git-lfs.github.com/spec/v1\noid sha256:87adda3b1671602f7e758e5ed8c1dfa5f1dffe89e9bcfbd7540b6c4ffb6d94a4\nsize 17\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Git LFS rejects the malformed pointer with status 1.";
        "files" = {
          "invalid.pointer" = "version https://git-lfs.github.com/spec/v1\noid sha256:87adda3b1671602f7e758e5ed8c1dfa5f1dffe89e9bcfbd7540b6c4ffb6d94a4\nsize seventeen\n";
        };
        "input" = "A pointer document with a nonnumeric size.";
        "operation" = "Validate the malformed document in strict pointer-check mode.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/git-lfs"
              "pointer"
              "--check"
              "--strict"
              "--file=invalid.pointer"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version src goModules;
    goPackage = ".";
    goOutput = "git-lfs";
    ldflags = "-s -w -X github.com/git-lfs/git-lfs/v3/config.Vendor=${version}";
    doCheck = false;
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
