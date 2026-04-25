##! opkssh — OpenPubkey SSH authentication
##!
##! Enables SSH authentication using OpenID Connect (OIDC) identities.
##! Users authenticate via their identity provider (Google, Azure, GitLab)
##! and receive ephemeral SSH keys containing PK Tokens. The SSH daemon
##! verifies these tokens via an AuthorizedKeysCommand.
{
  mkGoPackage,
  fetchurl,
  fetchGoModules,
}: let
  version = "0.13.0";
in
  mkGoPackage {
    pname = "opkssh";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/openpubkey/opkssh/archive/v${version}/opkssh-${version}.tar.gz"
      ];
      hash = "sha256-ewGAyL2g3xXGJ6maEF5B921CHBmo9/jyVtp+sv7JkbU=";
    };

    goModules = fetchGoModules {
      src = fetchurl {
        urls = [
          "https://github.com/openpubkey/opkssh/archive/v${version}/opkssh-${version}.tar.gz"
        ];
        hash = "sha256-ewGAyL2g3xXGJ6maEF5B921CHBmo9/jyVtp+sv7JkbU=";
      };
      hash = "sha256-JLVeQ1HlNnH5QFwMfSX/MBGqFPCyCcZfZGL7t1KjIOE=";
    };

    goPackage = ".";
    goOutput = "opkssh";
    ldflags = "-s -w -X main.Version=${version}";
    doCheck = false;

    checks = {
      testing,
      self,
      pkgs,
    }: {
      version = testing.mkToolCheck {
        pname = "tool-opkssh";
        tool = self;
        command = "opkssh --version";
      };
    };

    meta = {
      description = "opkssh — SSH authentication using OpenID Connect identities";
      homepage = "https://github.com/openpubkey/opkssh";
      license = "Apache-2.0";
    };
  }
