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
  version = "0.16.0";
in
  mkGoPackage {
    pname = "opkssh";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/openpubkey/opkssh/archive/v${version}/opkssh-${version}.tar.gz"
      ];
      hash = "sha256-t8Mmsk1v6XBW1Fny1e9+r7JYkLcCeVN3RqNoRn/i3Ds=";
    };

    goModules = fetchGoModules {
      src = fetchurl {
        urls = [
          "https://github.com/openpubkey/opkssh/archive/v${version}/opkssh-${version}.tar.gz"
        ];
        hash = "sha256-t8Mmsk1v6XBW1Fny1e9+r7JYkLcCeVN3RqNoRn/i3Ds=";
      };
      hash = "sha256-p9FvUta7eqkc8y8zzhwnAVAKEbdX4aWE6L6f/F+hEKQ=";
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
