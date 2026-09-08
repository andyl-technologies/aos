##! bottom — Graphical process and system monitor
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
}: let
  # Bottom 0.14 requires Rust 1.95 or newer.
  version = "0.14.9";
  src = fetchurl {
    urls = ["https://github.com/ClementTsang/bottom/archive/refs/tags/${version}.tar.gz"];
    hash = "sha256-HbuUDHY/tYO34cffoWW3PtmgunEucsyXMRxbHAmNW3I=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-98cmahv5kYjNHW8lEWDTtWzOPnnX4RTdq3ZQ9Xm4Zb0=";
  };
in
  mkCargoPackage {
    pname = "bottom";
    inherit version src cargoDeps;
    doCheck = false;
    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-bottom";
        tool = self;
        command = "btm --version";
      };
    };
    meta = {
      description = "Graphical process and system monitor";
      homepage = "https://github.com/ClementTsang/bottom";
      license = "MIT";
      mainProgram = "btm";
    };
  }
