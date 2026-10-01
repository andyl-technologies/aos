{
  pkgs,
  lib,
}: let
  scrub = import ./_rust-scrub.nix {inherit lib;};
  spaces = count: builtins.concatStringsSep "" (builtins.genList (_: " ") count);
  fixtures = [
    {
      source = "";
      expected = "";
    }
    {
      source = "fn visible() {}";
      expected = "fn visible() {}";
    }
    {
      source = "// hidden\nfn visible() {}";
      expected = spaces 9 + "\nfn visible() {}";
    }
    {
      source = "fn /* outer\n/* inner */\nend */ tail";
      expected = "fn " + spaces 8 + "\n" + spaces 11 + "\n" + spaces 6 + " tail";
    }
    {
      source = "let x = \"a\\\"b\";\n";
      expected = "let x = " + spaces 6 + ";\n";
    }
    {
      source = "let x = \"one\ntwo\";\nnext();";
      expected = "let x = " + spaces 4 + "\n" + spaces 4 + ";\nnext();";
    }
    {
      source = "\"// /* */\" fn visible() {}";
      expected = spaces 10 + " fn visible() {}";
    }
    {
      source = "let x = r#\"one \"quote\" // hidden\"#;\nnext();";
      expected = "let x = " + spaces 26 + ";\nnext();";
    }
    {
      source = "r##\"one\n\"# still inside\"##\nnext();";
      expected = spaces 7 + "\n" + spaces 18 + "\nnext();";
    }
  ];
  largeSource = builtins.concatStringsSep "\n" (builtins.genList (_: "// hidden") 2000) + "\nfn visible() {}";
  largeResult = scrub largeSource;
in
  assert builtins.all (fixture: scrub fixture.source == fixture.expected) fixtures;
  assert builtins.stringLength largeResult == builtins.stringLength largeSource;
  assert lib.hasSuffix "\nfn visible() {}" largeResult;
    pkgs.mkDerivation {
      pname = "crucible-rust-source-scrub";
      version = "0";
      src = null;
      phases = [
        {
          name = "check";
          script = ''
            mkdir -p "$out"
            printf 'PASS\n' > "$out/result"
          '';
        }
      ];
    }
