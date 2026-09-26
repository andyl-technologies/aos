##! Markdown book renderer with search, live serving, and file watching.
{
  lib,
  mkCargoPackage,
  fetchurl,
  fetchCargoVendor,
  stdenv,
}: let
  version = "0.5.4";
  src = fetchurl {
    urls = ["https://github.com/rust-lang/mdBook/archive/refs/tags/v${version}.tar.gz"];
    hash = "0jslymmwl5ha9mm69rgga1v0iv8fqlk7ikpnnr9pvirm1hri8xhh";
  };
in
  mkCargoPackage {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "mdbook";
    qualification.packageProbe = lib.qualification.commandProbe {
      primary = {
        input = "A one-chapter Markdown book.";
        operation = "Build the book as HTML.";
        expected = "The generated chapter contains the rendered title and text.";
        files = {
          "book/book.toml" = ''
            [book]
            title = "AOS Qualification"
          '';
          "book/src/SUMMARY.md" = ''
            # Summary

            - [Chapter](chapter.md)
          '';
          "book/src/chapter.md" = ''
            # Chapter

            AOS qualification text.
          '';
        };
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/mdbook" "build" "book" "-d" "rendered"];
            exit_code = 0;
            stdout.exact = "";
          }
          {
            argv = [
              "@python@"
              "-c"
              ''
                from pathlib import Path

                html = Path("rendered/chapter.html").read_text()
                assert '<h1 id="chapter"><a class="header" href="#chapter">Chapter</a></h1>' in html
                assert "<p>AOS qualification text.</p>" in html
                print("mdbook HTML rendering passed")
              ''
            ];
            exit_code = 0;
            stdout.exact = "mdbook HTML rendering passed\n";
            stderr.exact = "";
          }
        ];
      };
      badInput = {
        input = "A book with an unclosed TOML table header.";
        operation = "Attempt to build the malformed book.";
        expected = "mdBook rejects the invalid configuration.";
        files."book/book.toml" = "[book\n";
        artifacts = [];
        steps = [
          {
            argv = ["@out@/bin/mdbook" "build" "book" "-d" "rendered"];
            exit_code = 101;
            observes_rejection = true;
            stdout.exact = "";
          }
        ];
      };
    };
    inherit version src;
    cargoDeps = fetchCargoVendor {
      inherit src;
      name = "mdbook-${version}-vendor";
      hash = "sha256-OmlcPZuQ1RbyFrF5tuztucgtCA544UHJxEaXh/mfSHQ=";
    };
    cargoFlags = "-p mdbook";
    cargoTestFlags = "--workspace";
    doCheck = !stdenv.isCross;
    postInstall = ''
      mkdir -p "$out/share/licenses/mdbook"
      cp LICENSE "$out/share/licenses/mdbook/"
    '';
    meta = {
      description = "Create searchable HTML books from Markdown";
      homepage = "https://rust-lang.github.io/mdBook/";
      license = "MPL-2.0";
      mainProgram = "mdbook";
    };
  }
