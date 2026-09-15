##! OpenJDK 10 — bootstrap chain intermediate (built with openjdk-9)
{
  lib,
  mkDerivation,
  fetchurl,
  stdenv,
  buildPackages,
  gnumake,
  autoconf,
  bash,
  which,
  zip,
  unzip,
  gawk,
  coreutils,
  zlib,
  alsa-lib,
  binutils,
  cups,
  file,
  fontconfig,
  freetype,
  xorg-stubs,
  bootstrapTools,
  krb5,
  java-native-foundation,
  openjdk-9,
}: let
  mkOpenJDKBootstrap = import ./_openjdk-bootstrap.nix {
    inherit
      fetchurl
      mkDerivation
      stdenv
      buildPackages
      gnumake
      autoconf
      bash
      which
      zip
      unzip
      gawk
      coreutils
      zlib
      alsa-lib
      binutils
      cups
      file
      fontconfig
      freetype
      xorg-stubs
      bootstrapTools
      krb5
      ;
  };
in
  mkOpenJDKBootstrap {
  qualification.packageProbe = lib.qualification.commandProbe {
    "primary" = {
      "artifacts" = [];
      "expected" = "The packaged toolchain produces runnable bytecode that prints 42.";
      "files" = {
        "Answer.java" = "public final class Answer {\n    public static void main(String[] arguments) {\n        System.out.println(19 + 23);\n    }\n}\n";
      };
      "input" = "A Java class that prints the sum of 19 and 23.";
      "operation" = "Compile the class with javac and execute it with java.";
      "steps" = [
        {
          "argv" = [
            "@out@/bin/javac"
            "Answer.java"
          ];
          "exit_code" = 0;
          "stderr" = {
            "exact" = "";
          };
          "stdout" = {
            "exact" = "";
          };
        }
        {
          "argv" = [
            "@out@/bin/java"
            "-cp"
            "."
            "Answer"
          ];
          "exit_code" = 0;
          "stderr" = {
            "exact" = "";
          };
          "stdout" = {
            "exact" = "42\n";
          };
        }
      ];
    };
    "badInput" = {
      "artifacts" = [];
      "expected" = "javac rejects the source with its compilation-failure status.";
      "files" = {
        "Invalid.java" = "public final class Invalid {\n    public static int answer() { return; }\n}\n";
      };
      "input" = "A Java class whose return statement has no expression.";
      "operation" = "Compile the malformed class with javac.";
      "steps" = [
        {
          "argv" = [
            "@out@/bin/javac"
            "Invalid.java"
          ];
          "exit_code" = 1;
          "observes_rejection" = true;
        }
      ];
    };
  };

    major = 10;
    version = "10.0.2";
    build = "13";
    srcHash = "sha256-Oc4SONWyBm/+HBoJ2HwXB2Ywn+GCkPJ6SrfRWETTTcE=";
    prevJdk = openjdk-9;
    extraDarwinFrameworks = [java-native-foundation];
    # JDK-8299435 records the matching javac failure: jrtfs iterates a mutable
    # ImageReader child list. Resolving entries during that traversal can
    # extend the same list, even in a single-job build.
    extraPatches = [./openjdk-patches/snapshot-jrt-directory-children-jdk10.patch];
  }
