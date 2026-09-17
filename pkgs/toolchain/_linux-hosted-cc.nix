##! Target-hosted C and C++ compiler wrapper for Linux.
##!
##! The cross stdenv wrapper executes on the scheduler and remains private to
##! package construction.  This wrapper executes on the selected Linux target
##! and binds the public hosted GCC, binutils, libc, and hardening defaults.
{
  lib,
  stdenv,
  buildPackages,
  bash,
  gcc,
  binutils,
}: let
  defaultHardeningFlags =
    [
      "stackprotector"
      "relro"
      "bindnow"
      "pie"
      "noexecstack"
      "fortify"
      "fortify3"
      "stackclashprotection"
      "format"
      "strictflexarrays3"
      "glibcxxassertions"
    ]
    ++ lib.optional stdenv.hostPlatform.isAarch64 "pacret";
  defaultHardening = lib.hardening.effectiveString {
    name = "linux-hosted-cc-wrapper-default";
    platform = stdenv.hostPlatform;
    defaultFlags = defaultHardeningFlags;
    hardeningEnable = [];
    hardeningDisable = [];
  };
  wrapper = import ../../stdenv/cc-wrapper.nix {
    cc = gcc;
    libc = stdenv.glibc;
    binutils_ = binutils;
    shell = "${bash}/bin/bash";
    coreutils = buildPackages.coreutils;
    builderShell = stdenv.shell;
    builderCoreutils = buildPackages.coreutils;
    buildPlatform = stdenv.buildPlatform;
    executionPlatform = stdenv.hostPlatform;
    hostPlatform = stdenv.hostPlatform;
    storeDir = stdenv.storeDir;
    inherit defaultHardening;
  };
in
  wrapper
  // {
    constraints = wrapper.constraints // {build = stdenv.buildPlatform.constraints;};
  }
