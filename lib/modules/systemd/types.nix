# SPDX-License-Identifier: MIT
#
# Ported from nixpkgs for use in AOS.
#   Upstream path: nixos/lib/systemd-types.nix
#   Upstream rev:  6c9a78c09ff4d6c21d0319114873508a6ec01655
#
# Portions © 2003-2026 Eelco Dolstra and the Nixpkgs/NixOS contributors.
# Used under the MIT license; see nixpkgs' COPYING file for the full text.
#
# AOS adaptations (summary, spec §3.4):
#   - Top-level signature is `{ lib, systemdLib, systemdUnitOptions }`.
#     Upstream takes `{ lib, systemdUtils, pkgs }` — AOS passes the lib
#     and unit-options factories directly and does not need `pkgs`
#     because the dropped `initrdContents` / `initrdStorePath*` types
#     (see below) were its only consumers.
#   - `initrdStorePathModule`, `initrdStorePath`, `initrdContents`
#     dropped: these are initrd-builder concerns and AOS's tier-(i)
#     initrd module only needs a type tree for option typing, not a
#     way to copy store paths. Revisit when tier-(ii) lands (§11.3).
{
  lib,
  systemdLib,
  systemdUnitOptions,
}: let
  inherit
    (systemdLib)
    automountConfig
    makeUnit
    mountConfig
    pathConfig
    sliceConfig
    socketConfig
    stage1ServiceConfig
    stage2ServiceConfig
    targetConfig
    timerConfig
    unitConfig
    ;

  inherit
    (systemdUnitOptions)
    concreteUnitOptions
    stage1AutomountOptions
    stage1CommonUnitOptions
    stage1MountOptions
    stage1PathOptions
    stage1ServiceOptions
    stage1SliceOptions
    stage1SocketOptions
    stage1TimerOptions
    stage2AutomountOptions
    stage2CommonUnitOptions
    stage2MountOptions
    stage2PathOptions
    stage2ServiceOptions
    stage2SliceOptions
    stage2SocketOptions
    stage2TimerOptions
    ;

  inherit (lib) mkDefault mkOption;

  inherit
    (lib.types)
    attrsOf
    listOf
    submodule
    ;
in {
  units = attrsOf (
    submodule (
      {
        name,
        config,
        ...
      }: {
        options = concreteUnitOptions;
        config = {
          name = mkDefault name;
          unit = mkDefault (makeUnit name config);
        };
      }
    )
  );

  services = attrsOf (submodule [
    stage2ServiceOptions
    unitConfig
    stage2ServiceConfig
  ]);
  initrdServices = attrsOf (submodule [
    stage1ServiceOptions
    unitConfig
    stage1ServiceConfig
  ]);

  targets = attrsOf (submodule [
    stage2CommonUnitOptions
    unitConfig
    targetConfig
  ]);
  initrdTargets = attrsOf (submodule [
    stage1CommonUnitOptions
    unitConfig
    targetConfig
  ]);

  sockets = attrsOf (submodule [
    stage2SocketOptions
    unitConfig
    socketConfig
  ]);
  initrdSockets = attrsOf (submodule [
    stage1SocketOptions
    unitConfig
    socketConfig
  ]);

  timers = attrsOf (submodule [
    stage2TimerOptions
    unitConfig
    timerConfig
  ]);
  initrdTimers = attrsOf (submodule [
    stage1TimerOptions
    unitConfig
    timerConfig
  ]);

  paths = attrsOf (submodule [
    stage2PathOptions
    unitConfig
    pathConfig
  ]);
  initrdPaths = attrsOf (submodule [
    stage1PathOptions
    unitConfig
    pathConfig
  ]);

  slices = attrsOf (submodule [
    stage2SliceOptions
    unitConfig
    sliceConfig
  ]);
  initrdSlices = attrsOf (submodule [
    stage1SliceOptions
    unitConfig
    sliceConfig
  ]);

  mounts = listOf (submodule [
    stage2MountOptions
    unitConfig
    mountConfig
  ]);
  initrdMounts = listOf (submodule [
    stage1MountOptions
    unitConfig
    mountConfig
  ]);

  automounts = listOf (submodule [
    stage2AutomountOptions
    unitConfig
    automountConfig
  ]);
  # Upstream declares `initrdAutomounts` as `attrsOf` rather than
  # `listOf` — almost certainly a bug (every other `initrd<Thing>`
  # matches its stage-2 counterpart). The AOS port mirrors the stage-2
  # `automounts` shape so the initrd option has consistent semantics.
  initrdAutomounts = listOf (submodule [
    stage1AutomountOptions
    unitConfig
    automountConfig
  ]);
}
