##! Builds one published-image cancellation flight using the rollout VM fixture.
{
  lib,
  mkSystem,
  pkgs,
  nativeAdapterMatrix,
  systems,
  cellId,
  rolloutImage ? null,
}:
import ./_ability-effect-boundary-rollout-cohort.nix {
  inherit lib mkSystem pkgs nativeAdapterMatrix systems cellId rolloutImage;
  cancellation = true;
}
