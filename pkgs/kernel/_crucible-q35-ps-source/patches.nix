# Exact selected source chain; the original kernel19 variant is unchanged.
(import ../_crucible-q35-cold-source/patches.nix)
++ [
  ./ps-timer-deadline.patch
  ./ps-run-terminal-output.patch
  ./ps-loaded-run-counter.patch
  ./ps-counter-access.patch
  ./ps-irq-native-routes.patch
  ./ps-ceiling-observation.patch
  ./ps-control-history.patch
  ./original-cpu-resource-and-timer-source.patch
]
