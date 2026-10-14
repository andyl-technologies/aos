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
  ./original-task-allocator-scope.patch
  ./original-control-allocator-binding.patch
  ./original-large-bulk-refusal.patch
  ./original-direct-bulk-page-refusal.patch
  ./original-nolock-page-refusal.patch
  ./original-page-input-currentness.patch
  ./0042-original-vm-root-custody.patch
  ./0043-original-vmalloc-lifetime.patch
]
