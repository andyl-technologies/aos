# Terrane task gates

Each `.nix` file in this directory returns an attribute set of named checks.
The registry loads these files in filename order and rejects duplicate names.
Gate files receive `pkgs`, `lib`, `sourceGate`, and `structureGate`; tests that
exercise source code should use `sourceGate` so they run offline with AOS-built
tools and the locked vendor tree. A task owns its own gate file, which adds its
checks to the current trunk aggregate when the task is merged.
