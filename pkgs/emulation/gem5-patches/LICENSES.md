# gem5 native patch license inventory

Upstream revision: `f5c5a6e390f55dd5984977815bf9d0bd05da6945`
(gem5 25.1.0.1). Every modified upstream file retains its complete original
copyright and license notice. New native files retain explicit permissive
notices; they do not relicense the simulator.

| Patch | Modified upstream files | Preserved license |
| --- | --- | --- |
| `compiler-target-query.patch` | `SConstruct` | BSD three-clause notice, including upstream hardware intellectual-property scope statement |
| `reproducible-build-environment.patch` | `site_scons/gem5_scons/defaults.py` | BSD three-clause notice, including upstream hardware intellectual-property scope statement |
| `nondraining-event-boundary.patch` | `src/sim/simulate.hh`, `src/sim/simulate.cc`, `src/python/pybind11/event.cc`, `src/python/m5/simulate.py` | Each file's BSD three-clause notice and copyright holders |
| `time-buffer-value-initialization.patch` | `src/cpu/timebuf.hh` | Original BSD three-clause notice and copyright holders |
| `se-output-publication.patch` | `src/sim/simulate.hh`, `src/sim/simulate.cc`, `src/sim/syscall_emul.cc`, `src/sim/SConscript`, `src/python/pybind11/event.cc`, `src/python/m5/simulate.py`; new `src/sim/crucible_output.hh`, `src/sim/crucible_output.cc` | Original notices retained; new native publication files BSD-3-Clause |

The installed gem5 package retains upstream `LICENSE` and bundled dependency
license/notice files. The source manifest binds the exact upstream revision,
recipe and patch digests. It does not relicense upstream or qualify a Crucible
profile. The helper Python/C/C++/assembly sources under `../_gem5/` are separately
marked MIT; Nix recipes follow the repository's applicable file license.

DMTCP remains an independently packaged LGPL-3.0-or-later component. Its pinned
`include/dmtcp.h` explicitly dedicates that public interface header to the public
domain; the implementation/library is not public domain. The MIT resource
custody helper does not change DMTCP's license. Preloading DMTCP into a
GPL-2.0-only QEMU process is not authorized by this inventory.
