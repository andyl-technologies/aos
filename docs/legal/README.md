# AOS licensing and contribution agreements

AOS contains original project code and separately licensed components. Start
with the document that matches your question:

- **May I use or redistribute this code?** Read the
  [repository license map](licensing.md). It identifies the license that
  applies to each major component and explains the Crucible/QEMU boundary and
  corresponding-source requirements.
- **What agreement covers my contribution?** Read
  [`CONTRIBUTING.md`](../../CONTRIBUTING.md). External contributors can review
  the [AOS External Contributor License Agreement](external-contributor-license-agreement.md);
  current Andyl employees follow the internal authorization path described in
  the contribution guide.
- **Where are the complete license terms?** The root [`LICENSE`](../../LICENSE)
  is the Apache License 2.0 text that applies to original AOS code without a
  more specific notice. [`LICENSES/`](../../LICENSES/) contains the complete
  texts for every license used by AOS components.

## GitHub's license label

GitHub identifies a repository license from the root `LICENSE` file. It
therefore labels AOS as Apache-2.0, which is the default for original AOS code.
That label cannot describe every component in this multi-license repository.
The [license map](licensing.md) is authoritative for exceptions, including the
dual-licensed protocol crates and GPL-licensed QEMU integration.
