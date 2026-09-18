##! Offline final SELinux policy for the production Linux kernel.
{
  mkDerivation,
  linux,
  refpolicy-production,
  checkpolicy,
  semodule-utils,
  libselinux,
  secilc,
  setools,
  python3,
}: let
  policyVersion = "33";
  policySupport = ./_aos-selinux-production-policy;
in
  mkDerivation {
    pname = "aos-selinux-production-policy";
    version = "1";

    buildDeps = [
      checkpolicy
      semodule-utils
      libselinux
      secilc
      setools
      python3
    ];
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "build";
        script = ''
          module_dir=${refpolicy-production}/usr/share/selinux/refpolicy
          base_package="$module_dir/base.pp"
          aos_module=aos_sandbox
          attribute_negative_module=aos_sandbox_attribute_negative
          export PYTHONPATH=${setools}/lib/python3/site-packages

          ${python3}/bin/python3 ${policySupport}/effective_policy_test.py
          ${checkpolicy}/bin/checkmodule -m \
            -o "$aos_module.mod" ${policySupport}/aos_sandbox.te
          ${semodule-utils}/bin/semodule_package \
            -o "$aos_module.pp" \
            -m "$aos_module.mod" \
            -f ${policySupport}/aos_sandbox.fc
          test -s "$aos_module.pp"
          ${checkpolicy}/bin/checkmodule -m \
            -o "$attribute_negative_module.mod" \
            ${policySupport}/aos_sandbox_attribute_negative.te
          ${semodule-utils}/bin/semodule_package \
            -o "$attribute_negative_module.pp" \
            -m "$attribute_negative_module.mod"
          test -s "$attribute_negative_module.pp"

          test -f "$base_package"
          set -- "$base_package"
          for module_package in "$module_dir"/*.pp; do
            if [ "$module_package" != "$base_package" ]; then
              set -- "$@" "$module_package"
            fi
          done
          set -- "$@" "$aos_module.pp"

          # The production variant's base package carries reject-unknown and
          # its Linux 6.18 class map. The focused AOS sandbox module is linked
          # here; legacy mutable-store compatibility modules are not inputs.
          ${semodule-utils}/bin/semodule_link -o linked-policy.mod "$@"
          ${semodule-utils}/bin/semodule_expand \
            -c ${policyVersion} \
            linked-policy.mod final-policy.${policyVersion}

          ${checkpolicy}/bin/checkpolicy -b -C \
            -o final-policy.cil final-policy.${policyVersion}
          ${python3}/bin/python3 ${policySupport}/effective_policy.py \
            final-policy.${policyVersion} > effective-policy.tsv
          test -s effective-policy.tsv

          # Link a deliberately forbidden attribute-based process:ptrace rule
          # into a second loadable binary. This proves the production checker
          # uses SETools' indirect source expansion and unbounded target scan.
          ${semodule-utils}/bin/semodule_link \
            -o attribute-negative-linked-policy.mod \
            "$@" "$attribute_negative_module.pp"
          # Production expansion above keeps neverallow checking enabled. Only
          # this deliberately forbidden, never-installed fixture bypasses the
          # base policy assertions so the SETools gate can reject it itself.
          ${semodule-utils}/bin/semodule_expand \
            -a \
            -c ${policyVersion} \
            attribute-negative-linked-policy.mod \
            attribute-negative-policy.${policyVersion}
          if ${python3}/bin/python3 ${policySupport}/effective_policy.py \
            attribute-negative-policy.${policyVersion} \
            > attribute-negative-effective-policy.tsv \
            2> attribute-negative-diagnostic
          then
            echo "attribute-expanded forbidden rule unexpectedly passed" >&2
            exit 1
          fi
          grep -F "forbidden allow exists" attribute-negative-diagnostic
          grep -F "process" attribute-negative-diagnostic
          grep -F "ptrace" attribute-negative-diagnostic

          mkdir kernel-source
          tar xf ${linux.src} -C kernel-source --strip-components=1
          $CC \
            -std=c17 \
            -Wall \
            -Wextra \
            -Werror \
            -I kernel-source/security/selinux/include \
            ${policySupport}/kernel-classmap.c \
            -o emit-kernel-classmap
          ./emit-kernel-classmap > kernel-classmap.tsv

          ${python3}/bin/python3 ${policySupport}/coverage_test.py
          ${python3}/bin/python3 ${policySupport}/coverage.py check \
            kernel-classmap.tsv final-policy.cil observed-policy-classmap.tsv

          # The source-level negative catches comparator regressions directly.
          ${python3}/bin/python3 ${policySupport}/coverage.py remove \
            final-policy.cil deficient-policy.cil io_uring allowed
          if ${python3}/bin/python3 ${policySupport}/coverage.py check \
            kernel-classmap.tsv deficient-policy.cil deficient-source-classmap.tsv \
            2> deficient-source-diagnostic
          then
            echo "deficient source unexpectedly passed policy coverage" >&2
            exit 1
          fi
          grep -F "ordered permissions differ for io_uring" \
            deficient-source-diagnostic

          # The artifact negative must first compile, then fail the same gate
          # only after checkpolicy decodes the resulting loadable binary.
          ${secilc}/bin/secilc \
            -c ${policyVersion} \
            -f /dev/null \
            -o deficient-policy.${policyVersion} \
            deficient-policy.cil
          test -s deficient-policy.${policyVersion}
          ${checkpolicy}/bin/checkpolicy -b -C \
            -o deficient-policy-decoded.cil deficient-policy.${policyVersion}
          if ${python3}/bin/python3 ${policySupport}/coverage.py check \
            kernel-classmap.tsv \
            deficient-policy-decoded.cil \
            deficient-binary-classmap.tsv \
            2> deficient-binary-diagnostic
          then
            echo "deficient binary unexpectedly passed policy coverage" >&2
            exit 1
          fi
          grep -F "ordered permissions differ for io_uring" \
            deficient-binary-diagnostic

          mkdir unpacked-modules
          : > file_contexts
          module_index=0
          for module_package in "$module_dir"/*.pp; do
            module_index=$((module_index + 1))
            module_prefix="unpacked-modules/module-$module_index"
            ${semodule-utils}/bin/semodule_unpackage \
              "$module_package" "$module_prefix.mod" "$module_prefix.fc"

            if [ -s "$module_prefix.fc" ]; then
              cat "$module_prefix.fc" >> file_contexts
              printf '\n' >> file_contexts
            fi
          done

          cat ${policySupport}/aos_sandbox.fc >> file_contexts
          printf '\n' >> file_contexts

          test -s file_contexts
          ${libselinux}/sbin/sefcontext_compile \
            -p final-policy.${policyVersion} \
            -o file_contexts.bin \
            file_contexts
          test -s file_contexts.bin
        '';
      }
      {
        name = "install";
        script = ''
          policy_root=$out/etc/selinux/aos
          evidence_root=$out/share/aos-selinux-production-policy

          mkdir -p "$policy_root" "$evidence_root"
          cp -R ${refpolicy-production}/etc/selinux/refpolicy/. "$policy_root/"
          chmod -R u+w "$policy_root"
          mkdir -p "$policy_root/policy" "$policy_root/contexts/files"
          install -m 0644 final-policy.${policyVersion} \
            "$policy_root/policy/policy.${policyVersion}"
          install -m 0644 file_contexts file_contexts.bin \
            "$policy_root/contexts/files/"
          install -m 0644 \
            kernel-classmap.tsv \
            observed-policy-classmap.tsv \
            final-policy.cil \
            effective-policy.tsv \
            "$aos_module.mod" \
            "$aos_module.pp" \
            ${policySupport}/aos_sandbox.te \
            ${policySupport}/aos_sandbox.fc \
            ${policySupport}/aos_sandbox_attribute_negative.te \
            attribute-negative-diagnostic \
            deficient-source-diagnostic \
            deficient-binary-diagnostic \
            "$evidence_root/"

          cat > "$evidence_root/gate-result" <<'EOF'
          kernel_classmap_ordered_prefix=pass
          final_binary_handleunknown_reject=pass
          deficient_source_pair=io_uring.allowed
          deficient_source_coverage=rejected
          deficient_binary_compilation=pass
          deficient_binary_decoded_coverage=rejected
          aos_sandbox_module_linked=pass
          aos_sandbox_effective_policy=pass
          aos_sandbox_attribute_expansion_negative=rejected
          EOF
        '';
      }
    ];

    passthru.evidenceSources = [
      policySupport
      refpolicy-production.src
      linux.src
    ];

    meta = {
      description = "Offline SELinux policy matched to the production Linux class map";
      license = "GPL-2.0-or-later";
    };
  }
