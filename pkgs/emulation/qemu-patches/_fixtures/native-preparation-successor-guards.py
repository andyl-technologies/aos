# SPDX-License-Identifier: GPL-2.0-or-later
"""Checks mandatory source ownership and bounds for historical preparation."""

from pathlib import Path
import re
import sys


def require(label, source, expression):
    if len(re.findall(expression, source, re.S)) != 1:
        raise SystemExit(f"FAIL: {label}")


def main():
    root = Path(sys.argv[1])
    native = (root / "accel/tcg/crucible-node-preparation.c").read_text()
    rr = (root / "accel/tcg/tcg-accel-ops-rr.c").read_text()
    header = (root / "include/plugins/qemu-plugin.h").read_text()
    meson = (root / "accel/tcg/meson.build").read_text()

    checks = [
        ("source SPDX remains explicit", native,
         r"^/\* SPDX-License-Identifier: GPL-2\.0-or-later \*/"),
        ("source created only in BQL serialization", native,
         r"if \(!bql_locked\(\)\) \{\s*return -EPERM;\s*\}"),
        ("historical cache returns without resampling", native,
         r"if \(existing\) \{.*?\*successor = existing->facts;\s*return 0;\s*\}"),
        ("accepted execution permanently closes first creation", rr,
         r"rr_initialization_home_pending \|\| rr_node_command_valid \|\|"),
        ("source origin genuine RR owner", rr,
         r"if \(!bql_locked\(\) \|\| !first_cpu \|\| !qemu_cpu_is_self\(first_cpu\)\) \{"),
        ("Applied original status required", rr,
         r"rr_initialization_receipt.status !=\s*QEMU_PLUGIN_CRUCIBLE_NODE_INITIALIZATION_APPLIED"),
        ("fresh clock credit required", rr,
         r"park->next_service_deadline_ps != UINT64_MAX \|\|\s*park->pending_service_credit_ps \|\|"),
        ("caller-owned SHA output buffer", native,
         r"uint8_t \*hash = digest;\s*size_t size = 32;"),
        ("two complete observations agree before publication", native,
         r"if \(encoding.length != repeated.length \|\|\s*memcmp\(encoding.bytes, repeated.bytes, encoding.length\)\) \{\s*return -EAGAIN;\s*\}"),
        ("all native row ceilings checked locally", native,
         r"sample->writer.cpu_count > QEMU_PLUGIN_CRUCIBLE_NODE_WRITER_CPU_MAX.*?sample->timer.timer_count > QEMU_PLUGIN_CRUCIBLE_NODE_TIMER_MAX"),
        ("complete immutable object release published", native,
         r"qatomic_store_release\(&preparation_object, g_steal_pointer\(&candidate\)\);"),
        ("chunk subtraction follows checked offset", native,
         r"if \(offset > object->facts.content_length\) \{\s*return -ERANGE;\s*\}\s*length = MIN\(\(uint64_t\)capacity, object->facts.content_length - offset\);"),
        ("chunks retain original content identity", native,
         r"memcmp\(content_digest, object->facts.content_digest, 32\)\) \{\s*return -ESTALE;"),
        ("compile scope system TCG owns implementation", meson,
         r"system_ss.add\(files\(.*?'tcg-accel-ops-rr.c',\s*'crucible-node-preparation.c',"),
        ("explicit bounded object and chunk ceilings", header,
         r"PREPARATION_SUCCESSOR_MAX \(2U \* 1024U \* 1024U\).*?PREPARATION_SUCCESSOR_CHUNK_MAX 3000"),
        ("native summary ABI exact248", native,
         r"G_STATIC_ASSERT\(sizeof\(\*successor\) == 248\);"),
    ]
    for label, source, expression in checks:
        require(label, source, expression)
    print(f"PASS {len(checks)} source preparation ownership/bounds predicates")


if __name__ == "__main__":
    main()
