# SPDX-License-Identifier: GPL-2.0-or-later
"""Checks mandatory source ownership and bounds for historical preparation."""

from pathlib import Path
import re
import sys


def require(label, source, expression):
    if len(re.findall(expression, source, re.S)) != 1:
        raise SystemExit(f"FAIL: {label}")


def successor_origin(source):
    """Scopes predicates to the unique native origin and adjacent declaration."""
    first = r"^int rr_crucible_node_preparation_successor_origin\("
    following = r"^bool rr_crucible_node_root_factory_origin\("
    starts = list(re.finditer(first, source, re.M))
    ends = list(re.finditer(following, source, re.M))
    if len(starts) != 1 or len(ends) != 1:
        raise SystemExit("FAIL: unique preparation origin declarations required")

    begin = starts[0].start()
    end = ends[0].start()
    if end <= begin:
        raise SystemExit("FAIL: original preparation origin extent required")

    extent = source[begin:end]
    closing = re.search(r"^}[ \t]*\n", extent, re.M)
    # Native nested blocks are indented. The column-zero function close must
    # be followed only by whitespace before the immutable adjacent declaration.
    if closing is None or extent[closing.end():].strip():
        raise SystemExit("FAIL: exact adjacent preparation origin body required")
    return extent[:closing.end()]


def check_applied_scope_mutations(rr, origin, expression):
    """Rejects missing/duplicate origin guards while allowing other consumers."""
    match = re.search(expression, origin, re.S)
    if match is None:
        raise SystemExit("FAIL: original Applied guard unavailable for mutations")

    removed = origin[:match.start()] + "false" + origin[match.end():]
    duplicated = origin.rstrip()[:-1] + (
        "\n    if (" + match.group() + ") { return -ENOTSUP; }\n}\n"
    )
    for label, changed in (("removed", removed), ("duplicated", duplicated)):
        candidate = rr.replace(origin, changed, 1)
        try:
            require("Applied original status required", successor_origin(candidate),
                    expression)
        except SystemExit:
            continue
        raise SystemExit(f"FAIL: {label} original Applied guard survived")

    unrelated = rr + (
        "\nint another_legitimate_applied_consumer(void)\n{\n    if ("
        + match.group() + ") { return -ENOTSUP; }\n    return 0;\n}\n"
    )
    require("unrelated Applied consumer preserves original scope",
            successor_origin(unrelated), expression)

    following = "bool rr_crucible_node_root_factory_origin("
    unrelated_body = unrelated[len(rr):]
    disguised = rr.replace(origin, removed, 1).replace(
        following, unrelated_body + following, 1
    )
    try:
        require("original Applied cannot come from adjacent consumer",
                successor_origin(disguised), expression)
    except SystemExit:
        return
    raise SystemExit("FAIL: adjacent consumer supplied the removed origin guard")


def main():
    root = Path(sys.argv[1])
    native = (root / "accel/tcg/crucible-node-preparation.c").read_text()
    rr = (root / "accel/tcg/tcg-accel-ops-rr.c").read_text()
    header = (root / "include/plugins/qemu-plugin.h").read_text()
    meson = (root / "accel/tcg/meson.build").read_text()
    origin = successor_origin(rr)
    applied = (
        r"rr_initialization_receipt.status !=\s*"
        r"QEMU_PLUGIN_CRUCIBLE_NODE_INITIALIZATION_APPLIED"
    )

    checks = [
        ("source SPDX remains explicit", native,
         r"^/\* SPDX-License-Identifier: GPL-2\.0-or-later \*/"),
        ("source created only in BQL serialization", native,
         r"if \(!bql_locked\(\)\) \{\s*return -EPERM;\s*\}"),
        ("historical cache returns without resampling", native,
         r"if \(existing\) \{.*?\*successor = existing->facts;\s*return 0;\s*\}"),
        ("accepted execution permanently closes first creation", origin,
         r"rr_initialization_home_pending \|\| rr_node_command_valid \|\|"),
        ("source origin genuine RR owner", origin,
         r"if \(!bql_locked\(\) \|\| !first_cpu \|\| !qemu_cpu_is_self\(first_cpu\)\) \{"),
        ("Applied original status required", origin, applied),
        ("fresh clock credit required", origin,
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
    check_applied_scope_mutations(rr, origin, applied)
    print(f"PASS {len(checks)} source preparation ownership/bounds predicates")
    print("PASS removed/duplicate/adjacent-substitute guard refusals and unrelated consumer")


if __name__ == "__main__":
    main()
