"""Reproduces ordinary consumed-lineage fields with independent primitive CBOR.

Fixed token/signature fields are opaque data. Canonical Commit identities and
represented equality do not establish trust, policy, lineage or GC authority.
"""

import argparse
from copy import deepcopy
from pathlib import Path
import re
import textwrap

from collection_vectors import diagnostic, encode, head
from pack_vectors import digest


HEADING = "## Consumed-lineage record field witnesses"
MAX_UINT = (1 << 64) - 1
BEHAVIOR = sorted([
    "store", "chunk", "compression", "encryption", "retain", "domain", "dedup",
    "redundancy", "degraded", "durability", "replicate", "home", "warm", "quota",
    "compaction_threshold", "whole_pack_threshold", "gap_merge_bytes", "span_max_bytes",
    "trust", "baseline", "merge", "writers", "reflog_retain", "prefetch", "reassembly",
    "passthrough", "wipe", "on-release", "acl", "hashes", "classify", "index", "strict-attrs",
])


def owner(provider="local"):
    """Transcribes every local/remote registration field as an unverified claim."""
    if provider == "local":
        return [1, bytes([1]) * 32, b"/fixture/bucket", "public", 11, 12, 13, 14,
                b"/fixture/control"]
    binding = [1, provider,
               ["https://storage.invalid", "fixture-bucket", b"prefix/", bytes([2]) * 32],
               [b"coordination/key", bytes([3]) * 32]]
    return [2, bytes([1]) * 32, "public", binding, b"original/control"]


def pin(kind=0, provider="local"):
    """Builds exact registered relative keys independently of control encoders."""
    keys = ["registration.cbor", "bootstrap-" + "01" * 32 + "-" + "05" * 32 + "-24.cbor",
            "commit-" + "06" * 32 + ".cbor", "import-" + "07" * 32 + ".cbor",
            "import-binding-" + "08" * 32 + ".cbor", "import-trust-" + "09" * 32 + ".cbor"]
    return [kind, owner(provider), keys[kind], bytes([20 + kind]) * 32]


def property_layers():
    """Preserves complete ancestor property and graft override maps as bytes."""
    return [[encode({"domain": "public", "acl": [["alice", 31], ["alice", 0]],
                     "hashes": ["sha256", "sha512"], "strict-attrs": True}),
             encode({"store": "fixture-store", "retain": "forever"})],
            [encode({"domain": "group:readers", "prefetch": "none", "reassembly": "always"}),
             encode({"domain": "private:leaf", "hashes": ["sha256"]})]]


def root(path=b"/graft", layers=None, byte=30):
    """Constructs a full absolute occurrence with nonempty ordered layers."""
    return [bytes([byte]) * 32, path,
            deepcopy(property_layers() if layers is None else layers)]


def view(domain="public", empty=False):
    """Preserves unsorted occurrences and exact repeated root evidence."""
    roots = [] if empty else [root(b"/z"), root(b"/a"), root(b"/z")]
    return [bytes([31]) * 32, domain, roots]


def config(full=True):
    """Transcribes every trusted-config slot without making the value trusted."""
    return {0: 1, 1: "fixture-store", 2: "private:hint",
            3: {1: "region", 2: "zone", 3: "host"} if full else {},
            4: [["alice", 31], ["alice", 0]], 5: 262144, 6: "public", 7: "cdc-1m",
            8: [262144, 1048576, 4194304, 48, 2, bytes([40]) * 32],
            9: "policy:fixture" if full else None}


def registries(later=False):
    """Names the complete revision-one behavioral set and inert later fence."""
    return {0: 1, 1: 1, 2: BEHAVIOR, 3: 1, 4: 1, 5: 1, 6: 1, 7: "terrane-v1",
            8: ["future-note"] if later else []}


def used(full=True, later=False):
    """Constructs complete nested evidence including all presence alternatives."""
    issuers = [["issuer-a", "key-a", bytes([41]) * 32, None],
               ["issuer-a", "key-b", bytes([42]) * 32, 100]] if full else []
    disclosures = [["01" * 32, "public", bytes([43]) * 32, 10, None],
                   ["01" * 32, "tenant:fixture", bytes([44]) * 32, 20, 30]] if full else []
    controls = [pin(kind, provider) for kind in range(6)
                for provider in ["s3", "gcs", "local"]] if full else []
    controls.sort(key=lambda item: (item[0], encode(item[1]), item[2]))
    views = [view("public"), view("tenant:fixture", True)] if full else []
    if later:
        views = [[bytes([31]) * 32, "public", [root(b"/", [[encode({"future-note": "inert"}),
                                                           encode({})]])]]]
    return {0: 1, 1: issuers, 2: disclosures, 3: controls, 4: registries(later),
            5: config(full), 6: views}


def commit(full=True):
    """Builds canonical signed Commit fields with fixed opaque signature/token."""
    provenance = {1: "issuer-a", 2: bytes([45]) * 16, 3: "alice", 4: 2,
                  6: "fixture:lineage", 7: 100, 8: 24, 9: 3}
    profile = {1: 1, 2: "cdc-1m"}
    if full:
        token = [{1: "issuer-a", 2: "alice", 3: "alice", 4: 2, 5: ["readers"],
                  6: 200, 8: bytes([45]) * 16, 9: [["refs/heads/*", 4]],
                  11: bytes([46]) * 32, 12: bytes([47]) * 64}]
        provenance.update({5: "workload:fixture", 10: token})
        profile.update({4: False, 5: {1: "lease:fixture", 2: 200},
                        6: {"hashes": ["sha256"]}, 7: [],
                        8: {1: "refs/heads/_/authored", 2: "sdk",
                            3: {1: "region", 2: "zone", 3: "host"},
                            4: [[b"/", "public"], [b"/graft", "private:leaf"]]}})
    fields = {1: bytes([30]) * 32, 2: [bytes([48]) * 32], 3: provenance,
              4: 101, 5: "inert lineage fields", 6: profile, 8: bytes([49]) * 64}
    if full:
        fields[7] = [[bytes([50]) * 16, {1: "region", 2: "zone", 3: "host"}]]
    return fields


def source(commit_id, full=True):
    """Builds the whole selected source, including policy/snapshot/candidate."""
    record = {1: commit_id, 2: 24, 3: 25,
              4: {1: "region", 2: "zone", 3: "host"} if full else {}}
    if full:
        record[5] = {1: True, 2: ["prefer-ours", "keep-conflict", "prefer-ours"],
                     3: ["ttl", 300], 4: False,
                     5: {1: "refs/tags/_/selected", 2: commit_id,
                         3: {"note": "opaque"}, 4: "fixture:key", 5: bytes([51]) * 64}}
        record[6] = bytes([52]) * 32
    return record


def lineage(binary, provider="local", full=True, maximum=False):
    """Binds exact primitive Commit bytes/identity to the whole source record."""
    commit_bytes = encode(commit(full))
    commit_id = digest(binary, "terrane-commit-v1", commit_bytes)
    used_fields = used(full)
    return {0: 1, 1: "refs/tags/_/selected" if full else "refs/heads/_/source",
            2: encode(source(commit_id, full)), 3: commit_id, 4: commit_bytes,
            5: bytes([53]) * 32, 6: MAX_UINT if maximum else 24,
            7: deepcopy(used_fields[3]), 8: owner(provider), 9: used_fields}


def positives(binary):
    """Collects independently named complete models for all five format families."""
    models = {}
    for provider in ["local", "s3", "gcs"]:
        for kind in range(6):
            models[f"lineage-pin-{provider}-{kind}"] = ("pin", pin(kind, provider))
    root_models = {
        "absolute-root": root(b"/", [[encode({}), encode({})]]),
        "full-layers": root(),
        "ordered-layers-reversed": root(layers=list(reversed(property_layers()))),
        "path-byte-maximum": root(b"/" + b"/".join([b"x" * 255] * 15 + [b"x" * 254, b"x"])),
        "opaque-path-bytes": root(b"/\xff\xfe"),
        "maximum-layer-count": root(layers=[[encode({}), encode({})]] * 65),
    }
    for name, model in root_models.items():
        models["lineage-root-" + name] = ("root", model)
    for name, domain, empty in [("public", "public", False), ("private", "private:leaf", False),
                                ("group", "group:readers", False), ("tenant", "tenant:fixture", False),
                                ("empty-occurrences", "public", True)]:
        models["lineage-view-" + name] = ("view", view(domain, empty))
    for name, full, later in [("complete", True, False), ("empty-consumption", False, False),
                              ("inert-later-property", True, True)]:
        models["lineage-used-" + name] = ("used", used(full, later))
    for name, provider, full, maximum in [("local-complete", "local", True, False),
                                         ("s3-complete", "s3", True, False),
                                         ("gcs-maximum-loss", "gcs", True, True),
                                         ("legacy-empty", "local", False, False)]:
        models["lineage-checked-" + name] = ("checked", lineage(binary, provider, full, maximum))
    return models


def replace(model, path, replacement):
    """Changes one independently built field, without consulting a Terrane codec."""
    changed = deepcopy(model)
    target = changed
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement
    return changed


def raw_field(model, path, raw):
    """Builds one malformed primitive header inside a complete field table."""
    def assemble(value, prefix):
        if prefix == path:
            return raw
        if isinstance(value, list):
            return head(4, len(value)) + b"".join(assemble(item, prefix + (index,))
                                               for index, item in enumerate(value))
        if isinstance(value, dict):
            fields = sorted(value, key=lambda key: (len(encode(key)), encode(key)))
            return head(5, len(value)) + b"".join(encode(key) + assemble(value[key], prefix + (key,))
                                               for key in fields)
        return encode(value)
    return assemble(model, ())


def negatives(binary):
    """Assembles malformed/contradictory wires outside all owning encoders."""
    models = {"pin": pin(), "root": root(), "view": view(), "used": used(),
              "checked": lineage(binary)}
    wires = {}

    def add(family, name, changed):
        label = f"bad-lineage-{family}-{name}"
        if label in wires:
            raise ValueError("duplicate negative name")
        wires[label] = (family, encode(changed))

    for family, model in models.items():
        wire = encode(model)
        for name, malformed in [("trailing", wire + b"\0"), ("truncated", wire[:-1]),
                                ("tag", b"\xc0" + wire),
                                ("indefinite", bytes([(wire[0] & 0xe0) | 31]) + wire[1:] + b"\xff"),
                                ("null", b"\xf6"),
                                ("nonminimal-head", bytes([(wire[0] & 0xe0) | 24, wire[0] & 31]) + wire[1:]),
                                ("huge-count", head(5 if isinstance(model, dict) else 4, MAX_UINT))]:
            wires[f"bad-lineage-{family}-{name}"] = (family, malformed)
        if isinstance(model, dict):
            for key in model:
                changed = deepcopy(model)
                del changed[key]
                add(family, f"missing-{key}", changed)
            add(family, "unknown-key", {**model, max(model) + 1: 0})
            add(family, "version", replace(model, (0,), 2))
            pairs = [encode(key) + encode(value) for key, value in reversed(list(model.items()))]
            wires[f"bad-lineage-{family}-key-order"] = (family, head(5, len(model)) + b"".join(pairs))
        else:
            add(family, "short-tuple", model[:-1])
            add(family, "long-tuple", model + [0])
    for name, path, value in [
        ("kind-bool", (0,), True), ("key-bytes", (2,), b"registration.cbor"),
        ("digest-empty", (3,), b""), ("digest-wide", (3,), bytes(33)),
        ("owner-id-short", (1, 1), bytes(31)),
        ("kind", (0,), 6), ("key", (2,), "registration.cbor/extra"),
        ("digest-short", (3,), bytes(31)), ("owner-version", (1, 0), 3),
        ("owner-relative-root", (1, 2), b"relative"), ("owner-domain", (1, 3), "unknown"),
    ]:
        add("pin", name, replace(models["pin"], path, value))
    for kind, key in [(1, "bootstrap-" + "02" * 32 + "-" + "05" * 32 + "-24.cbor"),
                      (1, "bootstrap-" + "01" * 32 + "-" + "05" * 32 + "-024.cbor"),
                      (2, "commit-" + "AA" * 32 + ".cbor"),
                      (3, "import-" + "07" * 31 + ".cbor"),
                      (4, "import-" + "08" * 32 + ".cbor"),
                      (5, "import-trust-" + "09" * 32 + ".cbor/extra")]:
        add("pin", f"key-kind-{kind}-{len(key)}", replace(pin(kind), (2,), key))
    add("pin", "bootstrap-overflow", replace(pin(1), (2,),
        "bootstrap-" + "01" * 32 + "-" + "05" * 32 + f"-{MAX_UINT + 1}.cbor"))
    wires["bad-lineage-pin-key-utf8"] = ("pin", raw_field(models["pin"], (2,), b"\x61\xff"))
    wires["bad-lineage-pin-huge-digest"] = ("pin", raw_field(models["pin"], (3,), head(2, MAX_UINT)))
    for provider in ["s3", "gcs"]:
        for name, path, value in [("empty-endpoint", (1, 3, 2, 0), ""),
                                  ("empty-control", (1, 4), b""),
                                  ("provider", (1, 3, 1), "unknown")]:
            add("pin", provider + "-" + name, replace(pin(0, provider), path, value))
    for name, path, value in [
        ("empty-path", (1,), b""), ("relative-path", (1,), b"graft"),
        ("path-dot", (1,), b"/a/../b"), ("path-slash", (1,), b"/a//b"),
        ("path-nul", (1,), b"/a\0"), ("path-component-wide", (1,), b"/" + b"x" * 256),
        ("path-trailing-slash", (1,), b"/a/"), ("path-too-long", (1,), b"/" + b"x" * 4097),
        ("empty-layers", (2,), []), ("too-many-layers", (2,), [[b"\xa0", b"\xa0"]] * 66),
        ("root-width", (0,), bytes(31)), ("layer-tuple", (2, 0), [b"\xa0"]),
        ("property-trailing", (2, 0, 0), b"\xa0\0"),
        ("property-nonminimal", (2, 0, 0), b"\xb8\x00"),
        ("override-null", (2, 0, 1), b"\xf6"),
        ("property-invalid-domain", (2, 0, 0), encode({"domain": "unknown"})),
        ("property-invalid-type", (2, 0, 0), encode({"hashes": True})),
        ("override-trailing", (2, 0, 1), b"\xa0\0"),
    ]:
        add("root", name, replace(models["root"], path, value))
    for name, path in [("path", (1,)), ("layers", (2,)), ("property", (2, 0, 0)),
                       ("override", (2, 0, 1))]:
        major = 4 if name == "layers" else 2
        wires[f"bad-lineage-root-huge-{name}"] = ("root", raw_field(models["root"], path, head(major, MAX_UINT)))
    for label in ["unknown", "private:", "group:", "tenant:"]:
        add("view", "domain-" + label, replace(models["view"], (1,), label))
    conflicting = deepcopy(models["view"])
    conflicting[2][2][0] = bytes([99]) * 32
    add("view", "conflicting-occurrence", conflicting)
    conflicting = deepcopy(models["view"])
    conflicting[2][2][2].reverse()
    add("view", "conflicting-layers", conflicting)
    add("view", "identity-width", replace(models["view"], (0,), bytes(31)))
    wires["bad-lineage-view-huge-roots"] = ("view", raw_field(models["view"], (2,), head(4, MAX_UINT)))
    for name, path, value in [
        ("issuer-order", (1,), list(reversed(models["used"][1]))),
        ("issuer-duplicate", (1,), [models["used"][1][0]] * 2),
        ("issuer-key-width", (1, 0, 2), bytes(31)),
        ("disclosure-interval", (2, 1, 4), 20),
        ("disclosure-order", (2,), list(reversed(models["used"][2]))),
        ("controls-order", (3,), list(reversed(models["used"][3]))),
        ("controls-duplicate", (3,), [pin()] * 2),
        ("registry-revision", (4, 1), 2), ("registry-missing-name", (4, 2), BEHAVIOR[:-1]),
        ("later-overlap", (4, 8), ["domain"]),
        ("profile-minimum", (5, 5), 1), ("profile-maximum", (5, 8, 2), 1048576),
        ("policy-null-shape", (5, 9), True),
        ("unfenced-property", (6, 0, 2, 0, 2, 0, 0), encode({"future-note": "inert"})),
    ]:
        add("used", name, replace(models["used"], path, value))
    for key in [1, 2, 3, 6]:
        wires[f"bad-lineage-used-huge-rows-{key}"] = ("used", raw_field(models["used"], (key,), head(4, MAX_UINT)))
    for name, path, value in [
        ("source-name", (1,), "refs/unknown/source"), ("source-notes", (1,), "refs/notes/source"),
        ("identity", (3,), bytes([99]) * 32), ("guard-width", (5,), bytes(31)),
        ("loss-bool", (6,), True), ("controls-mismatch", (7,), []),
        ("original-version", (8, 0), 3), ("source-trailing", (2,), models["checked"][2] + b"\0"),
        ("commit-trailing", (4,), models["checked"][4] + b"\0"),
    ]:
        add("checked", name, replace(models["checked"], path, value))
    malformed_source = source(models["checked"][3])
    malformed_source[6] = bytes(31)
    add("checked", "source-candidate-width", replace(models["checked"], (2,), encode(malformed_source)))
    malformed_commit = commit()
    malformed_commit[8] = bytes(63)
    add("checked", "commit-signature-width", replace(models["checked"], (4,), encode(malformed_commit)))
    unsigned = commit()
    del unsigned[8]
    unsigned_bytes = encode(unsigned)
    unsigned_id = digest(binary, "terrane-commit-v1", unsigned_bytes)
    malformed = deepcopy(models["checked"])
    malformed.update({2: encode(source(unsigned_id)), 3: unsigned_id, 4: unsigned_bytes})
    add("checked", "unsigned-consistent-commit", malformed)
    source_wrong = source(bytes([99]) * 32)
    add("checked", "source-commit-mismatch", replace(models["checked"], (2,), encode(source_wrong)))
    for key, major in [(1, 3), (2, 2), (4, 2), (7, 4)]:
        wires[f"bad-lineage-checked-huge-field-{key}"] = ("checked", raw_field(models["checked"], (key,), head(major, MAX_UINT)))
    return wires


def render(binary):
    """Renders complete fields and independently reconstructed rejection inputs."""
    parts = [HEADING, "", textwrap.fill(
        "These TEST-1/TEST-2 ordinary format witnesses cover only format prerequisites "
        "of PROV-4/PROV-28/PROV-31. Pins, consumed policy layers, used-input summaries "
        "and CheckedLineage are unverified represented data. Opaque signatures and "
        "tokens are not authenticated. Exact canonical Commit bytes use the registered "
        "terrane-commit-v1 domain solely to check represented source/identity equality; "
        "these enclosing non-content-addressed records and all negative wires have no "
        "immutable-content identity. No signer, verifier, policy evaluation, private "
        "holder, factory, backend or authority conformance is involved.", 78), ""]
    for name, (family, model) in positives(binary).items():
        parts += [f"### {name}", "", "```text", "format = " + family,
                  "fields = " + diagnostic(model), "wire = " + encode(model).hex()]
        if family == "checked":
            parts += ["commit-id = " + model[3].hex()]
        parts += ["```", ""]
    for name, (family, wire) in negatives(binary).items():
        parts += [f"### {name}", "", "```text", "format = " + family,
                  "wire = " + wire.hex(), "result = structural rejection", "```", ""]
    return "\n".join(parts)


def check_section(document, expected):
    """Checks one bounded exact-byte UTF-8 section without newline normalization."""
    headings = list(re.finditer(r"^## .*?$", document, re.MULTILINE))
    matches = [index for index, match in enumerate(headings) if match[0] == HEADING]
    if len(matches) != 1:
        raise ValueError("expected exactly one consumed-lineage witness section")
    index = matches[0]
    end = headings[index + 1].start() if index + 1 < len(headings) else len(document)
    if document[headings[index].start():end].rstrip("\n") != expected.rstrip("\n"):
        raise ValueError("consumed-lineage fields or bytes differ")


def self_check(binary):
    """Checks primitive boundaries and missing/duplicate/split/tamper refusals."""
    if encode({1: bytes(2), 0: 1}) != bytes.fromhex("a2000101420000"):
        raise ValueError("primitive CBOR oracle failed")
    models, negative = positives(binary), negatives(binary)
    if len(models) != 36 or len(negative) != 155 or models.keys() & negative.keys():
        raise ValueError("positive count or distinct names changed")
    section = render(binary)
    check_section("## Earlier\ntext\n" + section + "\n## Later\ntext\n", section)
    for invalid in ["", section + section, section.replace("wire = ", "wire = 00", 1),
                    section.replace("### lineage-pin-local-0", "## Split", 1),
                    section[:-1] + " \n", section.replace("\n", "\r\n")]:
        try:
            check_section(invalid, section)
        except ValueError:
            continue
        raise ValueError("missing/duplicate/split/tamper/space/CRLF accepted")


def main():
    """Runs independent self-checks, emits a draft or checks an existing section."""
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    for name in ["self-check", "emit", "check"]:
        modes.add_argument("--" + name, action="store_true")
    parser.add_argument("reference", type=Path, nargs="?")
    parser.add_argument("--blake3-bin", type=Path, required=True)
    arguments = parser.parse_args()
    self_check(arguments.blake3_bin)
    if arguments.self_check:
        print(f"PASS: {len(positives(arguments.blake3_bin))} complete models; "
              f"{len(negatives(arguments.blake3_bin))} independent negative wires")
    elif arguments.emit:
        print(render(arguments.blake3_bin), end="")
    else:
        if arguments.reference is None:
            parser.error("--check requires a reference path")
        check_section(arguments.reference.read_bytes().decode("utf-8"), render(arguments.blake3_bin))
        print("PASS: independent consumed-lineage witness section matches")


if __name__ == "__main__":
    main()
