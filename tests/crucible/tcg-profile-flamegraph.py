# SPDX-License-Identifier: Apache-2.0
"""Render offline, mass-preserving comparisons of decoded QEMU CPU profiles.

Input is the counted, leaf-first stack JSON emitted by tcg-profile.py. Run with
``python tcg-profile-flamegraph.py --profile plain-tcg=plain.json
--profile sim=sim.json --output report-directory``. Optional --metadata accepts
a portable JSON object describing phases, guest hashes and trial scope. Reports
contain no original stack addresses, absolute paths, or external dependencies.
Pooled inputs declare capture_count (default 1); sampled CPU graphs show the
mean per capture, while raw sample totals and pooled CPU seconds remain intact.
"""

import argparse
import collections
import hashlib
import html
import json
import math
from pathlib import Path
import re


SCHEMA = "crucible-tcg-mode-flamegraphs-v1"
CAUTION = (
    "The guest boot workload and QEMU binary can be identical while execution "
    "contracts and guest instruction counts differ. Plain TCG, ordinary icount "
    "and Sim use different clocks and scheduling. These diagnostic samples are "
    "excluded from uninstrumented performance means. Sampled CPU seconds are "
    "count × sampling period, not elapsed wall time or a precise CPU accounting "
    "measurement. For pooled captures, CPU graphs show the average per capture; "
    "shares use every pooled sample. This diagnostic average is not a benchmark "
    "mean. Inclusive frames overlap: do not add their percentages. "
    "Unmapped frames remain unresolved and may include guest code or missing "
    "host mappings; no anonymous address is treated as a shared function."
)


def positive_integer(value, name):
    """Reject booleans, zero and malformed sample weights."""
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def portable_text(value, name):
    """Accept portable labels without machine paths or control characters."""
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError(f"{name} must be a nonempty, bounded string")
    if any(ord(character) < 32 for character in value) or "/" in value or "\\" in value:
        raise ValueError(f"{name} must not contain paths or control characters")
    return value


def object_name(value):
    if not isinstance(value, str) or not value:
        raise ValueError("frame object must be a nonempty string")
    return portable_text(value.rsplit("/", 1)[-1], "object basename")


def canonical_frame(frame):
    """Keep exact named functions and explicitly coarsen unresolved addresses."""
    if not isinstance(frame, dict):
        raise ValueError("frame must be an object")
    name = object_name(frame.get("object"))
    symbol = frame.get("symbol")
    if symbol is not None:
        return name + ":" + portable_text(symbol, "symbol")
    if name in ("unmapped", "[anon]", "[anonymous]", "[jit]"):
        return "[unmapped or anonymous; possible guest code]"
    return name + ":[unresolved function]"


def portable_metadata(value):
    """Require report metadata to be explicitly portable, never silently redact."""
    if isinstance(value, dict):
        return {portable_text(key, "metadata key"): portable_metadata(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [portable_metadata(item) for item in value]
    if isinstance(value, str):
        forbidden_paths = ("/nix/store/", "/tmp/", "/home/", "/scratch/")
        if (re.search(r"(?:^|[\s=:(])/[^\s]+", value) or "\\" in value
                or any(path in value for path in forbidden_paths)):
            raise ValueError("metadata contains an absolute path")
        if any(ord(character) < 32 for character in value):
            raise ValueError("metadata contains control characters")
        return value
    if value is None or type(value) in (int, bool):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise ValueError("metadata must contain finite JSON values")


def normalize_profile(mode, decoded):
    """Canonicalize stacks while retaining every record's full sample weight."""
    portable_text(mode, "mode")
    if not isinstance(decoded, dict):
        raise ValueError("profile must be an object")
    period = positive_integer(decoded.get("sampling_period_us"), "sampling_period_us")
    total = positive_integer(decoded.get("total_samples"), "total_samples")
    captures = positive_integer(decoded.get("capture_count", 1), "capture_count")
    records = decoded.get("stacks")
    if not isinstance(records, list) or not records:
        raise ValueError("stacks must be a nonempty list")

    stacks = collections.Counter()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("stack record must be an object")
        count = positive_integer(record.get("count"), "stack count")
        frames = record.get("frames")
        if not isinstance(frames, list) or not frames:
            raise ValueError("stack frames must be a nonempty leaf-first list")
        stacks[tuple(canonical_frame(frame) for frame in reversed(frames))] += count
    if sum(stacks.values()) != total:
        raise ValueError("counted stacks do not sum to total_samples")
    seconds = total * period / 1_000_000
    declared_seconds = decoded.get("sampled_cpu_seconds", seconds)
    if (type(declared_seconds) not in (int, float)
            or not math.isfinite(declared_seconds)
            or not math.isclose(declared_seconds, seconds, rel_tol=1e-12, abs_tol=1e-12)):
        raise ValueError("sampled_cpu_seconds is inconsistent with count and period")

    identities = {}
    raw_identities = decoded.get("mapped_elf_sha256")
    if not isinstance(raw_identities, dict):
        raise ValueError("mapped_elf_sha256 is required for same-binary verification")
    for path, digest in raw_identities.items():
        name = object_name(path)
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("ELF identities must be lowercase SHA-256 digests")
        if name in identities and identities[name] != digest:
            raise ValueError("conflicting ELF identities share an object basename")
        identities[name] = digest
    qemu_names = [name for name in identities if name.startswith("qemu-system-")]
    if len(qemu_names) != 1:
        raise ValueError("exactly one QEMU system ELF identity is required")

    artifact_hashes = {}
    for key in ("profile_sha256", "decoded_json_sha256"):
        digest = decoded.get(key)
        if digest is not None:
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise ValueError(f"{key} must be a lowercase SHA-256 digest")
            artifact_hashes[key] = digest

    return dict(mode=mode, total_samples=total, sampling_period_us=period,
                sampled_cpu_seconds=seconds,
                capture_count=captures, sampled_cpu_seconds_per_capture=seconds / captures,
                qemu_sha256=identities[qemu_names[0]], elf_sha256=identities,
                artifact_sha256=artifact_hashes,
                stacks=[dict(frames=list(frames), count=count)
                        for frames, count in sorted(stacks.items())])


def weighted_stacks(profile, metric):
    factor = (profile["sampling_period_us"] / 1_000_000 / profile["capture_count"]
              if metric == "cpu_seconds" else 1 / profile["total_samples"])
    return {tuple(record["frames"]): record["count"] * factor
            for record in profile["stacks"]}


def stack_tree(before, after=None):
    """Build union widths and signed deltas; child widths plus self conserve mass."""
    after = before if after is None else after
    root = dict(label="all samples", weight=0.0, before=0.0, after=0.0,
                self_weight=0.0, children={})
    for frames in sorted(set(before) | set(after)):
        left, right = before.get(frames, 0), after.get(frames, 0)
        width = max(left, right)
        node = root
        for label in (None, *frames):
            if label is not None:
                node = node["children"].setdefault(label, dict(
                    label=label, weight=0.0, before=0.0, after=0.0,
                    self_weight=0.0, children={}))
            node["weight"] += width
            node["before"] += left
            node["after"] += right
        node["self_weight"] += width

    def finish(node):
        node["delta"] = node["after"] - node["before"]
        node["children"] = [finish(child) for _, child in sorted(node["children"].items())]
        return node

    return finish(root)


def exclusive_diff(before, after):
    """Return additive leaf-function costs, distinct from overlapping callers."""
    left, right = collections.Counter(), collections.Counter()
    for frames, weight in before.items():
        left[frames[-1]] += weight
    for frames, weight in after.items():
        right[frames[-1]] += weight
    return sorted([dict(label=label, before=left[label], after=right[label],
                        delta=right[label] - left[label])
                   for label in set(left) | set(right)],
                  key=lambda row: (-abs(row["delta"]), row["label"]))


def build_report(inputs, metadata=None):
    """Verify the same binary and prepare all pairwise comparison metrics."""
    if len(inputs) < 2:
        raise ValueError("at least two modes are required")
    profiles = [normalize_profile(mode, decoded) for mode, decoded in inputs.items()]
    if len({profile["qemu_sha256"] for profile in profiles}) != 1:
        raise ValueError("profiles were captured from different QEMU binaries")
    pairs = []
    for before in profiles:
        for after in profiles:
            if before["mode"] == after["mode"]:
                continue
            metrics = {}
            for metric in ("cpu_seconds", "share"):
                left, right = weighted_stacks(before, metric), weighted_stacks(after, metric)
                metrics[metric] = dict(tree=stack_tree(left, right),
                                       exclusive=exclusive_diff(left, right))
            pairs.append(dict(before=before["mode"], after=after["mode"], metrics=metrics))
    for profile in profiles:
        profile["tree"] = stack_tree(weighted_stacks(profile, "cpu_seconds"))
    return dict(schema=SCHEMA, caution=CAUTION, metadata=portable_metadata(metadata or {}),
                profiles=profiles, pairs=pairs)


def color(label, delta=None, magnitude=1):
    if delta is not None:
        strength = min(1, abs(delta) / magnitude) if magnitude else 0
        pale = round(240 - 160 * strength)
        return f"rgb(240,{pale},{pale})" if delta >= 0 else f"rgb({pale},{pale},240)"
    digest = hashlib.sha256(label.encode()).digest()
    return f"hsl({digest[0] % 65 + 10},75%,70%)"


def svg_text(tree, title, differential=False, metric="cpu_seconds"):
    """Render an independent SVG with exact weights and escaped labels/tooltips."""
    rectangles = []
    max_depth = 0
    magnitude = max((abs(row["delta"]) for row in flatten_nodes(tree)), default=1)

    def draw(node, x, depth):
        nonlocal max_depth
        max_depth = max(max_depth, depth)
        width = node["weight"] / tree["weight"] * 1200
        unit = "s" if metric == "cpu_seconds" else "share"
        description = (f"{node['label']}: before {node['before']:.9g} {unit}; "
                       f"after {node['after']:.9g} {unit}; delta {node['delta']:+.9g} {unit}")
        fill = color(node["label"], node["delta"] if differential else None, magnitude)
        rectangles.append(
            f'<g><title>{html.escape(description)}</title><rect x="{x:.9f}" '
            f'y="{depth * 22 + 42}" width="{width:.9f}" height="21" '
            f'fill="{fill}" stroke="white" stroke-width="0.4"/></g>')
        if width > 35:
            label = html.escape(node["label"][:int(width / 7)])
            rectangles.append(f'<text x="{x + 3:.9f}" y="{depth * 22 + 57}" '
                              f'font-size="11" font-family="monospace">{label}</text>')
        child_x = x
        for child in node["children"]:
            draw(child, child_x, depth + 1)
            child_x += child["weight"] / tree["weight"] * 1200

    draw(tree, 0, 0)
    height = (max_depth + 1) * 22 + 45
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 {height}">'
            f'<title>{html.escape(title)}</title><text x="8" y="25" font-size="16">'
            f'{html.escape(title)}</text>' + "".join(rectangles) + "</svg>\n")


def flatten_nodes(tree):
    yield tree
    for child in tree["children"]:
        yield from flatten_nodes(child)


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Same-binary QEMU TCG mode comparison</title>
<style>
body{font:15px system-ui,sans-serif;max-width:1800px;margin:24px auto;padding:0 20px;color:#17202a}
h1{font-size:25px}p{line-height:1.5}label{margin-right:18px}select,input,button{font:inherit;padding:5px}
.paired{display:grid;grid-template-columns:1fr 1fr;gap:18px}.graph{overflow:auto;border:1px solid #ddd}
svg{width:100%;min-width:600px}svg g{cursor:pointer}svg text{pointer-events:none;font:11px monospace}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{padding:6px;text-align:left;border-bottom:1px solid #ddd}
pre{white-space:pre-wrap;word-break:break-word}details{margin:16px 0}.positive{color:#a22}.negative{color:#22a}
@media(max-width:900px){.paired{grid-template-columns:1fr}}
</style>
<h1>Same-binary QEMU TCG mode comparison</h1><p id="caution"></p><div id="identities"></div>
<p><label>Baseline <select id="before"></select></label><label>Candidate <select id="after"></select></label>
<label>Difference units <select id="metric"><option value="cpu_seconds">Mean sampled CPU seconds per capture</option>
<option value="share">Normalized sample share</option></select></label></p>
<p><label>Search <input id="search" type="search" placeholder="Function substring"></label>
<button id="reset">Reset zoom</button> Click a frame to zoom; hover for inclusive costs.</p>
<div class="paired"><section><h2 id="left-title"></h2><div id="left" class="graph"></div></section>
<section><h2 id="right-title"></h2><div id="right" class="graph"></div></section></div>
<h2>Candidate minus baseline</h2><p id="diff-summary"></p>
<p>Red: more cost; blue: less cost. Width is the union of per-stack maximum weights. Colors encode
signed inclusive differences; repeated caller frames overlap. Side-by-side graphs each span their own
mean CPU total per capture. Raw pooled totals remain in capture metadata.</p>
<div id="diff" class="graph"></div><h2>Exclusive leaf-function differences</h2>
<p>These rows partition samples by leaf function and are additive. Largest 50 absolute differences are displayed;
all counted stacks and exclusive rows remain embedded in this file.</p><table><thead><tr><th>Function</th>
<th>Baseline</th><th>Candidate</th><th>Difference</th></tr></thead><tbody id="rows"></tbody></table>
<details><summary>Capture metadata and artifact identities</summary><pre id="metadata"></pre></details>
<details><summary>Standalone SVG exports</summary><ul id="exports"></ul></details>
<script id="report" type="application/json">__REPORT__</script>
<script>
"use strict";
const report=JSON.parse(document.getElementById('report').textContent), NS='http://www.w3.org/2000/svg';
const $=id=>document.getElementById(id), zoom={};
$('caution').textContent=report.caution;
$('identities').textContent='Verified identical QEMU ELF SHA-256: '+report.profiles[0].qemu_sha256+
 '; sampling periods: '+report.profiles.map(p=>p.mode+' '+p.sampling_period_us+' µs').join(', ');
$('metadata').textContent=JSON.stringify({metadata:report.metadata,profiles:report.profiles.map(
 p=>({mode:p.mode,total_samples:p.total_samples,capture_count:p.capture_count,sampling_period_us:p.sampling_period_us,
 sampled_cpu_seconds:p.sampled_cpu_seconds,sampled_cpu_seconds_per_capture:p.sampled_cpu_seconds_per_capture,
 elf_sha256:p.elf_sha256,artifact_sha256:p.artifact_sha256}))},null,2);
for(const p of report.profiles){for(const id of ['before','after']){
 const o=document.createElement('option');o.value=p.mode;o.textContent=p.mode;$(id).append(o);}}
$('after').selectedIndex=report.profiles.length-1;
const fmt=(v,metric)=>metric==='share'?(v*100).toFixed(4)+'%':v.toFixed(5)+' s';
function exportLink(filename,label){const li=document.createElement('li'),a=document.createElement('a');
 a.href=filename;a.textContent=label;li.append(a);$('exports').append(li);}
report.profiles.forEach((p,index)=>exportLink(`mode-${index}.svg`,p.mode+' — mean sampled CPU seconds per capture'));
report.pairs.forEach((p,index)=>{for(const metric of ['cpu_seconds','share']){
 exportLink(`diff-${index}-${metric}.svg`,p.after+' minus '+p.before+' — '+metric);}});
function nodes(n){return [n,...n.children.flatMap(nodes)];}
function makeGraph(id,tree,differential,metric){
 const full=tree;for(const index of zoom[id]||[]){tree=tree.children[index];}
 const all=nodes(tree), max=all.reduce((value,n)=>Math.max(value,Math.abs(n.delta)),1e-15);
 const svg=document.createElementNS(NS,'svg');let deepest=0;
 const term=$('search').value.toLowerCase(), unit=metric==='share'?'share':'cpu_seconds';
 function draw(n,x,depth,path){
  const width=n.weight/tree.weight*1200;deepest=Math.max(deepest,depth);
  const g=document.createElementNS(NS,'g'),r=document.createElementNS(NS,'rect'),t=document.createElementNS(NS,'title');
  t.textContent=n.label+' | baseline '+fmt(n.before,unit)+' | candidate '+fmt(n.after,unit)+
   ' | delta '+fmt(n.delta,unit)+' | inclusive width '+(n.weight/tree.weight*100).toFixed(3)+'%';
  r.setAttribute('x',x);r.setAttribute('y',depth*22);r.setAttribute('width',width);r.setAttribute('height',21);
  if(differential){const pale=Math.round(240-160*Math.abs(n.delta)/max);
   r.setAttribute('fill',n.delta>=0?`rgb(240,${pale},${pale})`:`rgb(${pale},${pale},240)`);
  }else{let hash=0;for(const ch of n.label){hash=(hash*31+ch.charCodeAt(0))>>>0;}
   r.setAttribute('fill',`hsl(${hash%65+10},75%,70%)`);}
  r.setAttribute('stroke','white');r.setAttribute('stroke-width','.4');
  if(term&&!n.label.toLowerCase().includes(term)){g.setAttribute('opacity','.25');}
  g.append(t,r);if(width>35){const text=document.createElementNS(NS,'text');
   text.setAttribute('x',x+3);text.setAttribute('y',depth*22+15);
   text.textContent=n.label.slice(0,Math.floor(width/7));g.append(text);}
  g.onclick=()=>{if(path.length){zoom[id]=path;render();}};svg.append(g);
  let childX=x;n.children.forEach((child,index)=>{draw(child,childX,depth+1,[...path,index]);
   childX+=child.weight/tree.weight*1200;});
 }
 draw(tree,0,0,zoom[id]||[]);svg.setAttribute('viewBox',`0 0 1200 ${(deepest+1)*22}`);
 $(id).replaceChildren(svg);
}
function render(){
 if($('before').value===$('after').value){$('after').value=report.profiles.find(p=>p.mode!==$('before').value).mode;}
 const a=report.profiles.find(p=>p.mode===$('before').value),b=report.profiles.find(p=>p.mode===$('after').value);
 const pair=report.pairs.find(p=>p.before===a.mode&&p.after===b.mode),metric=$('metric').value,d=pair.metrics[metric];
 const caption=p=>p.mode+' · '+p.total_samples+' pooled samples / '+p.capture_count+
  ' capture(s) · '+fmt(p.sampled_cpu_seconds_per_capture,'cpu_seconds')+' mean sampled CPU';
 $('left-title').textContent=caption(a);$('right-title').textContent=caption(b);
 makeGraph('left',a.tree,false,'cpu_seconds');makeGraph('right',b.tree,false,'cpu_seconds');makeGraph('diff',d.tree,true,metric);
 $('diff-summary').textContent='Net difference: '+fmt(d.tree.delta,metric)+
  (metric==='share'?' (pooled shares balance to zero; this does not measure the runtime gap).':
   ' (mean sampled CPU cost per capture; this is not wall time).');
 $('rows').replaceChildren();for(const row of d.exclusive.slice(0,50)){
  const tr=document.createElement('tr');for(const item of [row.label,fmt(row.before,metric),fmt(row.after,metric),fmt(row.delta,metric)]){
   const td=document.createElement('td');td.textContent=item;tr.append(td);}
  tr.lastChild.className=row.delta>=0?'positive':'negative';$('rows').append(tr);}
}
for(const id of ['before','after','metric']){$(id).onchange=()=>{for(const key of Object.keys(zoom))delete zoom[key];render();};}
$('search').oninput=render;$('reset').onclick=()=>{for(const key of Object.keys(zoom))delete zoom[key];render();};render();
</script></html>
"""


def render_html(report):
    # A literal closing script tag must never escape the inert JSON container.
    serialized = json.dumps(report, ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return HTML_TEMPLATE.replace("__REPORT__", serialized)


def write_report(report, output):
    """Create a fresh report directory without overwriting retained evidence."""
    output.mkdir(parents=True, exist_ok=False)
    (output / "index.html").write_text(render_html(report), encoding="utf-8")
    (output / "comparison.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for index, profile in enumerate(report["profiles"]):
        title = profile["mode"] + " — mean sampled CPU seconds per capture"
        (output / f"mode-{index}.svg").write_text(svg_text(profile["tree"], title), encoding="utf-8")
    for index, pair in enumerate(report["pairs"]):
        for metric, comparison in pair["metrics"].items():
            units = "mean sampled CPU seconds per capture" if metric == "cpu_seconds" else "pooled share"
            title = f"{pair['after']} minus {pair['before']} — {units}"
            (output / f"diff-{index}-{metric}.svg").write_text(
                svg_text(comparison["tree"], title, True, metric), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", action="append", required=True, metavar="MODE=DECODED_JSON")
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        inputs = {}
        for item in arguments.profile:
            mode, separator, filename = item.partition("=")
            if not separator or not filename or mode in inputs:
                raise ValueError("--profile requires a unique MODE=DECODED_JSON")
            source = Path(filename).read_bytes()
            decoded = json.loads(source)
            if not isinstance(decoded, dict):
                raise ValueError("decoded profile must be an object")
            decoded["decoded_json_sha256"] = hashlib.sha256(source).hexdigest()
            inputs[mode] = decoded
        metadata = json.loads(arguments.metadata.read_text()) if arguments.metadata else {}
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be an object")
        report = build_report(inputs, metadata)
        write_report(report, arguments.output)
    except (OSError, ValueError, RecursionError) as error:
        parser.exit(1, f"flamegraph report rejected: {error}\n")
    print(json.dumps(dict(schema=SCHEMA, modes=list(inputs), status="PASS")))


if __name__ == "__main__":
    main()
