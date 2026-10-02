"""Runs actual image flights from an authenticated future native evaluation.

Preparation authenticates and indexes the candidate without boot selection.
Operator sources select the exact retained effect afterward. Independent slot,
UKI, firmware and boot readings remain separate from checked activation journals.
"""

import base64
import hashlib
import json
import re
import shlex
import time

IMAGE_STATE = "/var/lib/profiles/image/state.json"
ROOT = "/var/lib/aos/native-image-flights"
OPERATIONS = {"imageRollout", "imageSelection", "imageRetirement"}
ORACLE_TOP = None


def read_json(path):
    """Uses the common bounded reader for real guest state."""
    return NATIVE_FLIGHT.read_json(path)


def image_state():
    """Requires the actual durable native image index."""
    state = read_json(IMAGE_STATE)
    if state.get("schema") != "aos.image-generation-state/v1":
        raise RuntimeError("image flight encountered another index format")
    return state


def image_record(top):
    """Requires one physical entitlement for an exact authenticated image."""
    rows = [record for record in image_state()["generations"]
            if record["toplevel"] == top and not record["boot_provider_state"]["evidence"].get("retired", False)]
    if len(rows) != 1:
        raise RuntimeError("image flight has no unique non-retired image entitlement")
    return rows[0]


def write_worktree(path, source, retire=None):
    """Authors ordinary source options; package admission precedes this step."""
    body = "{ lib, ... }: { imports = [ " + source + " ];\n" + IMAGE_SETUP_BODY + OBSERVER_HOST_MODULE
    if retire is not None:
        body += "aos.activation.retire = " + json.dumps([retire]) + ";\n"
    body += "}\n"
    encoded = base64.b64encode(body.encode()).decode()
    runtime.succeed(f"{COREUTILS}/install -d -m0700 {shlex.quote(path)}")
    runtime.succeed(f"printf %s {shlex.quote(encoded)} | {COREUTILS}/base64 -d > {shlex.quote(path + '/image.nix')}")
    return path


def apply_source(path, label):
    """Uses the real package manager and its ordinary retained source transaction."""
    runtime.succeed(f"{APM} switch --worktree {shlex.quote(path)} --eval-root {ROOT}/{shlex.quote(label)}", timeout=1800)


def prepare_candidate():
    """Checks public preparation preserved both running and preferred authority."""
    runtime.assert_published_image("predecessor")
    runtime.stage_published_candidate()
    before = observe()
    qualified = " --qualified" if IMAGE_PURPOSE != "selection" else ""
    record = json.loads(runtime.succeed(f"{APM} --json --yes image prepare aos{qualified}", timeout=3600))
    if (record["toplevel"], record["native_executor_ref"], record["boot_artifact_contract"]) != (IMAGE_CANDIDATE_TOP, IMAGE_CANDIDATE_EXECUTOR, IMAGE_CANDIDATE_CONTRACT):
        raise RuntimeError("prepared signed candidate differs from the case-bound future inputs")
    after = observe()
    for key in ("running", "preferred"):
        if before["selected"][key] != after["selected"][key]:
            raise RuntimeError("preparation changed active boot authority")
    return record


def observe():
    """Reads live firmware/UKI bytes and a foreign file independently in the guest."""
    program = r'''
import hashlib, json, re
from pathlib import Path
import sys
request = json.loads(sys.argv[1])
root = Path('/boot')
def firmware(name):
    matches = list(Path('/sys/firmware/efi/efivars').glob(name + '-*'))
    if not matches:
        return None
    if len(matches) != 1:
        raise RuntimeError('firmware selection repeated')
    data = matches[0].read_bytes()
    if len(data) > 16384 or len(data) < 4:
        raise RuntimeError('firmware selection exceeds bound')
    return data[4:].decode('utf-16-le').rstrip('\x00')
# Exact UKI source bytes are observed without trusting receipt claims about them.
state = json.loads(Path('/var/lib/profiles/image/state.json').read_text())
records = [row for row in state['generations'] if row['toplevel'] == request['candidate'] ]
owners = []
uki = None
if len(records) > 1:
    raise RuntimeError('ambiguous candidate slot ownership')
if records:
    evidence = records[0]['boot_provider_state']['evidence']
    source = root / evidence.get('uki-source-path', evidence['installed-entry'])
    if source.is_symlink():
        raise RuntimeError('physical candidate payload is a foreign symlink')
    if not source.is_file():
        entry = evidence['installed-entry'].rsplit('/', 1)[-1]
        stable = re.sub(r'\+[0-9]+(?:-[0-9]+)?(?=\.efi$)', '', entry)
        pattern = re.escape(stable[:-4]) + r'(?:\+[0-9]+(?:-[0-9]+)?)?\.efi'
        matches = [path for path in (root / 'EFI/Linux').iterdir() if re.fullmatch(pattern, path.name)]
        if len(matches) > 1:
            raise RuntimeError('ambiguous physical candidate payload')
        if matches:
            source = matches[0]
    if source.is_symlink():
        raise RuntimeError('physical candidate entry is a foreign symlink')
    if source.is_file():
        owners = ['physical-slot:' + evidence['slot']]
        uki = hashlib.sha256(source.read_bytes()).hexdigest()
foreign = Path('/var/lib/aos/native-image-flight-foreign')
metadata = foreign.stat()
print(json.dumps({'selected': {
    'owners': owners, 'uki': uki,
    'running': str(Path('/run/current-system').readlink()),
    'preferred': firmware('LoaderEntryPreferred')},
    'foreign': {'digest': hashlib.sha256(foreign.read_bytes()).hexdigest(),
                'mode': metadata.st_mode & 0o7777, 'uid': metadata.st_uid, 'gid': metadata.st_gid}}))
'''
    encoded = base64.b64encode(program.encode()).decode()
    launcher = "import base64;exec(compile(base64.b64decode(" + repr(encoded) + "),'<image-live-oracle>','exec'))"
    return json.loads(runtime.succeed(f"{PYTHON} -c {shlex.quote(launcher)} {shlex.quote(json.dumps({'candidate': ORACLE_TOP or IMAGE_CANDIDATE_TOP}))}"))


def select_effect(cell, adapter):
    """Requires the exact operation, handler and image tuple in the signed carrier."""
    ability = cell["operation"]["ability"]
    matches = [(effect, node) for effect, node in SELECTED_EVALUATION_GRAPH["nodes"].items()
               if node["identity"][-3:-1] == [ability, "ensure"] and node["handler"] == adapter["handler"]]
    if len(matches) != 1:
        raise RuntimeError("image matrix has no unique selected native effect")
    effect, node = matches[0]
    pair = node["input"]["rollout"]
    expected_images = {
        "predecessor": (IMAGE_PREDECESSOR_TOP, IMAGE_PREDECESSOR_EXECUTOR, IMAGE_PREDECESSOR_CONTRACT),
        "candidate": (IMAGE_CANDIDATE_TOP, IMAGE_CANDIDATE_EXECUTOR, IMAGE_CANDIDATE_CONTRACT),
    }
    for role, expected in expected_images.items():
        actual = pair[role]
        if (actual["toplevel"], actual["executor"], actual["boot-artifact-contract"]) != expected:
            raise RuntimeError("selected image tuple belongs to another physical fixture")
    return effect, node


def launch(flight):
    """Uses normal source switching; recovery can span a real machine reboot."""
    if IMAGE_PURPOSE == "qualified" and flight.cell["action"] == "apply":
        runtime.expect_published_image("candidate")
    NATIVE_FLIGHT.start(flight)


def wait_commit(event):
    """Requires the original transaction's actual durable native commit."""
    journal = shlex.quote(NATIVE_FLIGHT.JOURNAL)
    transaction = shlex.quote(event["transaction"])
    runtime.wait_until_succeeds(
        f"{AOS} ability journal {journal} --format json | {JQ} -e --arg t {transaction} '.pending == null and any(.records[]; .event == \"commit\" and .transaction == $t)'", timeout=3600)
    if IMAGE_PURPOSE == "qualified" and event["action"] == "apply":
        runtime.assert_published_image("candidate")


def run_interruption(flight, expected):
    """Retains actual native recovery frames across process loss and boot."""
    boundary = NATIVE_EVIDENCE.SCENARIO_BOUNDARIES[flight.cell["scenario"]["id"]]
    sequence = flight.unit
    runtime.succeed(f"{COREUTILS}/rm -f {NATIVE_FLIGHT.HELD} {NATIVE_FLIGHT.CONTINUE}")
    NATIVE_FLIGHT.select(flight, "intent-durable", sequence + "-baseline", "pause")
    launch(flight)
    event = NATIVE_FLIGHT.wait_held(flight, sequence + "-baseline", "intent-durable")
    baseline = observe()
    if boundary != "intent-durable":
        NATIVE_FLIGHT.select(flight, boundary, sequence, "disconnect")
        NATIVE_FLIGHT.write_canonical(NATIVE_FLIGHT.CONTINUE, {"sequence": sequence + "-baseline"})
        event = NATIVE_FLIGHT.wait_held(flight, sequence, boundary)
    unsettled = observe()
    NATIVE_FLIGHT.stop_interrupted(flight)
    before = NATIVE_FLIGHT.inspect()
    runtime.succeed(f"{COREUTILS}/rm -f {NATIVE_FLIGHT.TARGET}")
    launch(flight)
    wait_commit(event)
    after = NATIVE_FLIGHT.inspect()
    boundaries = [json.loads(line) for line in NATIVE_FLIGHT.read_bounded(NATIVE_FLIGHT.EVENTS).splitlines()]
    NATIVE_BUILDER.retain(flight.cell["id"], NATIVE_EVIDENCE.NativeObservation(
        SELECTED_EVALUATION_GRAPH, event, before, after, boundaries,
        baseline, unsettled, observe(), expected))



def stable_entry(path):
    """Normalizes the actual counted UKI name to its firmware selection ID."""
    name = path.rsplit("/", 1)[-1]
    return re.sub(r"\+[0-9]+(?:-[0-9]+)?(?=\.efi$)", "", name)


def current_reference_graph():
    """Reads the checked committed source graph used by retained transitions."""
    target = runtime.succeed(f"{COREUTILS}/readlink /var/lib/profiles/system/current").strip()
    generation = int(target.rsplit("gen-", 1)[1])
    document = json.loads(runtime.succeed(f"{AOS} ability diagnostic /var/lib/profiles/system {generation} --audience deployment"))
    if document["liveStateVerified"] is not False:
        raise RuntimeError("diagnostic cannot replace the physical oracle")
    return document["desired"]["graph"]


def establish_lease(source, qualified):
    """Completes the actual lease precondition before testing its retirement."""
    worktree = write_worktree(ROOT + "/lease", source)
    if qualified:
        runtime.expect_published_image("candidate")
        unit = "native-image-lease-precondition"
        runtime.succeed(f"{SYSTEMD_RUN} --quiet --unit={unit} --property=Type=exec {APM} switch --worktree {shlex.quote(worktree)} --eval-root {ROOT}/lease-evaluation")
        runtime.wait_until_succeeds(f"test \"$({COREUTILS}/readlink /run/current-system)\" = {shlex.quote(IMAGE_CANDIDATE_TOP)}", timeout=3600)
        runtime.wait_until_succeeds(f"{AOS} ability journal {NATIVE_FLIGHT.JOURNAL} --format json | {JQ} -e '.pending == null and .completed != null'", timeout=3600)
    else:
        apply_source(worktree, "lease-evaluation")
        runtime.expect_published_image("candidate")
        runtime.reboot(timeout=600)
    runtime.assert_published_image("candidate")
    return worktree


def expire_lease(node):
    """Advances actual fixture time past the authenticated operation deadline."""
    deadline = node["input"]["rollout"]["retention-expires-at-millis"]
    runtime.succeed(f"{COREUTILS}/date -s @{deadline // 1000 + 1}")



def suspend_dispatched_handler(flight, node):
    """Blocks only the exact child of the controlled manager for a real deadline."""
    manager = int(runtime.succeed(f"{SYSTEMCTL} show --property=MainPID --value {shlex.quote(flight.unit)}").strip())
    if manager <= 0:
        raise RuntimeError("deadline manager is not running")
    executable = node["handler"]["executable"]
    program = r'''
import json, os, signal, sys, time
from pathlib import Path
request = json.loads(sys.argv[1])
expected = Path(request['executable']).resolve(strict=True)
def child_of(pid):
    seen = set()
    while pid > 1 and pid not in seen:
        seen.add(pid)
        if pid == request['manager']:
            return True
        status = Path('/proc') / str(pid) / 'status'
        fields = dict(line.split(':', 1) for line in status.read_text().splitlines() if ':' in line)
        pid = int(fields['PPid'].strip())
    return False
end = time.monotonic() + 15
while time.monotonic() < end:
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            pid = int(entry.name)
            if (entry / 'exe').resolve(strict=True) == expected and child_of(pid):
                os.kill(pid, signal.SIGSTOP)
                Path(request['receipt']).write_text(json.dumps({'process': pid, 'executable': str(expected)}))
                raise SystemExit(0)
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    time.sleep(0.0001)
raise RuntimeError('selected admitted handler was never suspended')
'''
    request = {"manager": manager, "executable": executable, "receipt": ROOT + "/deadline-substrate.json"}
    encoded = base64.b64encode(program.encode()).decode()
    launcher = "import base64;exec(compile(base64.b64decode(" + repr(encoded) + "),'<image-handler-deadline>','exec'))"
    runtime.succeed(f"{SYSTEMD_RUN} --quiet --unit={shlex.quote(flight.unit + '-deadline-control')} --property=Type=exec {PYTHON} -c {shlex.quote(launcher)} {shlex.quote(json.dumps(request))}")


def inject_owned_conflict(expected, node, after_result=False):
    """Alters only case-bound mutable EFI bytes, leaving the signed index intact."""
    pair = node["input"]["rollout"]
    owned_top = ORACLE_TOP or IMAGE_CANDIDATE_TOP
    request = {"pair": pair, "owned": owned_top, "after_result": after_result}
    program = r'''
import json, os, stat, sys
from pathlib import Path
request = json.loads(sys.argv[1])
root = Path('/boot')
paths = []
for manifest in (root / 'EFI/.aos-rollout-retention').glob('*/manifest.json'):
    if manifest.is_symlink() or not manifest.is_file():
        raise RuntimeError('retained manifest is not regular')
    contents = manifest.read_bytes()
    if len(contents) > 1048576:
        raise RuntimeError('retained manifest exceeds bound')
    value = json.loads(contents)
    if (value['candidate'], value['predecessor']) == (request['pair']['candidate']['boot-artifact-contract'], request['pair']['predecessor']['boot-artifact-contract']):
        paths.append(manifest.parent / 'candidate.efi')
if len(paths) > 1:
    raise RuntimeError('case has ambiguous physical retention leases')
if not paths:
    state = json.loads(Path('/var/lib/profiles/image/state.json').read_text())
    rows = [record for record in state['generations'] if record['toplevel'] == request['owned']]
    if len(rows) != 1:
        raise RuntimeError('owned image record is ambiguous')
    evidence = rows[0]['boot_provider_state']['evidence']
    relative = evidence.get('uki-source-path', evidence['installed-entry'])
    path = root / relative
    if not path.is_relative_to(root / 'EFI') or '..' in path.parts:
        raise RuntimeError('owned conflict escaped EFI namespace')
    paths.append(path)
path = paths[0]
if path.exists() and (path.is_symlink() or not stat.S_ISREG(path.stat().st_mode)):
    raise RuntimeError('owned conflict target is not regular')
path.parent.mkdir(parents=True, exist_ok=True)
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
os.write(fd, b'controlled foreign physical payload\n')
os.fsync(fd)
os.close(fd)
print(json.dumps({'path': str(path)}))
'''
    encoded = base64.b64encode(program.encode()).decode()
    launcher = "import base64;exec(compile(base64.b64decode(" + repr(encoded) + "),'<image-owned-conflict>','exec'))"
    runtime.succeed(f"{MOUNT} -o remount,rw /boot")
    try:
        runtime.succeed(f"{PYTHON} -c {shlex.quote(launcher)} {shlex.quote(json.dumps(request))}")
    finally:
        runtime.succeed(f"{MOUNT} -o remount,ro /boot")
    expected.clear()
    expected.update(observe()["selected"])


def dependent_oracle(remove):
    """Reads the actual reverse-order directory or forward-order systemd unit."""
    if remove:
        program = "import json;from pathlib import Path;p=Path('/var/lib/aos-native-image-prerequisite');s=p.stat();print(json.dumps({'present':p.is_dir(),'mode':s.st_mode&0o7777,'uid':s.st_uid,'gid':s.st_gid,'entries':sorted(x.name for x in p.iterdir())}))"
        return json.loads(runtime.succeed(f"{PYTHON} -c {shlex.quote(program)}"))
    output = runtime.succeed(f"{SYSTEMCTL} show image-qualification-dependent.service --property=LoadState,ActiveState,MainPID")
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def selected_dependency(graph, effect, remove):
    """Requires the real edge supplied by the fixture's native managers."""
    nodes = graph["nodes"]
    if remove:
        matches = [candidate for candidate in nodes[effect]["dependencies"]
                   if nodes[candidate]["identity"][-3:] == ["filesystem", "directory", "native-image-prerequisite"]]
    else:
        matches = [candidate for candidate, node in nodes.items()
                   if effect in node["dependencies"] and node["identity"][-1] == "image-qualification-dependent"]
    if len(matches) != 1:
        raise RuntimeError("image fixture lacks its exact action-specific dependency barrier")
    return matches[0]

def run():
    """Requires one fresh physical image context for each selected domain cell."""
    global ORACLE_TOP
    if len(COHORT_CELLS) != 1:
        raise RuntimeError("physical image flights require one independently booted case per execution")
    runtime.succeed(f"{COREUTILS}/install -d -m0700 {ROOT}")
    runtime.succeed(f"printf '%s\n' foreign-image-flight > /var/lib/aos/native-image-flight-foreign")
    runtime.succeed(f"{COREUTILS}/chmod 0600 /var/lib/aos/native-image-flight-foreign")
    baseline = write_worktree(ROOT + "/baseline", IMAGE_BASELINE_SOURCE)
    apply_source(baseline, "baseline")
    candidate = prepare_candidate()
    cells = {cell["id"]: cell for cell in MATRIX_SPEC["cells"]}
    adapters = {adapter["adapter"]: adapter for adapter in MATRIX_SPEC["surface"]["adapters"]}
    cell = cells[COHORT_CELLS[0]]
    adapter = adapters[cell["adapter"]]
    effect, node = select_effect(cell, adapter)
    if cell["operation"]["ability"] not in OPERATIONS:
        raise RuntimeError("closed image cohort selected another operation")
    scenario = cell["scenario"]["id"]
    source = IMAGE_SCENARIO_SOURCE
    source_path = write_worktree(ROOT + "/scenario", source)
    original = None
    retained = {"activate-retained-target", "retain-persistent-orphan", "retire-explicit-persistent-target"}
    if IMAGE_PURPOSE == "retirement":
        establish_lease(IMAGE_QUALIFIED_SOURCE, True)
        expire_lease(node)
        ORACLE_TOP = IMAGE_PREDECESSOR_TOP
    if cell["action"] == "remove" or scenario in retained:
        if IMAGE_PURPOSE == "retirement":
            apply_source(source_path, "retirement-precondition")
        else:
            establish_lease(source, IMAGE_PURPOSE == "qualified")
            ORACLE_TOP = IMAGE_PREDECESSOR_TOP
        original = current_reference_graph()
        if original["nodes"].get(effect) != node:
            raise RuntimeError("retained image effect differs from the admitted scenario graph")
        if cell["action"] == "remove" or scenario == "retire-explicit-persistent-target":
            expire_lease(node)
        if scenario != "activate-retained-target":
            retirement = effect if cell["action"] == "remove" or scenario == "retire-explicit-persistent-target" else None
            source_path = write_worktree(ROOT + "/withdraw", IMAGE_BASELINE_SOURCE, retirement)
    unit = "native-image-" + hashlib.sha256(cell["id"].encode()).hexdigest()[:20]
    flight = NATIVE_FLIGHT.NativeFlight(cell, effect, source_path, unit, original)
    expected = observe()["selected"]
    if scenario in retained:
        if scenario == "retire-explicit-persistent-target" and IMAGE_PURPOSE != "retirement":
            expected.update(owners=[], uki=None)
        NATIVE_FLIGHT.run_retained_transition(flight, NATIVE_BUILDER, observe, expected)
        return
    if scenario == "cancel-pending-invocation":
        NATIVE_FLIGHT.run_pending_control(flight, NATIVE_BUILDER, observe, expected, launch=NATIVE_FLIGHT.start)
        return
    if scenario == "expire-invocation-deadline":
        NATIVE_FLIGHT.run_pending_control(flight, NATIVE_BUILDER, observe, expected,
            prepare_block=lambda: suspend_dispatched_handler(flight, node), launch=NATIVE_FLIGHT.start)
        receipt = read_json(ROOT + "/deadline-substrate.json")
        if receipt["executable"] != node["handler"]["executable"]:
            raise RuntimeError("deadline did not block the selected immutable handler")
        return
    if scenario == "block-dependent-effect":
        graph = original or SELECTED_EVALUATION_GRAPH
        flight = NATIVE_FLIGHT.NativeFlight(cell, effect, source_path, unit, graph)
        dependent = selected_dependency(graph, effect, cell["action"] == "remove")
        NATIVE_FLIGHT.run_dependency_block(flight, NATIVE_BUILDER, observe, expected, dependent,
            lambda: dependent_oracle(cell["action"] == "remove"),
            lambda: inject_owned_conflict(expected, node), launch=NATIVE_FLIGHT.start)
        return
    if scenario in {"fail-manager-after-dispatch-attempt", "reject-uncertain-recovery", "reject-foreign-resource-mutation"}:
        NATIVE_FLIGHT.run_rejection(flight, NATIVE_BUILDER, observe, expected,
            lambda: inject_owned_conflict(expected, node, scenario == "reject-uncertain-recovery"),
            launch=launch, interruption_boundary="dispatch-started" if cell["action"] == "remove" else "dispatch-returned")
        return
    if scenario not in NATIVE_EVIDENCE.SCENARIO_BOUNDARIES:
        raise RuntimeError("image cell has no implemented physical proof; qualification remains incomplete")
    if IMAGE_PURPOSE == "retirement" or cell["action"] == "remove":
        if IMAGE_PURPOSE != "retirement" or cell["action"] == "apply":
            expected.update(owners=[], uki=None)
    else:
        evidence = candidate["boot_provider_state"]["evidence"]
        expected["preferred"] = stable_entry(evidence["installed-entry"])
        if IMAGE_PURPOSE == "qualified":
            expected["running"] = IMAGE_CANDIDATE_TOP
    run_interruption(flight, expected)
