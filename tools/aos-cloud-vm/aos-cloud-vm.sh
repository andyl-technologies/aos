# Run with: bash tools/aos-cloud-vm/aos-cloud-vm.sh <command> [options]
# Provider CLIs run on the operator's workstation. No ambient project, region,
# network, image, or on-demand fallback is selected by this tool.
set -euo pipefail
umask 077

fail() { printf 'aos-cloud-vm: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || fail "required command is unavailable: $1"; }
usage() {
    cat <<'HELP'
Usage: bash tools/aos-cloud-vm/aos-cloud-vm.sh plan|image-create|vm-create|up|delete [options]

Required: --provider gcp|aws --name NAME --state-dir DIRECTORY
  --hub HTTPS_ORIGIN --registry NAME --release IMMUTABLE_RELEASE --package NAME
  --region REGION --zone ZONE --network NETWORK --subnet SUBNET --bucket BUCKET
  --machine-type TYPE --ssh-key PUBLIC_KEY (--ssh-cidr CIDR | --private-access)
  GCP: --project PROJECT
  AWS: --account ACCOUNT_ID --import-role ROLE_NAME

Configuration:
  --config FILE             Repeatable Nix, JSON, or TOML module input.
  --config-root DIRECTORY   Bundle the bounded source tree, preserving imports.
  --set PATH=VALUE          JSON value, otherwise literal string; last value wins.
  --set-string PATH=VALUE   Always a string. Quoted JSON path segments supported.
  --set-file PATH=FILE      Public UTF-8 file contents as a string.
  --config-signing-key KEY  Sign exact input using SSHSIG namespace aos-config.
  --config-url-ttl SECONDS  Signed download URL lifetime (default 3600).
  --url-signer ACCOUNT     GCP service account authorized to sign object URLs.

Other options:
  --spot true|false         Capacity choice (default true; no fallback).
  --shutdown-after DURATION Automatic deletion after 24h by default; never opts out.
                           Use integer s/m/h/d, from 60s through 120d.
  --scheduler-role ARN      Existing AWS Scheduler role; required for finite lifetime.
  --architecture x86_64|aarch64 (default x86_64)
  --image-state-dir DIR     Reuse the verified owned image from another launch.
  --security-group ID       Existing AWS group (required with private access).
  --delete-image            Also delete the owned image and import objects.
  --disk-size GIB           Boot volume size (default 32).
  --aos PATH               Existing aos CLI (default aos).
  --help

plan validates inputs and writes local preparation artifacts; it never changes
cloud resources. image-create imports the verified Hub disk. vm-create launches
one VM using that owned image. up performs both. delete removes only the
resources recorded in this state directory (requires --provider and --name;
other deployment options are loaded from its private resource record).

First --config is the direct operator module. Additional --config modules are
ordinary imports. Assignments use mkOverride 60: they override ordinary host
values (75) and defaults, while explicit mkForce (50) remains stronger. A
--config-root requires an image advertising aos.config-bundle/v1. Without it,
Nix inputs must be self-contained; JSON/TOML data is embedded, not evaluated
locally. SSH is configured for root public-key login with passwords disabled.
The lifetime begins with the VM launch attempt; retries never extend it.
Automatic deletion retains images, ingress rules, and import/config objects;
run delete to clean up those recorded resources. Provider timing is approximate.
HELP
}

command=${1:-help}
[[ $# -gt 0 ]] && shift
case "$command" in help|--help|-h) usage; exit 0;; plan|image-create|vm-create|up|delete) ;; *) fail "unknown command: $command";; esac
provider= name= state_dir= project= account= region= zone= network= subnet= bucket=
hub= registry= release= package= machine_type= ssh_key= ssh_cidr= config_root=
import_role= signer= config_signing_key= private_access=false
image_state_dir= existing_security_group= delete_image=false
architecture=x86_64 disk_size=32 config_url_ttl=3600 aos=aos
spot=true shutdown_after=24h scheduler_role=
config_args=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h) usage; exit 0;;
        --private-access) private_access=true; shift; continue;;
        --delete-image) delete_image=true; shift; continue;;
        --config|--set|--set-string|--set-file)
            [[ $# -ge 2 ]] || fail "$1 requires a value"
            config_args+=("$1" "$2"); shift 2; continue;;
    esac
    [[ $# -ge 2 ]] || fail "$1 requires a value"
    case "$1" in
        --provider) provider=$2;; --name) name=$2;; --state-dir) state_dir=$2;;
        --project) project=$2;; --account) account=$2;; --region) region=$2;;
        --zone) zone=$2;; --network) network=$2;; --subnet) subnet=$2;;
        --bucket) bucket=$2;; --hub) hub=$2;; --registry) registry=$2;;
        --release) release=$2;; --package) package=$2;; --machine-type) machine_type=$2;;
        --ssh-key) ssh_key=$2;; --ssh-cidr) ssh_cidr=$2;; --config-root) config_root=$2;;
        --import-role) import_role=$2;; --url-signer) signer=$2;;
        --config-signing-key) config_signing_key=$2;; --config-url-ttl) config_url_ttl=$2;;
        --image-state-dir) image_state_dir=$2;; --security-group) existing_security_group=$2;;
        --architecture) architecture=$2;; --disk-size) disk_size=$2;; --aos) aos=$2;;
        --spot) spot=$2;; --shutdown-after) shutdown_after=$2;; --scheduler-role) scheduler_role=$2;;
        *) fail "unknown option: $1";;
    esac
    shift 2
done
[[ $provider == gcp || $provider == aws ]] || fail '--provider must be gcp or aws'
[[ $name =~ ^[a-z][a-z0-9-]{0,39}$ ]] || fail '--name must be 1..40 lowercase letters/digits/hyphens, starting with a letter'
[[ -n $state_dir ]] || fail '--state-dir is required'
need jq
need python3
mkdir -p "$state_dir"
state_dir=$(cd "$state_dir" && pwd -P)
chmod 700 "$state_dir"
state=$state_dir/resources.json
# A lock directory covers the complete lifecycle, including provider waits.
mkdir "$state_dir/lock" 2>/dev/null || fail "state directory is locked: $state_dir/lock"
trap 'rmdir "$state_dir/lock"' EXIT

record() {
    jq --arg key "$1" --arg value "$2" '.[$key] = $value' "$state" > "$state_dir/resources.new"
    mv "$state_dir/resources.new" "$state"
}
field() { jq -r --arg key "$1" '.[$key] // empty' "$state"; }
gcp() { gcloud --quiet --project "$project" "$@"; }
aws_cli() { aws --region "$region" --no-cli-pager "$@"; }

vm_owner() {
    local token
    token=$(field launch_token)
    printf 'aos.cloud-vm/v1 %s%s' "$(field identity)" "${token:+ $token}"
}

delete_schedule() {
    local schedule
    schedule=$(field schedule)
    [[ -n $schedule ]] || return 0
    if aws_cli scheduler get-schedule --name "$schedule" --group-name default > "$state_dir/schedule.json" 2> "$state_dir/schedule-error"; then
        [[ $(jq -r '.Description' "$state_dir/schedule.json") == "$(field schedule_owner)" ]] || fail 'scheduled deletion belongs to another launch'
        aws_cli scheduler delete-schedule --name "$schedule" --group-name default
    else
        [[ $(< "$state_dir/schedule-error") == *ResourceNotFoundException* ]] || fail 'cannot verify recorded deletion schedule'
    fi
    record schedule ''
}

verify_aws_instance() {
    jq -e --arg owner "$(field identity)" --arg token "$(field launch_token)" \
        '[.Reservations[].Instances[]] | length == 1 and all(.[];
          any(.Tags[]?; .Key == "aos-cloud-vm" and .Value == $owner)
          and ($token == "" or .ClientToken == $token))' "$1" >/dev/null
}

banner_notice() {
    local deadline=$1
    [[ $spot == true || $shutdown_seconds -gt 0 ]] || return 0
    printf 'Ephemeral AOS VM. '
    if [[ $shutdown_seconds -gt 0 ]]; then
        printf 'Automatic deletion scheduled: %s. ' "$deadline"
        if [[ $provider == gcp ]]; then
            printf 'GCP may begin deletion up to 30 seconds later. '
        else
            printf 'AWS Scheduler uses minute precision; retries can delay deletion. '
        fi
    else
        printf 'No automatic deletion is scheduled. '
    fi
    [[ $spot != true ]] || printf 'Spot capacity may end earlier. '
    printf '\n'
}

# Render only the generated layer from the already captured source tree. No
# source is reread after image import, and substitutions cannot touch user text.
render_config() {
    python3 - "$state_dir/config-template.json" "$1" "$2" <<'PY'
import base64, json, pathlib, shlex, sys
template = json.loads(pathlib.Path(sys.argv[1]).read_text())
notice = sys.argv[3]
fragment = ("case $- in *i*) printf '%s\\n' " + shlex.quote(notice) + ";; esac\n") if notice else ""
encoded = json.dumps(fragment, ensure_ascii=False).replace('${', '\\${')
module = template['prefix'] + encoded + template['suffix']
if template['mode'] == 'bundle':
    files = template['files']
    files['_aos_cloud/entry.nix'] = base64.b64encode(module.encode()).decode()
    if sum(len(base64.b64decode(value)) for value in files.values()) > 8 * 1024 * 1024:
        raise SystemExit('config root plus generated entrypoint exceeds 8 MiB')
    payload = json.dumps(dict(schema='aos.config-bundle/v1', entrypoint='_aos_cloud/entry.nix', files=files), sort_keys=True, separators=(',', ':')).encode()
else:
    payload = module.encode()
if len(payload) > 16 * 1024 * 1024:
    raise SystemExit('encoded configuration exceeds 16 MiB')
pathlib.Path(sys.argv[2]).write_bytes(payload)
PY
}

load_state() {
    [[ -f $state ]] || fail 'no resource record exists'
    [[ $(field schema) == aos.cloud-vm/v1 && $(field provider) == "$provider" && $(field name) == "$name" ]] || fail 'resource record belongs to another deployment'
    project=$(field project); account=$(field account); region=$(field region); zone=$(field zone)
    network=$(field network); subnet=$(field subnet); bucket=$(field bucket)
}

verify_account() {
    if [[ $provider == gcp ]]; then
        need gcloud
        [[ $(gcp projects describe "$project" --format='value(projectId)') == "$project" ]] || fail 'GCP project identity mismatch'
    else
        need aws
        [[ $(aws_cli sts get-caller-identity --query Account --output text) == "$account" ]] || fail 'AWS account identity mismatch'
    fi
}

# Deletion checks recorded identities and never performs bucket-wide operations.
delete_resources() {
    load_state
    verify_account
    if [[ $provider == gcp ]]; then
        if [[ -n $(field instance) || -n $(field launch_token) ]]; then
            owned_name=$(field instance)
            [[ -n $owned_name ]] || owned_name="$name-$(field identity | cut -c1-12)"
            gcp compute instances list --zones "$zone" --filter "name=$owned_name" --format=json > "$state_dir/live-instances.json"
            [[ $(jq 'length' "$state_dir/live-instances.json") -le 1 ]] || fail 'ambiguous VM cleanup lookup'
            if [[ $(jq 'length' "$state_dir/live-instances.json") -gt 0 ]]; then
                [[ $(jq -r '.[0].description' "$state_dir/live-instances.json") == "$(vm_owner)" ]] || fail 'recorded VM name now belongs to another owner'
                [[ -z $(field instance_id) || $(jq -r '.[0].id' "$state_dir/live-instances.json") == "$(field instance_id)" ]] || fail 'recorded VM was replaced'
                gcp compute instances delete "$owned_name" --zone "$zone"
            elif [[ $(field launch_phase) == launching ]]; then
                fail 'launch outcome is unresolved; retain the state and retry after the provider operation settles'
            fi
            record instance ''
        fi
        if [[ -n $(field firewall) ]]; then
            gcp compute firewall-rules delete "$(field firewall)"
            record firewall ''
        fi
        if [[ $delete_image == true && $(field owns_image) == true && -n $(field image) ]]; then
            gcp compute images delete "$(field image)"
            record image ''
        fi
        for key in image_object config_object signature_object; do
            [[ $key != image_object || $delete_image == true ]] || continue
            if [[ -n $(field "$key") ]]; then
                gcp storage rm "gs://$bucket/$(field "$key")"
                record "$key" ''
            fi
        done
    else
        if [[ -z $(field instance) && -n $(field launch_token) ]]; then
            aws_cli ec2 describe-instances --filters "Name=client-token,Values=$(field launch_token)" > "$state_dir/live-instances.json"
            if [[ $(jq '[.Reservations[].Instances[]] | length' "$state_dir/live-instances.json") -gt 0 ]]; then
                verify_aws_instance "$state_dir/live-instances.json" || fail 'AWS launch-token cleanup found unexpected ownership'
                record instance "$(jq -er '.Reservations[0].Instances[0].InstanceId' "$state_dir/live-instances.json")"
            elif [[ $(field launch_phase) == launching ]]; then
                fail 'AWS launch outcome is unresolved; retain the token and retry cleanup after it becomes visible'
            fi
        fi
        if [[ -n $(field instance) ]]; then
            if aws_cli ec2 describe-instances --instance-ids "$(field instance)" > "$state_dir/live-instances.json" 2> "$state_dir/instance-error"; then
                verify_aws_instance "$state_dir/live-instances.json" || fail 'recorded AWS instance ownership changed'
                if [[ $(jq -r '.Reservations[0].Instances[0].State.Name' "$state_dir/live-instances.json") != terminated ]]; then
                    aws_cli ec2 terminate-instances --instance-ids "$(field instance)" >/dev/null
                    aws_cli ec2 wait instance-terminated --instance-ids "$(field instance)"
                fi
            else
                [[ $(< "$state_dir/instance-error") == *InvalidInstanceID.NotFound* ]] || fail 'cannot verify recorded AWS instance'
                [[ $(field launch_phase) == active || $(field launch_phase) == terminated || -z $(field launch_token) ]] || fail 'AWS instance creation is not yet resolved; keep the launch evidence'
            fi
            record instance ''
        fi
        delete_schedule
        if [[ $(field owns_security_group) == true && -n $(field security_group) ]]; then
            aws_cli ec2 delete-security-group --group-id "$(field security_group)"
            record security_group ''
        fi
        if [[ $delete_image == true && $(field owns_image) == true && -n $(field image) ]]; then
            aws_cli ec2 deregister-image --image-id "$(field image)"
            record image ''
        fi
        if [[ $delete_image == true && -n $(field import_task) && -z $(field snapshot) ]]; then
            aws_cli ec2 cancel-import-task --import-task-id "$(field import_task)" >/dev/null
            record import_task ''
        fi
        if [[ $delete_image == true && -n $(field snapshot) ]]; then
            aws_cli ec2 delete-snapshot --snapshot-id "$(field snapshot)"
            record snapshot ''
        fi
        for key in image_object config_object signature_object; do
            [[ $key != image_object || $delete_image == true ]] || continue
            if [[ -n $(field "$key") ]]; then
                aws_cli s3 rm "s3://$bucket/$(field "$key")"
                record "$key" ''
            fi
        done
    fi
    for key in instance_id launch_token launch_phase deadline deadline_epoch payload_sha256 user_data_sha256 config_url_expires_epoch; do record "$key" ''; done
    rm -f "$state_dir/launch-config" "$state_dir/launch-config.sig" "$state_dir/user-data"
    printf 'Deleted resources recorded in %s\n' "$state"
}
if [[ $command == delete ]]; then delete_resources; exit 0; fi

for required in region zone network subnet bucket hub registry release package machine_type ssh_key; do
    [[ -n ${!required} ]] || fail "--${required//_/-} is required"
done
[[ $hub == https://* ]] || fail '--hub requires HTTPS'
[[ $architecture == x86_64 || $architecture == aarch64 ]] || fail 'unsupported architecture'
[[ $disk_size =~ ^[0-9]+$ && $disk_size -ge 8 && $disk_size -le 16384 ]] || fail '--disk-size must be 8..16384 GiB'
[[ $config_url_ttl =~ ^[0-9]+$ && $config_url_ttl -ge 300 && $config_url_ttl -le 604800 ]] || fail '--config-url-ttl must be 300..604800 seconds'
[[ $spot == true || $spot == false ]] || fail '--spot must be true or false'
shutdown_seconds=$(python3 - "$shutdown_after" <<'PY'
import re, sys
value = sys.argv[1]
if value == 'never':
    print(0)
else:
    match = re.fullmatch(r'([1-9][0-9]*)([smhd])', value)
    if not match:
        raise SystemExit('--shutdown-after requires integer s/m/h/d or never')
    seconds = int(match[1]) * {'s':1, 'm':60, 'h':3600, 'd':86400}[match[2]]
    if not 60 <= seconds <= 120 * 86400:
        raise SystemExit('--shutdown-after must be from 60s through 120d')
    print(seconds)
PY
)
if [[ $provider == gcp ]]; then
    [[ -n $project && -z $account ]] || fail 'GCP requires --project and does not accept --account'
    [[ $architecture == x86_64 ]] || fail 'GCP launcher currently supports qualified x86_64 VirtIO machine families only'
    [[ $machine_type == e2-* || $machine_type == n2-* || $machine_type == n2d-* ]] || fail 'GCP requires a VirtIO-capable e2, n2, or n2d machine type'
    [[ $zone == "$region"-* ]] || fail 'zone does not belong to the explicit region'
    [[ -z $scheduler_role ]] || fail '--scheduler-role is only supported for AWS'
else
    [[ $account =~ ^[0-9]{12}$ && -n $import_role ]] || fail 'AWS requires --account with 12 digits and --import-role'
    if [[ $shutdown_seconds -gt 0 ]]; then
        [[ $scheduler_role =~ ^arn:aws:iam::$account:role/[A-Za-z0-9+=,.@_/-]+$ ]] || fail 'finite AWS lifetime requires --scheduler-role in the explicit account (or --shutdown-after never)'
    fi
fi
if [[ $private_access == true ]]; then
    [[ -z $ssh_cidr ]] || fail 'choose --ssh-cidr or --private-access'
    [[ $provider != aws || -n $existing_security_group ]] || fail 'AWS private access requires --security-group allowing your existing private route'
else
    [[ -n $ssh_cidr ]] || fail 'explicit --ssh-cidr or --private-access is required'
fi

# The helper only packages public source/data and encodes Nix assignments. Nix
# remains the engine: no module evaluation happens on the launcher workstation.
python3 - "$state_dir" "$config_root" "$ssh_key" "$ssh_cidr" "${config_args[@]}" <<'PY'
import base64
import ipaddress
import json
import pathlib
import re
import sys

out, root_text, key_path, cidr, *arguments = sys.argv[1:]
out = pathlib.Path(out)
if cidr:
    network = ipaddress.ip_network(cidr, strict=True)
    if network.version != 4 or network.prefixlen < 8:
        raise SystemExit('SSH ingress requires an explicit IPv4 CIDR narrower than /7')
key = pathlib.Path(key_path).read_text().strip()
if '\n' in key or not re.fullmatch(r'(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/]+={0,2}(?: [^\r\n]*)?', key):
    raise SystemExit('SSH key must contain one OpenSSH public key, without options')

def nix_string(value):
    return json.dumps(value, ensure_ascii=False).replace('${', '\\${')

def option_path(value):
    parts = []
    decoder = json.JSONDecoder()
    while value:
        if value.startswith('"'):
            part, length = decoder.raw_decode(value)
            if not isinstance(part, str) or not part:
                raise ValueError('empty/invalid quoted option segment')
        else:
            match = re.match(r"[A-Za-z_][A-Za-z0-9_'-]*", value)
            if not match:
                raise ValueError('invalid option path: ' + value)
            part, length = match.group(), match.end()
        parts.append(part)
        value = value[length:]
        if value:
            if not value.startswith('.') or value == '.':
                raise ValueError('invalid option path separator')
            value = value[1:]
    if not parts or len(parts) > 64:
        raise ValueError('empty or excessively deep option path')
    return tuple(parts)

configs, assignments = [], {}
for flag, value in zip(arguments[::2], arguments[1::2]):
    if flag == '--config':
        configs.append(pathlib.Path(value).resolve(strict=True))
        continue
    path, separator, value = value.partition('=')
    if not separator:
        raise ValueError(flag + ' requires PATH=VALUE')
    path = option_path(path)
    if flag == '--set-file':
        value = pathlib.Path(value).read_text()
    elif flag == '--set':
        try:
            value = json.loads(value, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
        except (ValueError, json.JSONDecodeError):
            pass
    assignments[path] = value
for path in assignments:
    if any(path[:length] in assignments for length in range(1, len(path))):
        raise ValueError('assignment parent/child collision: ' + repr(path))

root = pathlib.Path(root_text).resolve(strict=True) if root_text else None
files = {}
if root:
    total = 0
    for index, path in enumerate(root.rglob('*')):
        if index >= 32000:
            raise ValueError('config root exceeds 32000 directory entries')
        relative = path.relative_to(root).as_posix()
        parts = relative.split('/')
        if path.is_symlink() or len(parts) > 32 or len(relative) > 512 or any(not re.fullmatch(r'[A-Za-z0-9_.-]+', part) or part in ('.', '..') for part in parts):
            raise ValueError('unsafe config source path: ' + relative)
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError('config source contains a special file')
        if relative == '_aos_cloud' or relative.startswith('_aos_cloud/'):
            raise ValueError('_aos_cloud is reserved for generated configuration')
        total += path.stat().st_size
        if total > 8 * 1024 * 1024 or len(files) >= 1000:
            raise ValueError('config root exceeds 8 MiB or 1000 files')
        files[relative] = base64.b64encode(path.read_bytes()).decode()

def module_expression(path):
    if path.suffix not in ('.nix', '.json', '.toml'):
        raise ValueError('config must be .nix, .json, or .toml')
    if root:
        relative = path.relative_to(root).as_posix()
        if relative not in files:
            raise ValueError('config entrypoint is not a regular included file')
        source = '../' + relative
        if path.suffix == '.nix':
            return '(import ./' + source + ')'
        data = '(builtins.readFile ./' + source + ')'
    else:
        data = nix_string(path.read_text())
        if path.suffix == '.nix':
            return '(' + path.read_text() + '\n)'
    return '(builtins.from' + ('JSON' if path.suffix == '.json' else 'TOML') + ' ' + data + ')'

expressions = [module_expression(path) for path in configs]
first = expressions[0] if expressions else '{}'
additional = ' '.join(expressions[1:])
values = []
for path, value in assignments.items():
    encoded = nix_string(json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(',', ':')))
    attributes = ' '.join(nix_string(part) for part in path)
    values.append('(lib.setAttrByPath [ ' + attributes + ' ] (lib.mkOverride 60 (builtins.fromJSON ' + encoded + ')))')

# Apply the original root function with the evaluator's standard/special args,
# retaining the same lazy required-argument fallback to config._module.args.
module = '''args:
let
  lib = args.lib;
  banner = BANNER;
  original = FIRST;
  required = if builtins.isFunction original then builtins.functionArgs original else {};
  proxies = builtins.mapAttrs (name: _: args.${name} or args.config._module.args.${name})
    (lib.filterAttrs (name: hasDefault: !hasDefault || builtins.hasAttr name args) required);
  host = if builtins.isFunction original then original (args // proxies) else original;
  originalConfig = host.config or (builtins.removeAttrs host [ "options" "imports" "require" "_file" "_type" "freeformType" "strict" ]);
in host // {
  imports = (host.imports or []) ++ [ ADDITIONAL ];
  config = lib.mkMerge ([ originalConfig ] ++ [ ASSIGNMENTS ] ++ [{
    aos.services.ssh.enable = lib.mkForce true;
    aos.services.ssh.passwordAuthentication = lib.mkForce false;
    aos.services.ssh.kbdInteractiveAuthentication = lib.mkForce false;
    aos.services.ssh.permitRootLogin = lib.mkForce "prohibit-password";
    environment.etc."ssh/authorized_keys/root".text = lib.mkForce KEY;
  }] ++ lib.optional (banner != "") {
    environment.etc."profile.local".text = banner;
  });
}
'''
substitutions = {'FIRST': first, 'ADDITIONAL': additional, 'ASSIGNMENTS': '\n    '.join(values), 'KEY': nix_string(key + '\n')}
prefix, suffix = module.split('BANNER')
def substitute(part):
    return re.sub(r'\b(FIRST|ADDITIONAL|ASSIGNMENTS|KEY)\b', lambda match: substitutions[match.group()], part)
mode = 'bundle' if root else 'literal'
(out / 'config-template.json').write_text(json.dumps(dict(prefix=substitute(prefix), suffix=substitute(suffix), files=files, mode=mode)))
(out / 'config-mode').write_text(mode)
PY
render_config "$state_dir/config-payload" "$(banner_notice 'assigned when VM launch begins (UTC)')"

need "$aos"
selection=(--hub "$hub" --registry "$registry" --release "$release" --package "$package" --architecture "$architecture" --format raw)
"$aos" --json image show "${selection[@]}" > "$state_dir/image-selection.json"
image_sha=$(jq -er '.sha256 | select(test("^[a-f0-9]{64}$"))' "$state_dir/image-selection.json")
[[ $(jq -r '.release' "$state_dir/image-selection.json") == "$release" ]] || fail 'resolved release differs from immutable selection'
config_mode=$(cat "$state_dir/config-mode")
config_sha=$(sha256sum "$state_dir/config-payload" | cut -d' ' -f1)

# image-info identity is authenticated by aos image show. The companion is
# downloaded by the existing aos verifier, including its signed NAR fallback.
"$aos" image download "${selection[@]}" --metadata-only --output "$state_dir/image-info.json" > /dev/null
python3 - "$state_dir/image-info.json" "$provider" "$config_mode" "$disk_size" <<'PY'
import json, sys
info = json.load(open(sys.argv[1]))
provider, mode, size = sys.argv[2], sys.argv[3], int(sys.argv[4]) * 1024**3
caps = info.get('capabilities', {})
protocols = caps.get('configuration', info.get('configurationCapabilities', []))
if mode == 'bundle' and 'aos.config-bundle/v1' not in protocols:
    raise SystemExit('selected image lacks aos.config-bundle/v1; use self-contained --config/--set or publish a bundle-capable image')
logical_size = info.get('disk', {}).get('logical', {}).get('size_bytes', info.get('virtualSizeBytes', 0))
if not logical_size or logical_size > size:
    raise SystemExit('boot volume is smaller than the authenticated logical disk, or geometry is missing')
if not caps:
    raise SystemExit('selected image lacks an authenticated driver inventory required for cloud preflight')
if caps.get('kernel_options', {}).get('CONFIG_EFI') != 'y':
    raise SystemExit('image does not advertise EFI support')
for driver in (['virtio_pci', 'virtio_scsi', 'virtio_net'] if provider == 'gcp' else ['nvme', 'ena']):
    for stage in ['initrd', 'runtime']:
        if driver not in caps.get('builtin_drivers', []) and driver not in caps.get('stages', {}).get(stage, {}).get('modules', {}):
            raise SystemExit(f'image lacks {driver} in {stage}')
PY

if [[ $config_mode == bundle || -n $config_signing_key || $(wc -c < "$state_dir/config-payload") -gt 15000 ]]; then
    pointer=true
    if [[ $provider == gcp ]]; then
        jq -e '(.capabilities.configuration // .configurationCapabilities // []) | index("aos.config-bundle/v1") != null' "$state_dir/image-info.json" >/dev/null || fail 'GCP pointer delivery requires a bundle-capable guest; use smaller unsigned inline input on this image'
    fi
    if [[ $provider == gcp && -z $signer ]]; then
        fail 'GCP pointer delivery requires --url-signer (an existing signing service account)'
    fi
else
    pointer=false
fi

# Identity includes all launch inputs and source bytes. Reusing a directory with
# different intent is an error, even if its cloud resources were partly created.
jq -n --arg provider "$provider" --arg name "$name" --arg project "$project" --arg account "$account" \
    --arg region "$region" --arg zone "$zone" --arg network "$network" --arg subnet "$subnet" \
    --arg bucket "$bucket" --arg machine "$machine_type" --arg disk "$disk_size" \
    --arg source "$image_sha" --arg config "$config_sha" --arg cidr "$ssh_cidr" \
    --arg private "$private_access" --arg architecture "$architecture" --arg securityGroup "$existing_security_group" \
    --argjson spot "$spot" --argjson lifetime "$shutdown_seconds" --arg schedulerRole "$scheduler_role" \
    '{preparation:"aos.cloud-vm/v1",provider:$provider,name:$name,project:$project,account:$account,region:$region,zone:$zone,network:$network,subnet:$subnet,bucket:$bucket,machine:$machine,disk:$disk,source:$source,config:$config,cidr:$cidr,private:$private,architecture:$architecture,securityGroup:$securityGroup,spot:$spot,shutdownAfterSeconds:$lifetime,schedulerRole:$schedulerRole}' > "$state_dir/intent.json"
identity=$(sha256sum "$state_dir/intent.json" | cut -d' ' -f1)
if [[ -e $state ]]; then
    [[ $(field identity) == "$identity" ]] || fail 'state directory has different source/preparation identity; choose another directory'
else
    jq --arg identity "$identity" '. + {schema:"aos.cloud-vm/v1",identity:$identity}' "$state_dir/intent.json" > "$state"
fi
if [[ -n $image_state_dir ]]; then
    source_state="$image_state_dir/resources.json"
    [[ -f $source_state ]] || fail 'image-state directory has no resource record'
    for key in provider project account region source disk architecture; do
        [[ $(jq -r --arg key "$key" '.[$key] // empty' "$source_state") == "$(field "$key")" ]] || fail "reused image has different $key identity"
    done
    image=$(jq -er '.image | select(length > 0)' "$source_state")
    if [[ -n $(field image) && $(field image) != "$image" ]]; then fail 'state already records a different image'; fi
    record image "$image"
    record image_owner_identity "$(jq -er '.image_owner_identity // .identity' "$source_state")"
    record owns_image false
fi
resource_name="$name-${identity:0:12}"
object_prefix="aos-cloud-vm/$resource_name"
if [[ $command == plan ]]; then
    jq --arg mode "$config_mode" --arg pointer "$pointer" \
        '. + {configurationMode:$mode,pointerDelivery:$pointer,capacity:(if .spot then "spot" else "on-demand" end),secureBoot:false}' "$state_dir/intent.json"
    exit 0
fi
verify_account

prepare_disk() {
    need zstd
    "$aos" image download "${selection[@]}" --output "$state_dir/image.download"
    case $(jq -r '.compression' "$state_dir/image-selection.json") in
        zstd) zstd -d -f "$state_dir/image.download" -o "$state_dir/disk.raw";;
        none) cp --sparse=always "$state_dir/image.download" "$state_dir/disk.raw";;
        *) fail 'unsupported authenticated raw compression';;
    esac
    expected=$(jq -er '.disk.logical.sha256 // .logicalDiskSha256' "$state_dir/image-info.json")
    [[ $(sha256sum "$state_dir/disk.raw" | cut -d' ' -f1) == "${expected#sha256:}" ]] || fail 'decompressed logical disk hash mismatch'
    need sgdisk
    truncate -s "${disk_size}G" "$state_dir/disk.raw"
    sgdisk -e "$state_dir/disk.raw" >/dev/null
    record prepared_sha256 "$(sha256sum "$state_dir/disk.raw" | cut -d' ' -f1)"
}

verify_image() {
    local owner attempt status
    owner=$(field image_owner_identity)
    [[ -n $owner ]] || fail 'image record has no ownership identity'
    if [[ $provider == gcp ]]; then
        for ((attempt = 0; attempt < 360; attempt++)); do
            gcp compute images describe "$(field image)" --format=json > "$state_dir/image-status.json"
            [[ $(jq -r '.description' "$state_dir/image-status.json") == "aos.cloud-vm/v1 $owner" ]] || fail 'cloud image ownership/source identity mismatch'
            status=$(jq -r '.status' "$state_dir/image-status.json")
            case $status in
                READY) return;;
                PENDING) sleep 10;;
                *) fail "cloud image is not usable (status: $status)";;
            esac
        done
        fail 'cloud image remained PENDING for one hour; retry after checking the provider operation'
    else
        [[ $(aws_cli ec2 describe-images --owners "$account" --image-ids "$(field image)" --query 'Images[0].Description' --output text) == "aos.cloud-vm/v1 $owner" ]] || fail 'AMI ownership/source identity mismatch'
    fi
}

create_image() {
    if [[ -n $(field image) ]]; then
        verify_image
        printf 'Reusing owned image %s\n' "$(field image)"
        return
    fi
    # A provider may commit creation before the local process records its ID.
    # Reconcile only this deterministic name and its complete ownership stamp.
    if [[ $provider == gcp ]]; then
        gcp compute images list --no-standard-images --filter "name=$resource_name" --format=json > "$state_dir/matching-images.json"
        if [[ $(jq 'length' "$state_dir/matching-images.json") -gt 0 ]]; then
            [[ $(jq -r '.[0].description' "$state_dir/matching-images.json") == "aos.cloud-vm/v1 $identity" ]] || fail 'image name belongs to different preparation identity'
            record image "$resource_name"
            record image_owner_identity "$identity"
            record owns_image true
            verify_image
            return
        fi
    else
        aws_cli ec2 describe-images --owners "$account" --filters "Name=name,Values=$resource_name" > "$state_dir/matching-images.json"
        if [[ $(jq '.Images | length' "$state_dir/matching-images.json") -gt 0 ]]; then
            [[ $(jq -r '.Images[0].Description' "$state_dir/matching-images.json") == "aos.cloud-vm/v1 $identity" ]] || fail 'AMI name belongs to different preparation identity'
            record image "$(jq -er '.Images[0].ImageId' "$state_dir/matching-images.json")"
            record image_owner_identity "$identity"
            record owns_image true
            verify_image
            return
        fi
    fi
    prepare_disk
    record owns_image true
    record image_owner_identity "$identity"
    if [[ $provider == gcp ]]; then
        need tar
        tar --format=oldgnu --sparse -C "$state_dir" -czf "$state_dir/disk.tar.gz" disk.raw
        object="$object_prefix/disk.tar.gz"
        if gcp storage objects describe "gs://$bucket/$object" --format=json > "$state_dir/object.json" 2> "$state_dir/object-error"; then
            [[ $(jq -r '.metadata["aos-prepared-sha256"] // .custom_metadata["aos-prepared-sha256"] // empty' "$state_dir/object.json") == "$(field prepared_sha256)" ]] || fail 'existing image upload has different preparation identity'
        else
            gcp storage cp --if-generation-match=0 \
                --custom-metadata "aos-prepared-sha256=$(field prepared_sha256)" \
                "$state_dir/disk.tar.gz" "gs://$bucket/$object"
        fi
        record image_object "$object"
        gcp compute images create "$resource_name" --source-uri "gs://$bucket/$object" \
            --guest-os-features UEFI_COMPATIBLE --architecture X86_64 \
            --labels "aos-cloud-vm=${identity:0:63}" --description "aos.cloud-vm/v1 $identity"
        record image "$resource_name"
    else
        object="$object_prefix/disk.raw"
        aws_cli s3 cp "$state_dir/disk.raw" "s3://$bucket/$object" --only-show-errors
        record image_object "$object"
        jq -n --arg bucket "$bucket" --arg key "$object" \
            '{Format:"RAW",UserBucket:{S3Bucket:$bucket,S3Key:$key}}' > "$state_dir/import-disk.json"
        if [[ -z $(field import_task) ]]; then
            task=$(aws_cli ec2 import-snapshot --description "aos.cloud-vm/v1 $identity" \
                --client-token "${identity:0:64}" --role-name "$import_role" \
                --disk-container "file://$state_dir/import-disk.json" --query ImportTaskId --output text)
            record import_task "$task"
        fi
        for ((attempt=0; attempt<360; attempt++)); do
            aws_cli ec2 describe-import-snapshot-tasks --import-task-ids "$(field import_task)" > "$state_dir/import-status.json"
            status=$(jq -r '.ImportSnapshotTasks[0].SnapshotTaskDetail.Status' "$state_dir/import-status.json")
            case "$status" in
                completed) record snapshot "$(jq -er '.ImportSnapshotTasks[0].SnapshotTaskDetail.SnapshotId' "$state_dir/import-status.json")"; break;;
                active|pending) sleep 10;;
                *) fail "snapshot import failed ($status); inspect $state_dir/import-status.json";;
            esac
        done
        [[ -n $(field snapshot) ]] || fail 'snapshot import timed out; rerun image-create to resume'
        jq -n --arg snapshot "$(field snapshot)" \
            '[{DeviceName:"/dev/sda1",Ebs:{SnapshotId:$snapshot,VolumeType:"gp3",DeleteOnTermination:true}}]' > "$state_dir/image-mappings.json"
        image=$(aws_cli ec2 register-image --name "$resource_name" --description "aos.cloud-vm/v1 $identity" \
            --architecture "${architecture/aarch64/arm64}" --virtualization-type hvm --boot-mode uefi --ena-support \
            --root-device-name /dev/sda1 --block-device-mappings "file://$state_dir/image-mappings.json" \
            --query ImageId --output text)
        record image "$image"
        aws_cli ec2 wait image-available --image-ids "$image"
    fi
}

preflight_scheduler() {
    [[ $provider == aws && $shutdown_seconds -gt 0 ]] || return 0
    aws_cli iam get-role --role-name "${scheduler_role##*/}" > "$state_dir/scheduler-role.json"
    jq -e --arg arn "$scheduler_role" '.Role.Arn == $arn and any(.Role.AssumeRolePolicyDocument.Statement[];
      .Effect == "Allow" and ([.Principal.Service] | flatten | index("scheduler.amazonaws.com") != null))' \
        "$state_dir/scheduler-role.json" >/dev/null || fail 'scheduler role identity or service trust is missing'
    aws_cli scheduler get-schedule-group --name default > /dev/null
}

freeze_launch() {
    if [[ -z $(field launch_token) ]]; then
        python3 - "$state" "$shutdown_seconds" <<'PY'
import datetime, json, pathlib, sys, uuid
path = pathlib.Path(sys.argv[1])
state = json.loads(path.read_text())
seconds = int(sys.argv[2])
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
deadline = now + datetime.timedelta(seconds=seconds)
state.update(launch_token=str(uuid.uuid4()), launch_phase='prepared', user_data_sha256='', config_url_expires_epoch='',
             deadline=deadline.strftime('%Y-%m-%dT%H:%M:%SZ') if seconds else '',
             deadline_epoch=int(deadline.timestamp()) if seconds else '', payload_sha256='')
temporary = path.with_suffix('.new')
temporary.write_text(json.dumps(state, indent=2) + '\n')
temporary.replace(path)
PY
    fi
    if [[ -z $(field payload_sha256) ]]; then
        render_config "$state_dir/launch-config" "$(banner_notice "$(field deadline)")"
        record payload_sha256 "$(sha256sum "$state_dir/launch-config" | cut -d' ' -f1)"
    fi
    [[ -f $state_dir/launch-config && $(sha256sum "$state_dir/launch-config" | cut -d' ' -f1) == "$(field payload_sha256)" ]] || fail 'frozen launch configuration is missing or modified'
    if [[ $shutdown_seconds -gt 0 ]]; then
        [[ $(field deadline_epoch) -gt $(($(date -u +%s) + 30)) ]] || fail 'launch deadline has elapsed or is too near; this attempt cannot be extended'
    fi
    config_sha=$(field payload_sha256)
}

retire_launch() {
    # Only called after the provider confirms the predecessor no longer exists.
    [[ $provider != aws ]] || delete_schedule
    for key in config_object signature_object; do
        if [[ -n $(field "$key") ]]; then
            if [[ $provider == gcp ]]; then
                gcp storage rm "gs://$bucket/$(field "$key")"
            else
                aws_cli s3 rm "s3://$bucket/$(field "$key")"
            fi
            record "$key" ''
        fi
    done
    for key in instance instance_id launch_token launch_phase deadline deadline_epoch payload_sha256 user_data_sha256 config_url_expires_epoch; do record "$key" ''; done
    rm -f "$state_dir/launch-config" "$state_dir/launch-config.sig" "$state_dir/user-data"
}

verify_schedule() {
    local deadline
    deadline=$(field deadline)
    jq -e --arg owner "$(vm_owner)" --arg time "at(${deadline%Z})" \
        --arg role "$scheduler_role" --arg instance "$(field instance)" \
        '.Description == $owner and .State == "ENABLED" and .ScheduleExpression == $time
         and .ScheduleExpressionTimezone == "UTC" and .FlexibleTimeWindow.Mode == "OFF"
         and .ActionAfterCompletion == "DELETE" and .Target.RoleArn == $role
         and .Target.Arn == "arn:aws:scheduler:::aws-sdk:ec2:terminateInstances"
         and (.Target.Input | fromjson) == {InstanceIds:[$instance]}' "$state_dir/schedule.json" >/dev/null
}

ensure_schedule() {
    [[ $shutdown_seconds -gt 0 ]] || return 0
    local deadline schedule
    deadline=$(field deadline)
    schedule="aos-${identity:0:20}-$(field launch_token)"
    # Name stays under Scheduler's 64-character limit, including the UUID.
    record schedule "$schedule" || return 1
    record schedule_owner "$(vm_owner)" || return 1
    if aws_cli scheduler get-schedule --name "$schedule" --group-name default > "$state_dir/schedule.json" 2> "$state_dir/schedule-error"; then
        verify_schedule || return 1
        return 0
    fi
    [[ $(< "$state_dir/schedule-error") == *ResourceNotFoundException* ]] || return 1
    [[ $(field deadline_epoch) -gt $(date -u +%s) ]] || return 1
    jq -n --arg role "$scheduler_role" --arg instance "$(field instance)" \
        '{Arn:"arn:aws:scheduler:::aws-sdk:ec2:terminateInstances",RoleArn:$role,
          Input:({InstanceIds:[$instance]} | tojson),RetryPolicy:{MaximumEventAgeInSeconds:3600,MaximumRetryAttempts:10}}' \
        > "$state_dir/schedule-target.json" || return 1
    # A failed client response can still mean the remote creation committed.
    aws_cli scheduler create-schedule --name "$schedule" --group-name default \
        --description "$(vm_owner)" --client-token "$(field launch_token)" \
        --schedule-expression "at(${deadline%Z})" --schedule-expression-timezone UTC \
        --flexible-time-window '{"Mode":"OFF"}' --action-after-completion DELETE \
        --target "file://$state_dir/schedule-target.json" > "$state_dir/schedule-created.json" || true
    aws_cli scheduler get-schedule --name "$schedule" --group-name default > "$state_dir/schedule.json" || return 1
    verify_schedule
}

finish_aws_launch() {
    if ensure_schedule; then
        record launch_phase active
        return
    fi
    # Existing active VMs are never terminated merely because a read failed.
    # Compensation covers this unfinished launch attempt, including retries.
    if [[ $(field launch_phase) != active ]]; then
        if aws_cli ec2 describe-instances --instance-ids "$(field instance)" > "$state_dir/cleanup-instance.json" \
            && verify_aws_instance "$state_dir/cleanup-instance.json" \
            && aws_cli ec2 terminate-instances --instance-ids "$(field instance)" >/dev/null \
            && aws_cli ec2 wait instance-terminated --instance-ids "$(field instance)"; then
            record launch_phase terminated
            fail 'could not establish scheduled deletion; the new instance was terminated'
        fi
        fail 'scheduled deletion and instance cleanup failed; keep the resource record and reconcile this instance immediately'
    fi
    fail 'cannot verify the existing VM deletion schedule; its deadline was not changed'
}

publish_config() {
    if [[ -n $(field user_data_sha256) ]]; then
        [[ -f $state_dir/user-data && $(sha256sum "$state_dir/user-data" | cut -d' ' -f1) == "$(field user_data_sha256)" ]] || fail 'frozen launch metadata is missing or modified'
        if [[ $pointer == true ]]; then
            [[ $(field config_url_expires_epoch) -gt $(($(date -u +%s) + 30)) ]] || fail 'signed launch metadata has expired; this attempt cannot be retried with different user-data'
        fi
        return
    fi
    if [[ $pointer == false ]]; then
        cp "$state_dir/launch-config" "$state_dir/user-data"
        record user_data_sha256 "$(sha256sum "$state_dir/user-data" | cut -d' ' -f1)"
        return
    fi
    object="$object_prefix/config-$config_sha"
    if [[ -n $config_signing_key ]]; then
        need ssh-keygen
        rm -f "$state_dir/launch-config.sig"
        ssh-keygen -Y sign -f "$config_signing_key" -n aos-config "$state_dir/launch-config"
    fi
    if [[ $provider == gcp ]]; then
        gcp storage cp "$state_dir/launch-config" "gs://$bucket/$object" >/dev/null
        record config_object "$object"
        gcp storage sign-url "gs://$bucket/$object" --duration "${config_url_ttl}s" \
            --impersonate-service-account "$signer" --format=json > "$state_dir/signed-url.json"
        url=$(jq -er '.[0].signed_url' "$state_dir/signed-url.json")
        sig_url=
        if [[ -n $config_signing_key ]]; then
            gcp storage cp "$state_dir/launch-config.sig" "gs://$bucket/$object.sig" >/dev/null
            record signature_object "$object.sig"
            gcp storage sign-url "gs://$bucket/$object.sig" --duration "${config_url_ttl}s" \
                --impersonate-service-account "$signer" --format=json > "$state_dir/signed-url.json"
            sig_url=$(jq -er '.[0].signed_url' "$state_dir/signed-url.json")
        fi
    else
        aws_cli s3 cp "$state_dir/launch-config" "s3://$bucket/$object" --only-show-errors
        record config_object "$object"
        url=$(aws_cli s3 presign "s3://$bucket/$object" --expires-in "$config_url_ttl")
        sig_url=
        if [[ -n $config_signing_key ]]; then
            aws_cli s3 cp "$state_dir/launch-config.sig" "s3://$bucket/$object.sig" --only-show-errors
            record signature_object "$object.sig"
            sig_url=$(aws_cli s3 presign "s3://$bucket/$object.sig" --expires-in "$config_url_ttl")
        fi
    fi
    jq -n --arg mode "$config_mode" --arg url "$url" --arg sha "$config_sha" --arg sig "$sig_url" \
        'if $mode == "bundle" then {schema:"aos.config-bundle-pointer/v1",url:$url,sha256:$sha,entrypoint:"_aos_cloud/entry.nix"} else {host_nix_url:$url,sha256:$sha} end | if $sig != "" then .sig_url=$sig else . end' > "$state_dir/user-data"
    rm -f "$state_dir/signed-url.json"
    record config_url_expires_epoch "$(($(date -u +%s) + config_url_ttl))"
    record user_data_sha256 "$(sha256sum "$state_dir/user-data" | cut -d' ' -f1)"
}

create_vm() {
    [[ -n $(field image) ]] || fail 'run image-create first'
    local live_state count remote_deadline
    if [[ $provider == gcp ]]; then
        gcp compute instances list --zones "$zone" --filter "name=$resource_name" --format=json > "$state_dir/live-instances.json"
        count=$(jq 'length' "$state_dir/live-instances.json")
        [[ $count -le 1 ]] || fail 'ambiguous VM ownership lookup'
        if [[ $count == 1 ]]; then
            [[ -n $(field launch_token) && $(jq -r '.[0].description' "$state_dir/live-instances.json") == "$(vm_owner)" ]] || fail 'VM name belongs to a different launch attempt'
            [[ -z $(field instance_id) || $(jq -r '.[0].id' "$state_dir/live-instances.json") == "$(field instance_id)" ]] || fail 'recorded VM instance ID changed'
            [[ $(jq -r '.[0].scheduling.provisioningModel // "STANDARD"' "$state_dir/live-instances.json") == "$([[ $spot == true ]] && printf SPOT || printf STANDARD)" ]] || fail 'VM capacity differs from recorded intent'
            remote_deadline=$(jq -r '.[0].scheduling.terminationTime // empty' "$state_dir/live-instances.json")
            if [[ $shutdown_seconds -gt 0 ]]; then
                [[ -n $remote_deadline && $(date -u -d "$remote_deadline" +%s) == "$(field deadline_epoch)" \
                    && $(jq -r '.[0].scheduling.instanceTerminationAction' "$state_dir/live-instances.json") == DELETE ]] || fail 'VM deletion deadline differs from recorded intent'
            else
                [[ -z $remote_deadline ]] || fail 'VM has an unexpected deletion deadline'
            fi
            record instance "$resource_name"
            record instance_id "$(jq -er '.[0].id' "$state_dir/live-instances.json")"
            record launch_phase active
            printf 'Owned VM already exists: %s\n' "$(field instance)"
            return
        fi
    elif [[ -n $(field launch_token) ]]; then
        # Lookup by token also repairs a lost run-instances response before any
        # signed URL or other idempotency-sensitive launch argument is changed.
        aws_cli ec2 describe-instances --filters "Name=client-token,Values=$(field launch_token)" > "$state_dir/live-instances.json"
        count=$(jq '[.Reservations[].Instances[]] | length' "$state_dir/live-instances.json")
        [[ $count -le 1 ]] || fail 'ambiguous AWS launch-token lookup'
        if [[ $count == 0 && -n $(field instance) ]]; then
            # An eventually consistent filter miss must not replace a live VM.
            aws_cli ec2 describe-instances --instance-ids "$(field instance)" > "$state_dir/live-instances.json" \
                || fail 'recorded AWS instance is not yet visible; retry without changing this attempt'
            count=$(jq '[.Reservations[].Instances[]] | length' "$state_dir/live-instances.json")
            [[ $count == 1 ]] || fail 'recorded AWS instance lookup is unresolved'
        fi
        if [[ $count == 1 ]]; then
            verify_aws_instance "$state_dir/live-instances.json" || fail 'AWS launch token has unexpected ownership'
            record instance "$(jq -er '.Reservations[0].Instances[0].InstanceId' "$state_dir/live-instances.json")"
            live_state=$(jq -r '.Reservations[0].Instances[0].State.Name' "$state_dir/live-instances.json")
            [[ $live_state != shutting-down ]] || fail 'previous VM is still terminating; retry after it is gone'
            if [[ $live_state != terminated ]]; then
                finish_aws_launch
                printf 'Owned VM already exists: %s\n' "$(field instance)"
                return
            fi
        fi
    fi
    if [[ -n $(field instance) || $(field launch_phase) == active || $(field launch_phase) == terminated ]]; then
        retire_launch
    fi

    verify_image
    preflight_scheduler
    if [[ $provider == gcp ]]; then
        gcp compute networks subnets describe "$subnet" --region "$region" --format=json > "$state_dir/subnet.json"
        [[ $(jq -r '.network | split("/")[-1]' "$state_dir/subnet.json") == "$network" ]] || fail 'subnet belongs to a different network'
        if [[ $private_access == false && -z $(field firewall) ]]; then
            gcp compute firewall-rules create "$resource_name-ssh" --network "$network" \
                --direction INGRESS --action ALLOW --rules tcp:22 --source-ranges "$ssh_cidr" \
                --target-tags "$resource_name" --description "aos.cloud-vm/v1 $identity"
            record firewall "$resource_name-ssh"
        fi
        network_interface="network=$network,subnet=$subnet,nic-type=VIRTIO_NET"
        [[ $private_access == true ]] && network_interface+=",no-address"
    else
        aws_cli ec2 describe-subnets --subnet-ids "$subnet" > "$state_dir/subnet.json"
        [[ $(jq -r '.Subnets[0].VpcId' "$state_dir/subnet.json") == "$network" && $(jq -r '.Subnets[0].AvailabilityZone' "$state_dir/subnet.json") == "$zone" ]] || fail 'subnet does not match network/zone'
        if [[ -n $existing_security_group ]]; then
            [[ $(aws_cli ec2 describe-security-groups --group-ids "$existing_security_group" --query 'SecurityGroups[0].VpcId' --output text) == "$network" ]] || fail 'security group belongs to another network'
            record security_group "$existing_security_group"
            record owns_security_group false
        elif [[ -z $(field security_group) ]]; then
            group=$(aws_cli ec2 create-security-group --group-name "$resource_name-ssh" --description "aos.cloud-vm/v1 $identity" --vpc-id "$network" --query GroupId --output text)
            record security_group "$group"
            record owns_security_group true
            aws_cli ec2 authorize-security-group-ingress --group-id "$group" --protocol tcp --port 22 --cidr "$ssh_cidr"
        fi
        jq -n --arg subnet "$subnet" --arg group "$(field security_group)" --arg private "$private_access" \
            '[{DeviceIndex:0,SubnetId:$subnet,Groups:[$group],AssociatePublicIpAddress:($private != "true"),DeleteOnTermination:true}]' > "$state_dir/interfaces.json"
        jq -n --argjson size "$disk_size" \
            '[{DeviceName:"/dev/sda1",Ebs:{VolumeSize:$size,VolumeType:"gp3",DeleteOnTermination:true}}]' > "$state_dir/vm-mappings.json"
    fi

    # Imports and network preparation are complete before the lifetime begins.
    # These exact bytes and this absolute deadline belong to one launch token.
    freeze_launch
    publish_config
    if [[ $shutdown_seconds -gt 0 ]]; then
        [[ $(field deadline_epoch) -gt $(($(date -u +%s) + 30)) ]] || fail 'deadline is too near after metadata preparation; launch was not attempted'
    fi
    capacity_args=()
    record launch_phase launching
    if [[ $provider == gcp ]]; then
        if [[ $spot == true ]]; then
            capacity_args+=(--provisioning-model SPOT --instance-termination-action DELETE --maintenance-policy TERMINATE)
        else
            capacity_args+=(--provisioning-model STANDARD)
        fi
        if [[ $shutdown_seconds -gt 0 ]]; then
            capacity_args+=(--termination-time "$(field deadline)")
            [[ $spot == true ]] || capacity_args+=(--instance-termination-action DELETE)
        fi
        gcp compute instances create "$resource_name" --zone "$zone" --machine-type "$machine_type" \
            --image "$(field image)" --image-project "$project" --boot-disk-size "${disk_size}GB" \
            --boot-disk-auto-delete --network-interface "$network_interface" --tags "$resource_name" \
            "${capacity_args[@]}" \
            --no-restart-on-failure --no-shielded-secure-boot --no-service-account --no-scopes \
            --metadata-from-file "user-data=$state_dir/user-data" --metadata block-project-ssh-keys=TRUE \
            --labels "aos-cloud-vm=${identity:0:63}" --description "$(vm_owner)" --format=json > "$state_dir/instance.json"
        record instance "$resource_name"
        record instance_id "$(jq -er '.[0].id' "$state_dir/instance.json")"
        record launch_phase active
    else
        [[ $spot != true ]] || capacity_args+=(--instance-market-options 'MarketType=spot,SpotOptions={SpotInstanceType=one-time,InstanceInterruptionBehavior=terminate}')
        instance=$(aws_cli ec2 run-instances --image-id "$(field image)" --instance-type "$machine_type" \
            --count 1 --client-token "$(field launch_token)" --placement "AvailabilityZone=$zone" \
            --network-interfaces "file://$state_dir/interfaces.json" --block-device-mappings "file://$state_dir/vm-mappings.json" \
            "${capacity_args[@]}" --metadata-options 'HttpTokens=required,HttpEndpoint=enabled,HttpPutResponseHopLimit=1' \
            --tag-specifications "ResourceType=instance,Tags=[{Key=aos-cloud-vm,Value=$identity}]" \
            --user-data "file://$state_dir/user-data" --query 'Instances[0].InstanceId' --output text)
        record instance "$instance"
        finish_aws_launch
    fi
    printf 'Created %s VM %s.\n' "$([[ $spot == true ]] && printf Spot || printf on-demand)" "$(field instance)"
    [[ $shutdown_seconds == 0 ]] || printf 'Scheduled deletion: %s (provider timing is approximate).\n' "$(field deadline)"
    if [[ $provider == gcp ]]; then
        gcp compute instances describe "$(field instance)" --zone "$zone" --format=json > "$state_dir/instance.json"
        address=$(jq -r '.networkInterfaces[0].accessConfigs[0].natIP // .networkInterfaces[0].networkIP' "$state_dir/instance.json")
    else
        aws_cli ec2 describe-instances --instance-ids "$(field instance)" > "$state_dir/instance.json"
        address=$(jq -r '.Reservations[0].Instances[0] | .PublicIpAddress // .PrivateIpAddress' "$state_dir/instance.json")
    fi
    printf 'SSH (after boot completes): ssh -i <matching-private-key> root@%s\n' "$address"
}

case "$command" in
    image-create) create_image;;
    vm-create) create_vm;;
    up) create_image; create_vm;;
esac
