//! Off-box unit tests for the `aos metadata` agent.
//!
//! Every test runs without root, network, `blkid`/`mount`, or a real `/sys`:
//! the DMI table is pure, fetchers read fixture directories, the config-drive
//! probe is faked, and the AWS IMDSv2 dance is replayed from
//! [`RecordedHttp`](super::http::RecordedHttp).

use std::path::Path;

use tempfile::tempdir;

use super::detect::{classify_dmi, detect, needs_network};
use super::facts_render::render_host_facts_nix;
use super::fetcher::{Facts, MacIface, PlatformFetcher, StaticNetwork, UserData};
use super::http::{RecordedHttp, RecordedMethod};
use super::mount::{CONFIG_DRIVE_LABELS, FakeProbe};
use super::offline::{
    AosMetadataFetcher, ConfigDriveFetcher, NoCloudFetcher, QemuFwCfgFetcher,
};
use super::staticnet::{
    parse_netplan_network_config, parse_openstack_network_data, render_networkd,
};
use super::stash::{MetadataResult, PlatformEnv, Stash};

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(f)
}

// ---------------------------------------------------------------------------
// detect — the DMI decision table (table-driven, verbatim port)
// ---------------------------------------------------------------------------

#[test]
fn dmi_table_matches_nix_decision_order() {
    // (sys_vendor, bios_vendor, product, asset_tag) -> platform
    let cases: &[(&str, &str, &str, &str, &str)] = &[
        // Asset tag wins over everything.
        ("", "", "", "7783-7084-3265-9085-8269-3286-77", "azure"),
        ("Amazon EC2", "", "", "OracleCloud.com", "oraclecloud"),
        // sys_vendor.
        ("Amazon EC2", "", "", "", "aws"),
        ("Google", "", "", "", "gcp"),
        ("Microsoft Corporation", "", "Virtual Machine", "", "hyperv"),
        ("Microsoft Corporation", "", "Other", "", "metal"),
        ("DigitalOcean", "", "", "", "digitalocean"),
        ("OpenStack Foundation", "", "", "", "openstack"),
        ("VMware, Inc.", "", "", "", "vmware"),
        ("innotek GmbH", "", "", "", "virtualbox"),
        ("QEMU", "", "", "", "qemu"),
        // bios_vendor (Nitro bare-metal).
        ("Dell Inc.", "Amazon EC2", "", "", "aws"),
        // product_name.
        ("", "", "Google Compute Engine", "", "gcp"),
        ("", "", "Standard PC (Q35 + ICH9, 2009)", "", "qemu"),
        // Fallback.
        ("", "", "", "", "metal"),
    ];
    for (sv, bv, prod, tag, want) in cases {
        let got = classify_dmi(sv, bv, prod, tag);
        assert_eq!(&got, want, "DMI({sv:?},{bv:?},{prod:?},{tag:?})");
    }
}

#[test]
fn network_platforms_gated() {
    assert!(needs_network("aws"));
    assert!(needs_network("azure"));
    assert!(!needs_network("qemu"));
    assert!(!needs_network("metal"));
    assert!(!needs_network("aos-metadata"));
}

#[test]
fn detect_reads_fake_sysfs() {
    let dir = tempdir().unwrap();
    let dmi = dir.path().join("sys/class/dmi/id");
    std::fs::create_dir_all(&dmi).unwrap();
    std::fs::write(dmi.join("sys_vendor"), "Amazon EC2\n").unwrap();

    let probe = FakeProbe::new(); // no config-drive present
    let env = detect(dir.path(), &probe, Path::new("/run/aos-metadata/media")).unwrap();
    assert_eq!(env.platform_id, "aws");
    assert!(env.need_network);
    assert!(env.metadata_dir.is_none());
}

#[test]
fn detect_config_drive_short_circuits_cloud() {
    let dir = tempdir().unwrap();
    // Even with cloud DMI present, an offline drive wins.
    let dmi = dir.path().join("sys/class/dmi/id");
    std::fs::create_dir_all(&dmi).unwrap();
    std::fs::write(dmi.join("sys_vendor"), "Amazon EC2").unwrap();

    let media = tempdir().unwrap();
    let probe = FakeProbe::new().with("cidata", media.path());
    let env = detect(dir.path(), &probe, Path::new("/unused")).unwrap();
    assert_eq!(env.platform_id, "nocloud");
    assert!(!env.need_network);
    assert_eq!(env.metadata_dir.as_deref(), Some(media.path().to_str().unwrap()));
}

#[test]
fn config_drive_labels_priority() {
    assert_eq!(CONFIG_DRIVE_LABELS, &["aos-metadata", "cidata", "config-2"]);
}

// ---------------------------------------------------------------------------
// offline fetchers over fixtures
// ---------------------------------------------------------------------------

#[test]
fn aos_metadata_fetcher_reads_host_nix_and_sig() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("host.nix"), b"{ services.x.enable = true; }").unwrap();
    std::fs::write(dir.path().join("host.nix.sig"), "-----BEGIN SSH SIGNATURE-----\n").unwrap();

    let f = AosMetadataFetcher::new(dir.path());
    let http = RecordedHttp::new();
    let ud = block_on(f.fetch_user_data(&http)).unwrap().unwrap();
    match ud {
        UserData::Inline { host_nix, sig } => {
            assert_eq!(host_nix, b"{ services.x.enable = true; }");
            assert!(sig.unwrap().starts_with("-----BEGIN SSH SIGNATURE"));
        }
        _ => panic!("expected inline"),
    }
}

#[test]
fn aos_metadata_fetcher_absent_user_data_is_none() {
    let dir = tempdir().unwrap();
    let f = AosMetadataFetcher::new(dir.path());
    let http = RecordedHttp::new();
    assert!(block_on(f.fetch_user_data(&http)).unwrap().is_none());
    assert_eq!(block_on(f.fetch_facts(&http)).unwrap(), Facts::default());
}

#[test]
fn nocloud_fetcher_user_data_is_literal_host_nix() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("user-data"), b"#cloud-config-not-interpreted\n{ }").unwrap();
    std::fs::write(
        dir.path().join("meta-data"),
        "local-hostname: web-1\ninstance-id: i-123\n",
    )
    .unwrap();

    let f = NoCloudFetcher::new(dir.path());
    let http = RecordedHttp::new();
    let ud = block_on(f.fetch_user_data(&http)).unwrap().unwrap();
    match ud {
        UserData::Inline { host_nix, .. } => {
            assert!(host_nix.starts_with(b"#cloud-config-not-interpreted"));
        }
        _ => panic!("expected inline"),
    }
    let facts = block_on(f.fetch_facts(&http)).unwrap();
    assert_eq!(facts.hostname.as_deref(), Some("web-1"));
    assert_eq!(facts.instance_id.as_deref(), Some("i-123"));
}

#[test]
fn nocloud_fetcher_parses_netplan_network_config() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("user-data"), b"{ }").unwrap();
    std::fs::write(
        dir.path().join("network-config"),
        "network:\n  version: 2\n  ethernets:\n    eth0:\n      addresses: [10.0.0.5/24]\n      gateway4: 10.0.0.1\n      nameservers:\n        addresses: [1.1.1.1]\n      match:\n        macaddress: 0A:1B:2C:3D:4E:5F\n",
    )
    .unwrap();

    let f = NoCloudFetcher::new(dir.path());
    let http = RecordedHttp::new();
    let facts = block_on(f.fetch_facts(&http)).unwrap();
    let net = facts.network.expect("network seeded");
    assert_eq!(net.addresses, vec!["10.0.0.5/24"]);
    assert_eq!(net.gateway.as_deref(), Some("10.0.0.1"));
    assert_eq!(net.dns, vec!["1.1.1.1"]);
    assert_eq!(net.mac.as_deref(), Some("0a:1b:2c:3d:4e:5f"));
}

#[test]
fn config_drive_fetcher_parses_openstack_metadata() {
    let dir = tempdir().unwrap();
    let os = dir.path().join("openstack/latest");
    std::fs::create_dir_all(&os).unwrap();
    std::fs::write(os.join("user_data"), b"{ services.y.enable = true; }").unwrap();
    std::fs::write(
        os.join("meta_data.json"),
        r#"{"hostname":"os-1","uuid":"u-9","public_keys":{"default":"ssh-ed25519 AAAA op@h"},"devices":[{"serial":"vol-abc"}]}"#,
    )
    .unwrap();
    std::fs::write(
        os.join("network_data.json"),
        r#"{"links":[{"id":"eth0","ethernet_mac_address":"0A:bb:cc:dd:ee:ff"}],"networks":[{"link":"eth0","ip_address":"203.0.113.10","netmask":"255.255.255.0","gateway":"203.0.113.1"}],"services":[{"type":"dns","address":"67.207.67.2"}]}"#,
    )
    .unwrap();

    let f = ConfigDriveFetcher::new(dir.path());
    let http = RecordedHttp::new();
    let facts = block_on(f.fetch_facts(&http)).unwrap();
    assert_eq!(facts.hostname.as_deref(), Some("os-1"));
    assert_eq!(facts.instance_id.as_deref(), Some("u-9"));
    assert_eq!(facts.ssh_authorized_keys, vec!["ssh-ed25519 AAAA op@h"]);
    assert_eq!(facts.disk_ids, vec!["vol-abc"]);
    let net = facts.network.unwrap();
    assert_eq!(net.addresses, vec!["203.0.113.10/24"]);
    assert_eq!(net.gateway.as_deref(), Some("203.0.113.1"));
    assert_eq!(net.dns, vec!["67.207.67.2"]);
    assert_eq!(net.mac.as_deref(), Some("0a:bb:cc:dd:ee:ff"));
}

#[test]
fn qemu_fwcfg_reads_blob() {
    let root = tempdir().unwrap();
    let blob = root.path().join("opt/org.andyl/host.nix");
    std::fs::create_dir_all(&blob).unwrap();
    std::fs::write(blob.join("raw"), b"{ qemu = true; }").unwrap();

    let f = QemuFwCfgFetcher::new(root.path());
    let http = RecordedHttp::new();
    let ud = block_on(f.fetch_user_data(&http)).unwrap().unwrap();
    match ud {
        UserData::Inline { host_nix, .. } => assert_eq!(host_nix, b"{ qemu = true; }"),
        _ => panic!("expected inline"),
    }
}

// ---------------------------------------------------------------------------
// AWS IMDSv2 over a recorded fixture (the token dance)
// ---------------------------------------------------------------------------

fn aws_recorded() -> RecordedHttp {
    RecordedHttp::new()
        .on(RecordedMethod::Put, "http://169.254.169.254/latest/api/token", 200, b"TOKEN123")
        .on(
            RecordedMethod::Get,
            "http://169.254.169.254/latest/user-data",
            200,
            b"{ services.web.enable = true; }",
        )
        .on(
            RecordedMethod::Get,
            "http://169.254.169.254/latest/meta-data/instance-id",
            200,
            b"i-0abc",
        )
        .on(
            RecordedMethod::Get,
            "http://169.254.169.254/latest/meta-data/placement/region",
            200,
            b"us-east-1",
        )
        .on(
            RecordedMethod::Get,
            "http://169.254.169.254/latest/meta-data/placement/availability-zone",
            200,
            b"us-east-1a",
        )
        .on(
            RecordedMethod::Get,
            "http://169.254.169.254/latest/meta-data/local-hostname",
            200,
            b"ip-10-0-1-22",
        )
        .on(
            RecordedMethod::Get,
            "http://169.254.169.254/latest/meta-data/public-keys/",
            200,
            b"0=my-key",
        )
        .on(
            RecordedMethod::Get,
            "http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key",
            200,
            b"ssh-ed25519 AAAA op@host",
        )
        .on(
            RecordedMethod::Get,
            "http://169.254.169.254/latest/meta-data/network/interfaces/macs/",
            200,
            b"0a:1b:2c:3d:4e:5f/",
        )
        .on(
            RecordedMethod::Get,
            "http://169.254.169.254/latest/meta-data/network/interfaces/macs/0a:1b:2c:3d:4e:5f/device-number",
            200,
            b"0",
        )
}

#[test]
fn aws_imdsv2_token_dance_and_facts() {
    let f = super::aws::AwsImdsFetcher::default();
    let http = aws_recorded();

    let ud = block_on(f.fetch_user_data(&http)).unwrap().unwrap();
    match ud {
        UserData::Inline { host_nix, .. } => {
            assert_eq!(host_nix, b"{ services.web.enable = true; }");
        }
        _ => panic!("expected inline host.nix"),
    }

    let facts = block_on(f.fetch_facts(&http)).unwrap();
    assert_eq!(facts.instance_id.as_deref(), Some("i-0abc"));
    assert_eq!(facts.region.as_deref(), Some("us-east-1"));
    assert_eq!(facts.availability_zone.as_deref(), Some("us-east-1a"));
    assert_eq!(facts.hostname.as_deref(), Some("ip-10-0-1-22"));
    assert_eq!(facts.ssh_authorized_keys, vec!["ssh-ed25519 AAAA op@host"]);
    assert_eq!(
        facts.mac_to_iface,
        vec![MacIface { mac: "0a:1b:2c:3d:4e:5f".into(), iface: "eth0".into() }]
    );
}

#[test]
fn aws_imdsv2_404_user_data_is_none() {
    let http = RecordedHttp::new()
        .on(RecordedMethod::Put, "http://169.254.169.254/latest/api/token", 200, b"T")
        .on(RecordedMethod::Get, "http://169.254.169.254/latest/user-data", 404, b"");
    let f = super::aws::AwsImdsFetcher::default();
    assert!(block_on(f.fetch_user_data(&http)).unwrap().is_none());
}

#[test]
fn aws_imdsv2_pointer_resolved_with_pin() {
    let pin = super::stash::sha256_hex(b"big host.nix body");
    let pointer = format!(
        r#"{{"host_nix_url":"https://cfg.example/host.nix","sha256":"{pin}","sig_url":"https://cfg.example/host.nix.sig"}}"#
    );
    let http = RecordedHttp::new()
        .on(RecordedMethod::Put, "http://169.254.169.254/latest/api/token", 200, b"T")
        .on(
            RecordedMethod::Get,
            "http://169.254.169.254/latest/user-data",
            200,
            pointer.as_bytes(),
        )
        .on(RecordedMethod::Get, "https://cfg.example/host.nix", 200, b"big host.nix body")
        .on(RecordedMethod::Get, "https://cfg.example/host.nix.sig", 200, b"SIG");

    let f = super::aws::AwsImdsFetcher::default();
    let ud = block_on(f.fetch_user_data(&http)).unwrap().unwrap();
    let resolved = block_on(ud.resolve(&http)).unwrap();
    assert_eq!(resolved.host_nix, b"big host.nix body");
    assert_eq!(resolved.sig.as_deref(), Some("SIG"));
}

// ---------------------------------------------------------------------------
// static-net parse + render
// ---------------------------------------------------------------------------

#[test]
fn openstack_network_data_to_networkd() {
    let json = br#"{"links":[{"id":"tap0","ethernet_mac_address":"0a:1b:2c:3d:4e:5f"}],"networks":[{"link":"tap0","ip_address":"203.0.113.10","netmask":"255.255.255.0","gateway":"203.0.113.1"}],"services":[{"type":"dns","address":"67.207.67.2"}]}"#;
    let net = parse_openstack_network_data(json).unwrap();
    let rendered = render_networkd(&net);
    assert!(rendered.contains("MACAddress=0a:1b:2c:3d:4e:5f"));
    assert!(rendered.contains("Address=203.0.113.10/24"));
    assert!(rendered.contains("Gateway=203.0.113.1"));
    assert!(rendered.contains("DNS=67.207.67.2"));
}

#[test]
fn netplan_v2_cidr_addresses() {
    let yaml = b"network:\n  version: 2\n  ethernets:\n    en0:\n      addresses:\n        - 192.0.2.5/25\n      gateway4: 192.0.2.1\n";
    let net = parse_netplan_network_config(yaml).unwrap();
    assert_eq!(net.addresses, vec!["192.0.2.5/25"]);
    assert_eq!(net.gateway.as_deref(), Some("192.0.2.1"));
}

// ---------------------------------------------------------------------------
// facts.json -> host-facts.nix render
// ---------------------------------------------------------------------------

#[test]
fn facts_render_is_deterministic_and_typed() {
    let facts = Facts {
        hostname: Some("ip-10-0-1-22".into()),
        instance_id: Some("i-0abc".into()),
        region: Some("us-east-1".into()),
        availability_zone: Some("us-east-1a".into()),
        ssh_authorized_keys: vec!["ssh-ed25519 AAAA op@host".into()],
        mac_to_iface: vec![MacIface { mac: "0a:1b:2c:3d:4e:5f".into(), iface: "ens5".into() }],
        disk_ids: vec!["nvme-Amazon_EBS_vol0abc".into()],
        network: None,
    };
    let a = render_host_facts_nix(&facts);
    let b = render_host_facts_nix(&facts);
    assert_eq!(a, b, "render must be deterministic");
    assert!(a.contains("hostname = \"ip-10-0-1-22\";"));
    assert!(a.contains("instanceId = \"i-0abc\";"));
    assert!(a.contains("sshAuthorizedKeys = [ \"ssh-ed25519 AAAA op@host\" ];"));
    assert!(a.contains("{ mac = \"0a:1b:2c:3d:4e:5f\"; iface = \"ens5\"; }"));
    assert!(a.contains("diskIds = [ \"nvme-Amazon_EBS_vol0abc\" ];"));
}

#[test]
fn facts_render_escapes_hostile_input() {
    // A hostile hostname must not break out of the Nix string literal: every
    // embedded quote is backslash-escaped, so the payload stays inert data.
    let facts = Facts {
        hostname: Some("\"; system.evil = true; x = \"".into()),
        ..Facts::default()
    };
    let rendered = render_host_facts_nix(&facts);
    // The full line carries the value with both quotes escaped.
    assert!(
        rendered.contains("hostname = \"\\\"; system.evil = true; x = \\\"\";"),
        "hostile value must be fully escaped; got:\n{rendered}"
    );
}

#[test]
fn facts_render_antiquotation_neutralized() {
    let facts = Facts {
        hostname: Some("${builtins.exec [\"/bin/sh\"]}".into()),
        ..Facts::default()
    };
    let rendered = render_host_facts_nix(&facts);
    assert!(rendered.contains("\\$"), "dollar must be escaped to neutralize ${{}}");
}

// ---------------------------------------------------------------------------
// stash format + run_fetch end-to-end (offline)
// ---------------------------------------------------------------------------

#[test]
fn platform_env_roundtrip() {
    let env = PlatformEnv {
        platform_id: "nocloud".into(),
        metadata_dir: Some("/run/aos-metadata/media".into()),
        need_network: false,
    };
    let parsed = PlatformEnv::parse(&env.render());
    assert_eq!(parsed, env);

    let cloud = PlatformEnv {
        platform_id: "aws".into(),
        metadata_dir: None,
        need_network: true,
    };
    let parsed = PlatformEnv::parse(&cloud.render());
    assert_eq!(parsed, cloud);
}

#[test]
fn run_fetch_offline_writes_full_stash() {
    let stash_dir = tempdir().unwrap();
    let media = tempdir().unwrap();
    let os = media.path().join("openstack/latest");
    std::fs::create_dir_all(&os).unwrap();
    std::fs::write(os.join("user_data"), b"{ ok = true; }").unwrap();
    std::fs::write(os.join("user_data.sig"), "-----BEGIN SSH SIGNATURE-----\n").unwrap();
    std::fs::write(
        os.join("meta_data.json"),
        r#"{"hostname":"os-1","uuid":"u-1"}"#,
    )
    .unwrap();
    std::fs::write(
        os.join("network_data.json"),
        r#"{"links":[{"id":"e0","ethernet_mac_address":"0a:00:00:00:00:01"}],"networks":[{"link":"e0","ip_address":"10.1.1.5","netmask":"255.255.255.0","gateway":"10.1.1.1"}]}"#,
    )
    .unwrap();

    let stash = Stash::open(stash_dir.path()).unwrap();
    let fetcher = ConfigDriveFetcher::new(media.path());
    let http = RecordedHttp::new();
    let var_etc = tempdir().unwrap();
    block_on(super::run_fetch_with(
        &stash,
        &fetcher,
        &http,
        Some(var_etc.path()),
        "config-drive",
    ))
    .unwrap();

    // host.nix + sig stashed.
    assert_eq!(
        std::fs::read(stash_dir.path().join("host.nix")).unwrap(),
        b"{ ok = true; }"
    );
    assert!(stash_dir.path().join("host.nix.sig").exists());

    // facts.json present.
    assert!(stash_dir.path().join("facts.json").exists());

    // network seed in stash AND in /var/etc lower.
    assert!(stash_dir.path().join("network/10-aos-seed.network").exists());
    assert!(var_etc.path().join("systemd/network/10-aos-seed.network").exists());

    // run record reflects the run.
    let result: MetadataResult = serde_json::from_slice(
        &std::fs::read(stash_dir.path().join(".metadata-result.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(result.platform_id, "config-drive");
    assert!(result.fetched_user_data);
    assert!(result.sig_present);
    assert!(result.network_seed_written);
    assert_eq!(result.user_data_source, "config-drive");
    assert!(stash.already_run());
}

#[test]
fn run_fetch_no_user_data_is_failure_safe() {
    let stash_dir = tempdir().unwrap();
    let media = tempdir().unwrap(); // empty: no host.nix
    let stash = Stash::open(stash_dir.path()).unwrap();
    let fetcher = AosMetadataFetcher::new(media.path());
    let http = RecordedHttp::new();
    block_on(super::run_fetch_with(&stash, &fetcher, &http, None, "aos-metadata")).unwrap();

    assert!(!stash_dir.path().join("host.nix").exists());
    let result: MetadataResult = serde_json::from_slice(
        &std::fs::read(stash_dir.path().join(".metadata-result.json")).unwrap(),
    )
    .unwrap();
    assert!(!result.fetched_user_data);
    assert!(!result.sig_present);
}

// ---------------------------------------------------------------------------
// two-boot repart persist seam
// ---------------------------------------------------------------------------

#[test]
fn repart_persist_and_verified_gate() {
    use super::repart::{RepartFragment, persist_operator_repart, verified_fragments_present};
    let var = tempdir().unwrap();
    assert!(!verified_fragments_present(var.path()));

    let frags = vec![RepartFragment {
        name: "60-data.conf".into(),
        contents: "[Partition]\nType=linux-generic\n".into(),
    }];
    let written = persist_operator_repart(var.path(), &frags).unwrap();
    assert_eq!(written.len(), 1);
    assert!(verified_fragments_present(var.path()));
    assert!(var.path().join("var/lib/aos/repart.d/60-data.conf").is_file());
}

#[test]
fn repart_rejects_non_conf_name() {
    use super::repart::{RepartFragment, persist_operator_repart};
    let var = tempdir().unwrap();
    let frags = vec![RepartFragment { name: "bad".into(), contents: "x".into() }];
    assert!(persist_operator_repart(var.path(), &frags).is_err());
}

// Keep StaticNetwork import used even if a future refactor drops a test.
#[allow(dead_code)]
fn _assert_static_network_default() -> StaticNetwork {
    StaticNetwork::default()
}
