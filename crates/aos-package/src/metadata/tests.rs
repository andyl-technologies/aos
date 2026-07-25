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
use super::offline::{AosMetadataFetcher, ConfigDriveFetcher, NoCloudFetcher, QemuFwCfgFetcher};
use super::stash::{MetadataResult, PlatformEnv, Stash};
use super::staticnet::{
    parse_netplan_network_config, parse_openstack_network_data, render_networkd,
};

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
    assert_eq!(
        env.metadata_dir.as_deref(),
        Some(media.path().to_str().unwrap())
    );
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
    std::fs::write(
        dir.path().join("host.nix"),
        b"{ services.x.enable = true; }",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("host.nix.sig"),
        "-----BEGIN SSH SIGNATURE-----\n",
    )
    .unwrap();

    let f = AosMetadataFetcher::new(dir.path());
    let http = RecordedHttp::new();
    let ud = block_on(f.fetch_user_data(&http)).unwrap().unwrap();
    match ud {
        UserData::Inline { payload, sig } => {
            assert_eq!(payload, b"{ services.x.enable = true; }");
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
    std::fs::write(
        dir.path().join("user-data"),
        b"#cloud-config-not-interpreted\n{ }",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("meta-data"),
        "local-hostname: web-1\ninstance-id: i-123\n",
    )
    .unwrap();

    let f = NoCloudFetcher::new(dir.path());
    let http = RecordedHttp::new();
    let ud = block_on(f.fetch_user_data(&http)).unwrap().unwrap();
    match ud {
        UserData::Inline { payload, .. } => {
            assert!(payload.starts_with(b"#cloud-config-not-interpreted"));
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
    let blob = root.path().join("opt/org.andyl/host-nix");
    std::fs::create_dir_all(&blob).unwrap();
    std::fs::write(blob.join("raw"), b"{ qemu = true; }").unwrap();

    let f = QemuFwCfgFetcher::new(root.path());
    let http = RecordedHttp::new();
    let ud = block_on(f.fetch_user_data(&http)).unwrap().unwrap();
    match ud {
        UserData::Inline { payload, .. } => assert_eq!(payload, b"{ qemu = true; }"),
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
        UserData::Inline { payload, .. } => {
            assert_eq!(payload, b"{ services.web.enable = true; }");
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
        vec![MacIface {
            mac: "0a:1b:2c:3d:4e:5f".into(),
            iface: "eth0".into()
        }]
    );
}

#[test]
fn aws_imdsv2_404_user_data_is_none() {
    let http = RecordedHttp::new()
        .on(
            RecordedMethod::Put,
            "http://169.254.169.254/latest/api/token",
            200,
            b"T",
        )
        .on(
            RecordedMethod::Get,
            "http://169.254.169.254/latest/user-data",
            404,
            b"",
        );
    let f = super::aws::AwsImdsFetcher::default();
    assert!(block_on(f.fetch_user_data(&http)).unwrap().is_none());
}

#[test]
fn aws_imdsv2_host_pointer_resolved_with_pin() {
    let pin = super::stash::sha256_hex(b"{ big = true; }");
    let pointer = format!(
        r#"{{"host_nix_url":"https://cfg.example/host.nix","sha256":"{pin}","sig_url":"https://cfg.example/host.nix.sig"}}"#
    );
    let http = RecordedHttp::new()
        .on(
            RecordedMethod::Put,
            "http://169.254.169.254/latest/api/token",
            200,
            b"T",
        )
        .on(
            RecordedMethod::Get,
            "http://169.254.169.254/latest/user-data",
            200,
            pointer.as_bytes(),
        )
        .on(
            RecordedMethod::Get,
            "https://cfg.example/host.nix",
            200,
            b"{ big = true; }",
        )
        .on(
            RecordedMethod::Get,
            "https://cfg.example/host.nix.sig",
            200,
            b"SIG",
        );

    let f = super::aws::AwsImdsFetcher::default();
    let ud = block_on(f.fetch_user_data(&http)).unwrap().unwrap();
    let resolved = block_on(ud.resolve(&http)).unwrap();
    assert_eq!(resolved.payload, b"{ big = true; }");
    assert_eq!(resolved.sig.as_deref(), Some("SIG"));
}

#[test]
fn native_cloud_fetchers_acquire_provider_user_data() {
    let cases: Vec<(Box<dyn PlatformFetcher>, &str, &[u8])> = vec![
        (
            Box::new(super::cloud::GcpFetcher),
            "http://metadata.google.internal/computeMetadata/v1/instance/attributes/user-data",
            b"{ gcp = true; }",
        ),
        (
            Box::new(super::cloud::AzureFetcher),
            "http://169.254.169.254/metadata/instance/compute/userData?api-version=2021-02-01&format=text",
            b"eyBhenVyZSA9IHRydWU7IH0=",
        ),
        (
            Box::new(super::cloud::DigitalOceanFetcher),
            "http://169.254.169.254/metadata/v1/user-data",
            b"{ digitalocean = true; }",
        ),
        (
            Box::new(super::cloud::OpenStackImdsFetcher),
            "http://169.254.169.254/openstack/latest/user_data",
            b"{ openstack = true; }",
        ),
    ];

    for (fetcher, url, body) in cases {
        let http = RecordedHttp::new().on(RecordedMethod::Get, url, 200, body);
        let user_data = block_on(fetcher.fetch_user_data(&http)).unwrap().unwrap();
        let UserData::Inline { payload, .. } = user_data else {
            panic!("{} returned a pointer unexpectedly", fetcher.platform_id());
        };
        assert!(
            payload.starts_with(b"{ "),
            "{} did not return decoded literal input: {:?}",
            fetcher.platform_id(),
            payload
        );
    }
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
        mac_to_iface: vec![MacIface {
            mac: "0a:1b:2c:3d:4e:5f".into(),
            iface: "ens5".into(),
        }],
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
    assert!(
        rendered.contains("\\$"),
        "dollar must be escaped to neutralize ${{}}"
    );
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

    // Exact user-data + signature are stashed; authorization owns host.nix.
    assert_eq!(
        std::fs::read(stash_dir.path().join("user-data")).unwrap(),
        b"{ ok = true; }"
    );
    assert!(stash_dir.path().join("user-data.sig").exists());
    assert!(!stash_dir.path().join("host.nix").exists());

    // facts.json present.
    assert!(stash_dir.path().join("facts.json").exists());

    // network seed in stash AND in /var/etc lower.
    assert!(
        stash_dir
            .path()
            .join("network/10-aos-seed.network")
            .exists()
    );
    assert!(
        var_etc
            .path()
            .join("systemd/network/10-aos-seed.network")
            .exists()
    );

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
    block_on(super::run_fetch_with(
        &stash,
        &fetcher,
        &http,
        None,
        "aos-metadata",
    ))
    .unwrap();

    assert!(!stash_dir.path().join("user-data").exists());
    let result: MetadataResult = serde_json::from_slice(
        &std::fs::read(stash_dir.path().join(".metadata-result.json")).unwrap(),
    )
    .unwrap();
    assert!(!result.fetched_user_data);
    assert!(!result.sig_present);
}

// ---------------------------------------------------------------------------
// first-boot host authorization + evaluated repart rendering
// ---------------------------------------------------------------------------

#[test]
fn no_user_data_selects_schema_defaults_without_authorized_host() {
    use super::provisioning::{AuthorizeOptions, ProvisioningTrust, run_authorize};

    let stash_dir = tempdir().unwrap();
    let stash = Stash::open(stash_dir.path()).unwrap();
    stash
        .write_platform_env(&PlatformEnv {
            platform_id: "metal".into(),
            metadata_dir: None,
            need_network: false,
        })
        .unwrap();
    stash
        .write_result(&MetadataResult {
            platform_id: "metal".into(),
            fetched_user_data: false,
            user_data_source: "imds".into(),
            user_data_sha256: None,
            sig_present: false,
            facts_hash: "00".repeat(32),
            network_seed_written: false,
            timestamp: "1970-01-01T00:00:00Z".into(),
        })
        .unwrap();

    let result = run_authorize(&AuthorizeOptions {
        stash_dir: stash_dir.path().to_path_buf(),
        trust: ProvisioningTrust::Platform,
        trusted_config_key_dirs: Vec::new(),
    })
    .unwrap();
    assert!(result.is_none());
    assert!(!stash_dir.path().join("host.nix").exists());
}

#[test]
fn platform_input_is_preserved_as_exact_host_nix() {
    use super::provisioning::{AuthorizeOptions, ProvisioningTrust, run_authorize};

    let stash_dir = tempdir().unwrap();
    let media = tempdir().unwrap();
    let host = b"{ aos.provisioning.storage.partitions.var.sizeMin = \"8G\"; }\n";
    std::fs::write(media.path().join("host.nix"), host).unwrap();

    let stash = Stash::open(stash_dir.path()).unwrap();
    stash
        .write_platform_env(&PlatformEnv {
            platform_id: "aos-metadata".into(),
            metadata_dir: Some(media.path().display().to_string()),
            need_network: false,
        })
        .unwrap();
    let fetcher = AosMetadataFetcher::new(media.path());
    let http = RecordedHttp::new();
    block_on(super::run_fetch_with(
        &stash,
        &fetcher,
        &http,
        None,
        "aos-metadata",
    ))
    .unwrap();

    let result = run_authorize(&AuthorizeOptions {
        stash_dir: stash_dir.path().to_path_buf(),
        trust: ProvisioningTrust::Platform,
        trusted_config_key_dirs: Vec::new(),
    })
    .unwrap()
    .unwrap();

    assert_eq!(
        std::fs::read(stash_dir.path().join("host.nix")).unwrap(),
        host
    );
    assert_eq!(result.host_nix_sha256, super::stash::sha256_hex(host));
    super::provisioning::verify_host_binding(stash_dir.path()).unwrap();
}

#[test]
fn signed_host_verifies_exact_input_and_rejects_tampering() {
    use super::provisioning::{AuthorizeOptions, ProvisioningTrust, run_authorize};
    use crate::config_trust::CONFIG_SIGNATURE_NAMESPACE;
    use crate::security::sign_payload_signature;
    use crate::sshkey::Ed25519Keypair;

    let stash_dir = tempdir().unwrap();
    let media = tempdir().unwrap();
    let keys = tempdir().unwrap();
    let host = b"{ aos.provisioning.storage.partitions.var.sizeMin = \"8G\"; }\n";

    let key = Ed25519Keypair::generate();
    let private = keys.path().join("ops.key");
    std::fs::write(&private, key.to_openssh_private_key("ops")).unwrap();
    std::fs::write(
        keys.path().join("ops.pub"),
        format!("{}\n", key.trust_key_line("ops")),
    )
    .unwrap();
    let signature = sign_payload_signature(&private, CONFIG_SIGNATURE_NAMESPACE, host).unwrap();
    std::fs::write(media.path().join("host.nix"), host).unwrap();
    std::fs::write(media.path().join("host.nix.sig"), signature).unwrap();

    let stash = Stash::open(stash_dir.path()).unwrap();
    stash
        .write_platform_env(&PlatformEnv {
            platform_id: "aos-metadata".into(),
            metadata_dir: Some(media.path().display().to_string()),
            need_network: false,
        })
        .unwrap();
    let http = RecordedHttp::new();
    block_on(super::run_fetch_with(
        &stash,
        &AosMetadataFetcher::new(media.path()),
        &http,
        None,
        "aos-metadata",
    ))
    .unwrap();

    let opts = AuthorizeOptions {
        stash_dir: stash_dir.path().to_path_buf(),
        trust: ProvisioningTrust::Signed,
        trusted_config_key_dirs: vec![keys.path().to_path_buf()],
    };
    let accepted = run_authorize(&opts).unwrap().unwrap();
    assert!(accepted.signer.is_some());

    std::fs::write(stash_dir.path().join("user-data"), b"tampered").unwrap();
    assert!(run_authorize(&opts).is_err());
    assert!(!stash_dir.path().join("host.nix").exists());
}

#[test]
fn storage_projection_is_strict_and_renders_pending_marker() {
    use std::collections::BTreeMap;

    use super::repart::{
        PENDING_LABEL, PartitionSpec, ProvisioningPlan, StoragePlan, render_provisioning_plan,
        validate_provisioning_plan,
    };

    let mut partitions = BTreeMap::new();
    partitions.insert(
        "var".into(),
        PartitionSpec {
            device: None,
            label: "var".into(),
            partition_type: "linux-generic".into(),
            size_min: "4G".into(),
            size_max: None,
            weight: 1000,
            format: None,
            uuid: None,
            grow: true,
            grow_fs: true,
            priority: 9000,
        },
    );
    let mut plan = ProvisioningPlan {
        schema: "aos.provisioning-plan/v1".into(),
        storage: StoragePlan { partitions },
    };
    validate_provisioning_plan(&plan, true).unwrap();
    let output = tempdir().unwrap();
    let marker_uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let paths =
        render_provisioning_plan(output.path(), &mut plan, true, PENDING_LABEL, marker_uuid)
            .unwrap();
    assert!(paths.iter().any(|path| {
        std::fs::read_to_string(path)
            .map(|contents| contents.contains(PENDING_LABEL))
            .unwrap_or(false)
    }));
    assert!(output.path().join("repart-targets").is_file());
}

#[test]
fn storage_projection_rejects_unsafe_device_and_protected_type() {
    use super::repart::ProvisioningPlan;

    let unsafe_plans = [
        r#"{"schema":"aos.provisioning-plan/v1","storage":{"partitions":{"var":{"device":"/dev/vdb","label":"var","type":"linux-generic","sizeMin":"4G","sizeMax":null,"weight":1000,"format":null,"uuid":null,"grow":true,"growFs":true,"priority":1}}}}"#,
        r#"{"schema":"aos.provisioning-plan/v1","storage":{"partitions":{"var":{"device":null,"label":"var","type":"root-a","sizeMin":"4G","sizeMax":null,"weight":1000,"format":null,"uuid":null,"grow":true,"growFs":true,"priority":1}}}}"#,
    ];
    for input in unsafe_plans {
        let plan: ProvisioningPlan = serde_json::from_str(input).unwrap();
        assert!(super::repart::validate_provisioning_plan(&plan, false).is_err());
    }
}

#[test]
fn storage_projection_enforces_swap_pairing() {
    use super::repart::ProvisioningPlan;

    let invalid_plans = [
        r#"{"schema":"aos.provisioning-plan/v1","storage":{"partitions":{"var":{"device":null,"label":"var","type":"linux-generic","sizeMin":"4G","sizeMax":null,"weight":1000,"format":null,"uuid":null,"grow":true,"growFs":true,"priority":1},"bad":{"device":null,"label":"bad","type":"linux-generic","sizeMin":"1G","sizeMax":"1G","weight":1000,"format":"swap","uuid":null,"grow":false,"growFs":true,"priority":2}}}}"#,
        r#"{"schema":"aos.provisioning-plan/v1","storage":{"partitions":{"var":{"device":null,"label":"var","type":"linux-generic","sizeMin":"4G","sizeMax":null,"weight":1000,"format":null,"uuid":null,"grow":true,"growFs":true,"priority":1},"bad":{"device":null,"label":"bad","type":"swap","sizeMin":"1G","sizeMax":"1G","weight":1000,"format":"ext4","uuid":null,"grow":false,"growFs":true,"priority":2}}}}"#,
    ];
    for input in invalid_plans {
        let plan: ProvisioningPlan = serde_json::from_str(input).unwrap();
        assert!(super::repart::validate_provisioning_plan(&plan, false).is_err());
    }
}

#[test]
fn provisioning_state_persists_audit_definitions_and_runtime_input() {
    use std::collections::BTreeMap;

    use super::provisioning::{
        PROVISIONING_RESULT_FILE, ProvisioningResult, ProvisioningSource, ProvisioningTrust,
    };
    use super::repart::{
        OPERATOR_LABEL, PartitionSpec, ProvisioningPlan, StoragePlan, render_provisioning_plan,
    };
    use super::state::{
        AUDIT_FILE, PersistProvisioningOptions, ProvisioningAudit, cache_runtime_input,
        persist_provisioning_state, restore_runtime_input,
    };

    let stash = tempdir().unwrap();
    let state = tempdir().unwrap();
    let host = b"{ aos.provisioning.storage.partitions.var.sizeMin = \"4G\"; }\n";
    std::fs::write(stash.path().join("host.nix"), host).unwrap();
    std::fs::write(
        stash.path().join(PROVISIONING_RESULT_FILE),
        serde_json::to_vec_pretty(&ProvisioningResult {
            trust_mode: ProvisioningTrust::Platform,
            platform_id: "aos-metadata".into(),
            host_nix_sha256: super::stash::sha256_hex(host),
            signer: None,
        })
        .unwrap(),
    )
    .unwrap();
    let facts = Facts {
        instance_id: Some("instance-7".into()),
        ..Default::default()
    };
    let facts_bytes = serde_json::to_vec_pretty(&facts).unwrap();
    std::fs::write(stash.path().join("facts.json"), &facts_bytes).unwrap();
    std::fs::write(
        stash.path().join(".metadata-result.json"),
        serde_json::to_vec_pretty(&MetadataResult {
            platform_id: "aos-metadata".into(),
            fetched_user_data: true,
            user_data_source: "config-drive".into(),
            user_data_sha256: Some(super::stash::sha256_hex(host)),
            sig_present: false,
            facts_hash: super::stash::sha256_hex(&facts_bytes),
            network_seed_written: false,
            timestamp: "2026-07-24T00:00:00Z".into(),
        })
        .unwrap(),
    )
    .unwrap();
    std::fs::write(stash.path().join("provisioning-source"), "operator\n").unwrap();

    let mut partitions = BTreeMap::new();
    partitions.insert(
        "var".into(),
        PartitionSpec {
            device: None,
            label: "var".into(),
            partition_type: "linux-generic".into(),
            size_min: "4G".into(),
            size_max: None,
            weight: 1000,
            format: None,
            uuid: None,
            grow: true,
            grow_fs: true,
            priority: 9000,
        },
    );
    let mut plan = ProvisioningPlan {
        schema: "aos.provisioning-plan/v1".into(),
        storage: StoragePlan { partitions },
    };
    render_provisioning_plan(
        stash.path(),
        &mut plan,
        true,
        OPERATOR_LABEL,
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    )
    .unwrap();

    assert!(
        persist_provisioning_state(&PersistProvisioningOptions {
            stash_dir: stash.path().to_path_buf(),
            state_dir: state.path().to_path_buf(),
            module_abi: 7,
            image_version: "test-image".into(),
        })
        .unwrap()
    );
    let audit: ProvisioningAudit =
        serde_json::from_slice(&std::fs::read(state.path().join(AUDIT_FILE)).unwrap()).unwrap();
    assert_eq!(audit.source, ProvisioningSource::Operator);
    assert_eq!(audit.module_abi, 7);
    assert_eq!(audit.instance_id.as_deref(), Some("instance-7"));
    assert!(
        state
            .path()
            .join("desired/repart.d/0000/0000-aos-provisioning-marker.conf")
            .is_file()
    );

    assert!(cache_runtime_input(stash.path(), state.path()).unwrap());
    std::fs::remove_file(stash.path().join("host.nix")).unwrap();
    std::fs::remove_file(stash.path().join(PROVISIONING_RESULT_FILE)).unwrap();
    std::fs::remove_file(state.path().join("current/facts.json")).unwrap();
    std::fs::remove_file(state.path().join("current/.metadata-result.json")).unwrap();
    std::fs::write(stash.path().join("facts.json"), b"{\"stale\":true}").unwrap();
    assert!(restore_runtime_input(stash.path(), state.path()).unwrap());
    assert_eq!(std::fs::read(stash.path().join("host.nix")).unwrap(), host);
    assert!(!stash.path().join("facts.json").exists());
}

#[test]
fn provisioning_marker_is_first_and_protected_from_space_pressure() {
    use std::collections::BTreeMap;

    use super::repart::{
        PENDING_LABEL, PartitionSpec, ProvisioningPlan, StoragePlan, render_provisioning_plan,
    };

    let mut partitions = BTreeMap::new();
    partitions.insert(
        "var".into(),
        PartitionSpec {
            device: None,
            label: "var".into(),
            partition_type: "linux-generic".into(),
            size_min: "4G".into(),
            size_max: None,
            weight: 1000,
            format: None,
            uuid: None,
            grow: true,
            grow_fs: true,
            priority: 1,
        },
    );
    let output = tempdir().unwrap();
    let mut plan = ProvisioningPlan {
        schema: "aos.provisioning-plan/v1".into(),
        storage: StoragePlan { partitions },
    };
    render_provisioning_plan(
        output.path(),
        &mut plan,
        true,
        PENDING_LABEL,
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    )
    .unwrap();
    let marker = std::fs::read_to_string(
        output
            .path()
            .join("repart.d/0000/0000-aos-provisioning-marker.conf"),
    )
    .unwrap();
    assert!(marker.contains("Priority=1000000"));
    assert!(marker.contains("UUID=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"));
    let first_uuid = plan.storage.partitions["var"].uuid.clone().unwrap();

    let second_output = tempdir().unwrap();
    plan.storage.partitions.get_mut("var").unwrap().uuid = None;
    render_provisioning_plan(
        second_output.path(),
        &mut plan,
        true,
        PENDING_LABEL,
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    )
    .unwrap();
    assert_eq!(
        plan.storage.partitions["var"].uuid.as_deref(),
        Some(first_uuid.as_str())
    );
    assert!(output.path().join("repart.d/0000/0010-var.conf").is_file());
}

#[test]
fn provisioning_renderer_groups_devices_and_places_growth_last() {
    use std::collections::BTreeMap;

    use super::repart::{
        PENDING_LABEL, PartitionSpec, ProvisioningPlan, StoragePlan, render_provisioning_plan,
    };

    let partition =
        |device: Option<&str>, label: &str, size_max: Option<&str>, grow: bool, priority: i64| {
            PartitionSpec {
                device: device.map(str::to_owned),
                label: label.into(),
                partition_type: "linux-generic".into(),
                size_min: "1G".into(),
                size_max: size_max.map(str::to_owned),
                weight: 1000,
                format: Some("ext4".into()),
                uuid: None,
                grow,
                grow_fs: true,
                priority,
            }
        };
    let mut partitions = BTreeMap::new();
    partitions.insert("var".into(), partition(None, "var", None, true, 1));
    partitions.insert(
        "logs".into(),
        partition(None, "logs", Some("1G"), false, 9000),
    );
    partitions.insert(
        "data".into(),
        partition(
            Some("/dev/disk/by-id/test-data"),
            "data",
            Some("1G"),
            false,
            1000,
        ),
    );
    let output = tempdir().unwrap();
    let mut plan = ProvisioningPlan {
        schema: "aos.provisioning-plan/v1".into(),
        storage: StoragePlan { partitions },
    };
    render_provisioning_plan(
        output.path(),
        &mut plan,
        false,
        PENDING_LABEL,
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    )
    .unwrap();

    let targets = std::fs::read_to_string(output.path().join("repart-targets")).unwrap();
    assert!(targets.starts_with("root\t0000\n"));
    assert!(targets.contains("/dev/disk/by-id/test-data\t"));
    assert!(targets.contains("root\t"));
    let root_dir = targets
        .lines()
        .find_map(|line| line.strip_prefix("root\t"))
        .unwrap();
    let root_files: Vec<_> = std::fs::read_dir(output.path().join("repart.d").join(root_dir))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(root_files.iter().any(|name| name == "0010-logs.conf"));
    assert!(root_files.iter().any(|name| name == "0011-var.conf"));
}

// Keep StaticNetwork import used even if a future refactor drops a test.
#[allow(dead_code)]
fn _assert_static_network_default() -> StaticNetwork {
    StaticNetwork::default()
}
