fn content_path(root: &Path, key: &ContentHash) -> PathBuf {
    let hex = key.to_hex();
    root.join(&hex[0..2]).join(hex)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn validate_claim_request(request: &FrontierClaimRequest) -> Result<(), CasError> {
    if request.host_id.is_empty() {
        return Err(CasError::InvalidLease {
            reason: "host id must not be empty",
        });
    }
    if request.host_id.contains('\n') {
        return Err(CasError::InvalidLease {
            reason: "host id must not contain newlines",
        });
    }
    if request.ttl_ticks == 0 {
        return Err(CasError::InvalidLease {
            reason: "ttl must be greater than zero",
        });
    }
    request
        .now_tick
        .checked_add(request.ttl_ticks)
        .ok_or(CasError::InvalidLease {
            reason: "lease expiry tick overflows u64",
        })?;
    Ok(())
}

fn create_content_record(path: &Path, material: &str) -> Result<bool, CasError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| CasError::Io {
            operation: "create-dir",
            path: parent.to_path_buf(),
            source,
        })?;
    }
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            if let Err(source) = file.write_all(material.as_bytes()) {
                let _ = fs::remove_file(path);
                return Err(CasError::Io {
                    operation: "write",
                    path: path.to_path_buf(),
                    source,
                });
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(source) => Err(CasError::Io {
            operation: "create",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn coverage_record_material(coverage_fingerprint: &ContentHash, entry: &ContentHash) -> String {
    format!(
        "format=crucible.coverage-map-entry.v1\ncoverage_fingerprint={}\nentry={}\n",
        coverage_fingerprint.to_hex(),
        entry.to_hex()
    )
}

fn coverage_fingerprint_record_material(
    coverage_fingerprint: &ContentHash,
    entries: &[ContentHash],
) -> String {
    let entries = entries
        .iter()
        .map(|entry| entry.to_hex())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "format=crucible.coverage-fingerprint.v1\ncoverage_fingerprint={}\nentries={entries}\n",
        coverage_fingerprint.to_hex()
    )
}

fn reduction_record_material(fingerprint: &ContentHash, representative: &ContentHash) -> String {
    format!(
        "format=crucible.reduction-fingerprint.v1\nfingerprint={}\nrepresentative={}\n",
        fingerprint.to_hex(),
        representative.to_hex()
    )
}

fn manifest_record_material(manifest: &CampaignManifest) -> String {
    format!(
        "format=crucible.campaign-manifest.v1\ncorpus_root={}\ncoverage_map_root={}\nfindings_root={}\ngenesis_pin={}\nprovenance.crucible_version={}\nprovenance.qemu_build={}\nprovenance.abi_versions={}\n",
        manifest.corpus_root.to_hex(),
        manifest.coverage_map_root.to_hex(),
        manifest.findings_root.to_hex(),
        manifest.genesis_pin.to_hex(),
        manifest.provenance.crucible_version,
        manifest.provenance.qemu_build,
        manifest.provenance.abi_versions,
    )
}

fn campaign_provenance_material(provenance: &CampaignProvenance) -> String {
    format!(
        "format={CAMPAIGN_PROVENANCE_SCHEMA}\ncrucible_version={}\nqemu_build={}\nabi_versions={}\n",
        provenance.crucible_version, provenance.qemu_build, provenance.abi_versions,
    )
}

fn campaign_lineage_material(manifest: &CampaignManifest, provenance_key: ContentHash) -> String {
    format!(
        "format={CAMPAIGN_LINEAGE_SCHEMA}\ngenesis_pin={}\nprovenance_key={provenance_key}\n",
        manifest.genesis_pin.to_hex(),
        provenance_key = provenance_key.to_hex(),
    )
}

fn campaign_fresh_lineage_baseline_event_material(
    event: &CampaignFreshLineageBaselineEvent,
) -> String {
    format!(
        "format={}\nreason={}\nrefused_corpus_root={}\nprevious_lineage_id={}\nfresh_lineage_id={}\nprevious_provenance_key={}\nrun_provenance_key={}\nfresh_manifest_hash={}\nfresh_manifest.corpus_root={}\nfresh_manifest.coverage_map_root={}\nfresh_manifest.findings_root={}\nfresh_manifest.genesis_pin={}\nfresh_manifest.provenance.crucible_version={}\nfresh_manifest.provenance.qemu_build={}\nfresh_manifest.provenance.abi_versions={}\n",
        event.schema_version,
        event.reason,
        event.refused_corpus_root.to_hex(),
        event.previous_lineage_id.to_hex(),
        event.fresh_lineage_id.to_hex(),
        event.previous_provenance_key.to_hex(),
        event.run_provenance_key.to_hex(),
        event.fresh_manifest_hash.to_hex(),
        event.fresh_manifest.corpus_root.to_hex(),
        event.fresh_manifest.coverage_map_root.to_hex(),
        event.fresh_manifest.findings_root.to_hex(),
        event.fresh_manifest.genesis_pin.to_hex(),
        event.fresh_manifest.provenance.crucible_version,
        event.fresh_manifest.provenance.qemu_build,
        event.fresh_manifest.provenance.abi_versions,
    )
}

fn campaign_replay_input_material(artifact: &CampaignReplayArtifact) -> String {
    format!(
        "format=crucible.campaign-replay-input.v1\ndefinition={}\nseed={}\nschedule={}\n",
        encode_hex(artifact.definition()),
        encode_hex(artifact.seed()),
        encode_hex(artifact.schedule())
    )
}

fn campaign_replay_artifact_material(artifact: &CampaignReplayArtifact) -> String {
    format!(
        "format=crucible.campaign-replay-artifact.v1\ndefinition={}\nseed={}\nschedule={}\nreplay_hash={}\n",
        encode_hex(artifact.definition()),
        encode_hex(artifact.seed()),
        encode_hex(artifact.schedule()),
        artifact.replay_hash().to_hex()
    )
}

fn campaign_corpus_record_material(entries: &BTreeMap<ContentHash, ContentHash>) -> String {
    let mut material = String::from("format=crucible.campaign-corpus.v1\n");
    for (artifact_hash, replay_hash) in entries {
        material.push_str(&format!(
            "entry artifact={} replay={}\n",
            artifact_hash.to_hex(),
            replay_hash.to_hex()
        ));
    }
    material
}

fn campaign_corpus_retention_record_material(
    source_root: ContentHash,
    policy: &CampaignCorpusRetentionPolicy,
    entries: &BTreeMap<ContentHash, ContentHash>,
) -> String {
    let mut material = format!(
        "format=crucible.campaign-corpus-retention.v1\nsource={}\ncap={}\nseed={}\n",
        source_root.to_hex(),
        policy.cap,
        policy.seed.to_hex()
    );
    for (artifact_hash, replay_hash) in entries {
        material.push_str(&format!(
            "entry artifact={} replay={}\n",
            artifact_hash.to_hex(),
            replay_hash.to_hex()
        ));
    }
    material
}

fn campaign_coverage_map_record_material(edges: &BTreeSet<ContentHash>) -> String {
    let mut material = String::from("format=crucible.campaign-coverage-map.v1\n");
    for edge in edges {
        material.push_str(&format!("edge={}\n", edge.to_hex()));
    }
    material
}

fn campaign_finding_record_material(
    finding: &CampaignFinding,
    artifact_hash: ContentHash,
) -> String {
    format!(
        "format=crucible.campaign-finding.v1\nfingerprint={}\nartifact={}\nreplay={}\n",
        finding.fingerprint.to_hex(),
        artifact_hash.to_hex(),
        finding.artifact.replay_hash().to_hex()
    )
}

fn campaign_findings_ledger_record_material(
    entries: &BTreeMap<ContentHash, ContentHash>,
) -> String {
    let mut material = String::from("format=crucible.campaign-findings-ledger.v1\n");
    for (artifact_hash, finding_hash) in entries {
        material.push_str(&format!(
            "entry artifact={} finding={}\n",
            artifact_hash.to_hex(),
            finding_hash.to_hex()
        ));
    }
    material
}

fn campaign_head_entry_material(generation: u64, manifest_hash: ContentHash) -> String {
    let checksum = campaign_head_entry_checksum(generation, manifest_hash);
    format!(
        "entry generation={generation} manifest={} checksum={}\n",
        manifest_hash.to_hex(),
        checksum.to_hex()
    )
}

fn campaign_head_entry_checksum(generation: u64, manifest_hash: ContentHash) -> ContentHash {
    ContentHash::from_bytes(
        format!(
            "crucible.campaign-head-entry.v1\ngeneration={generation}\nmanifest={}\n",
            manifest_hash.to_hex()
        )
        .as_bytes(),
    )
}

fn frontier_lease_id(node: &ContentHash, owner: &str, expires_at_tick: u64) -> ContentHash {
    ContentHash::from_bytes(
        format!(
            "crucible.frontier-lease.v1\nnode={}\nowner={owner}\nexpires_at_tick={expires_at_tick}\n",
            node.to_hex()
        )
        .as_bytes(),
    )
}

fn lease_record_material(lease: &FrontierLease) -> String {
    format!(
        "format=crucible.frontier-lease.v1\nnode={}\nowner={}\nexpires_at_tick={}\nlease_id={}\n",
        lease.node.to_hex(),
        lease.owner,
        lease.expires_at_tick,
        lease.lease_id.to_hex()
    )
}

fn claim_lock_record_material(
    node: &ContentHash,
    acquired_at_tick: u64,
    expires_at_tick: u64,
) -> String {
    format!(
        "format=crucible.frontier-claim-lock.v1\nnode={}\nacquired_at_tick={acquired_at_tick}\nexpires_at_tick={expires_at_tick}\n",
        node.to_hex()
    )
}

fn parse_lease_record(
    path: &Path,
    expected_node: &ContentHash,
    material: &str,
) -> Result<FrontierLease, CasError> {
    let mut fields = BTreeMap::new();
    for line in material.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(CasError::InvalidFrontierRecord {
                path: path.to_path_buf(),
                reason: "claim record line is missing '='",
            });
        };
        fields.insert(key, value);
    }
    if fields.get("format") != Some(&"crucible.frontier-lease.v1") {
        return Err(CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim record format is unsupported",
        });
    }
    let node = parse_required_hash(path, &fields, "node")?;
    if node != *expected_node {
        return Err(CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim record node does not match claim path",
        });
    }
    let owner = fields
        .get("owner")
        .ok_or_else(|| CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim record is missing owner",
        })?
        .to_string();
    let expires_at_tick = fields
        .get("expires_at_tick")
        .ok_or_else(|| CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim record is missing expiry",
        })?
        .parse::<u64>()
        .map_err(|_| CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim record expiry is not a u64",
        })?;
    let lease_id = parse_required_hash(path, &fields, "lease_id")?;
    let expected_lease_id = frontier_lease_id(&node, &owner, expires_at_tick);
    if lease_id != expected_lease_id {
        return Err(CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim record lease id does not match record material",
        });
    }
    Ok(FrontierLease {
        node,
        owner,
        expires_at_tick,
        lease_id,
    })
}

fn parse_reduction_record(
    path: &Path,
    expected_fingerprint: &ContentHash,
    material: &str,
) -> Result<ContentHash, CasError> {
    let mut fields = BTreeMap::new();
    for line in material.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(CasError::InvalidFrontierRecord {
                path: path.to_path_buf(),
                reason: "reduction record line is missing '='",
            });
        };
        fields.insert(key, value);
    }
    if fields.get("format") != Some(&"crucible.reduction-fingerprint.v1") {
        return Err(CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "reduction record format is unsupported",
        });
    }
    let fingerprint = parse_required_hash(path, &fields, "fingerprint")?;
    if fingerprint != *expected_fingerprint {
        return Err(CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "reduction record fingerprint does not match marker path",
        });
    }
    parse_required_hash(path, &fields, "representative")
}

fn parse_manifest_record(path: &Path, material: &str) -> Result<CampaignManifest, CasError> {
    let fields = parse_key_value_record(path, material, "campaign manifest")?;
    if fields.get("format") != Some(&"crucible.campaign-manifest.v1") {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign manifest format is unsupported",
        });
    }
    let manifest = CampaignManifest {
        corpus_root: parse_required_campaign_hash(path, &fields, "corpus_root")?,
        coverage_map_root: parse_required_campaign_hash(path, &fields, "coverage_map_root")?,
        findings_root: parse_required_campaign_hash(path, &fields, "findings_root")?,
        genesis_pin: parse_required_campaign_hash(path, &fields, "genesis_pin")?,
        provenance: CampaignProvenance {
            crucible_version: parse_required_string(path, &fields, "provenance.crucible_version")?,
            qemu_build: parse_required_string(path, &fields, "provenance.qemu_build")?,
            abi_versions: parse_required_string(path, &fields, "provenance.abi_versions")?,
        },
    };
    validate_campaign_manifest(&manifest)?;
    Ok(manifest)
}

fn parse_replay_artifact_record(
    path: &Path,
    material: &str,
) -> Result<CampaignReplayArtifact, CasError> {
    let fields = parse_key_value_record(path, material, "campaign replay artifact")?;
    if fields.get("format") != Some(&"crucible.campaign-replay-artifact.v1") {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign replay artifact format is unsupported",
        });
    }
    let artifact = CampaignReplayArtifact::new(
        decode_hex_field(path, &fields, "definition")?,
        decode_hex_field(path, &fields, "seed")?,
        decode_hex_field(path, &fields, "schedule")?,
    );
    let replay_hash = parse_required_campaign_hash(path, &fields, "replay_hash")?;
    if replay_hash != artifact.replay_hash() {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign replay artifact hash is invalid",
        });
    }
    Ok(artifact)
}

fn parse_campaign_corpus_record(
    path: &Path,
    material: &str,
) -> Result<BTreeMap<ContentHash, ContentHash>, CasError> {
    let mut lines = material.lines();
    if lines.next() != Some("format=crucible.campaign-corpus.v1") {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus format is unsupported",
        });
    }
    let mut entries = BTreeMap::new();
    for line in lines {
        let Some(fields_material) = line.strip_prefix("entry ") else {
            return Err(CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason: "campaign corpus entry line is unsupported",
            });
        };
        let fields = parse_space_fields(path, fields_material, "campaign corpus entry")?;
        let artifact = parse_required_campaign_hash(path, &fields, "artifact")?;
        let replay = parse_required_campaign_hash(path, &fields, "replay")?;
        entries.insert(artifact, replay);
    }
    Ok(entries)
}

fn parse_campaign_corpus_retention_record(
    path: &Path,
    material: &str,
) -> Result<CampaignCorpusRetentionRecord, CasError> {
    let mut lines = material.lines();
    if lines.next() != Some("format=crucible.campaign-corpus-retention.v1") {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention format is unsupported",
        });
    }
    let source_line = lines
        .next()
        .ok_or_else(|| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention source is missing",
        })?;
    let Some(source_hex) = source_line.strip_prefix("source=") else {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention source is missing",
        });
    };
    let source_root =
        ContentHash::from_hex(source_hex).ok_or_else(|| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention source hash is invalid",
        })?;

    let cap_line = lines
        .next()
        .ok_or_else(|| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention cap is missing",
        })?;
    let Some(cap_value) = cap_line.strip_prefix("cap=") else {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention cap is missing",
        });
    };
    let cap = cap_value
        .parse::<usize>()
        .map_err(|_| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention cap is invalid",
        })?;
    if cap == 0 {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention cap must be greater than zero",
        });
    }

    let seed_line = lines
        .next()
        .ok_or_else(|| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention seed is missing",
        })?;
    let Some(seed_hex) = seed_line.strip_prefix("seed=") else {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention seed is missing",
        });
    };
    let seed = ContentHash::from_hex(seed_hex).ok_or_else(|| CasError::InvalidCampaignRecord {
        path: path.to_path_buf(),
        reason: "campaign corpus retention seed hash is invalid",
    })?;

    let mut entries = BTreeMap::new();
    for line in lines {
        let Some(fields_material) = line.strip_prefix("entry ") else {
            return Err(CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason: "campaign corpus retention entry line is unsupported",
            });
        };
        let fields = parse_space_fields(path, fields_material, "campaign corpus entry")?;
        let artifact = parse_required_campaign_hash(path, &fields, "artifact")?;
        let replay = parse_required_campaign_hash(path, &fields, "replay")?;
        entries.insert(artifact, replay);
    }

    Ok(CampaignCorpusRetentionRecord {
        source_root,
        policy: CampaignCorpusRetentionPolicy { cap, seed },
        entries,
    })
}

fn parse_campaign_coverage_map_record(
    path: &Path,
    material: &str,
) -> Result<BTreeSet<ContentHash>, CasError> {
    let mut lines = material.lines();
    if lines.next() != Some("format=crucible.campaign-coverage-map.v1") {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign coverage-map format is unsupported",
        });
    }
    let mut edges = BTreeSet::new();
    for line in lines {
        let Some(edge) = line.strip_prefix("edge=") else {
            return Err(CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason: "campaign coverage-map edge line is unsupported",
            });
        };
        edges.insert(ContentHash::from_hex(edge).ok_or_else(|| {
            CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason: "campaign coverage-map edge hash is invalid",
            }
        })?);
    }
    Ok(edges)
}

fn parse_campaign_finding_record(
    path: &Path,
    finding_hash: ContentHash,
    material: &str,
) -> Result<PersistedCampaignFinding, CasError> {
    let fields = parse_key_value_record(path, material, "campaign finding")?;
    if fields.get("format") != Some(&"crucible.campaign-finding.v1") {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign finding format is unsupported",
        });
    }
    Ok(PersistedCampaignFinding {
        finding_hash,
        fingerprint: parse_required_campaign_hash(path, &fields, "fingerprint")?,
        artifact_hash: parse_required_campaign_hash(path, &fields, "artifact")?,
        replay_hash: parse_required_campaign_hash(path, &fields, "replay")?,
    })
}

fn parse_campaign_findings_ledger_record(
    path: &Path,
    material: &str,
) -> Result<BTreeMap<ContentHash, ContentHash>, CasError> {
    let mut lines = material.lines();
    if lines.next() != Some("format=crucible.campaign-findings-ledger.v1") {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign findings ledger format is unsupported",
        });
    }
    let mut findings = BTreeMap::new();
    for line in lines {
        let Some(fields_material) = line.strip_prefix("entry ") else {
            return Err(CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason: "campaign findings ledger line is unsupported",
            });
        };
        let fields = parse_space_fields(path, fields_material, "campaign findings ledger entry")?;
        let artifact = parse_required_campaign_hash(path, &fields, "artifact")?;
        let finding = parse_required_campaign_hash(path, &fields, "finding")?;
        insert_deduped_finding_entry(&mut findings, artifact, finding);
    }
    Ok(findings)
}

fn parse_campaign_root_merge_record(
    path: &Path,
    material: &str,
) -> Result<CampaignRootMerge, CasError> {
    let fields = parse_key_value_record(path, material, "campaign root merge")?;
    if fields.get("format") != Some(&"crucible.campaign-root-merge.v1") {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign root merge format is unsupported",
        });
    }
    let label = match fields.get("label").copied() {
        Some("corpus") => "corpus",
        Some("coverage-map") => "coverage-map",
        Some("findings") => "findings",
        Some(_) => {
            return Err(CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason: "campaign root merge label is unsupported",
            });
        }
        None => {
            return Err(CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason: "campaign root merge is missing label",
            });
        }
    };
    Ok(CampaignRootMerge {
        label,
        left: parse_required_campaign_hash(path, &fields, "left")?,
        right: parse_required_campaign_hash(path, &fields, "right")?,
    })
}

fn parse_fresh_lineage_baseline_event(
    path: &Path,
    baseline_event_hash: ContentHash,
    material: &str,
) -> Result<CampaignFreshLineageBaselineEvent, CasError> {
    let fields = parse_key_value_record(path, material, "fresh-lineage baseline event")?;
    if fields.get("format") != Some(&CAMPAIGN_FRESH_LINEAGE_BASELINE_EVENT_SCHEMA) {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "fresh-lineage baseline event format is unsupported",
        });
    }
    let fresh_manifest = CampaignManifest {
        corpus_root: parse_required_campaign_hash(path, &fields, "fresh_manifest.corpus_root")?,
        coverage_map_root: parse_required_campaign_hash(
            path,
            &fields,
            "fresh_manifest.coverage_map_root",
        )?,
        findings_root: parse_required_campaign_hash(path, &fields, "fresh_manifest.findings_root")?,
        genesis_pin: parse_required_campaign_hash(path, &fields, "fresh_manifest.genesis_pin")?,
        provenance: CampaignProvenance {
            crucible_version: parse_required_string(
                path,
                &fields,
                "fresh_manifest.provenance.crucible_version",
            )?,
            qemu_build: parse_required_string(
                path,
                &fields,
                "fresh_manifest.provenance.qemu_build",
            )?,
            abi_versions: parse_required_string(
                path,
                &fields,
                "fresh_manifest.provenance.abi_versions",
            )?,
        },
    };
    validate_campaign_manifest(&fresh_manifest)?;
    let event = CampaignFreshLineageBaselineEvent {
        baseline_event_hash,
        schema_version: CAMPAIGN_FRESH_LINEAGE_BASELINE_EVENT_SCHEMA.to_owned(),
        reason: parse_required_string(path, &fields, "reason")?,
        refused_corpus_root: parse_required_campaign_hash(path, &fields, "refused_corpus_root")?,
        previous_lineage_id: parse_required_campaign_hash(path, &fields, "previous_lineage_id")?,
        fresh_lineage_id: parse_required_campaign_hash(path, &fields, "fresh_lineage_id")?,
        previous_provenance_key: parse_required_campaign_hash(
            path,
            &fields,
            "previous_provenance_key",
        )?,
        run_provenance_key: parse_required_campaign_hash(path, &fields, "run_provenance_key")?,
        fresh_manifest_hash: parse_required_campaign_hash(path, &fields, "fresh_manifest_hash")?,
        fresh_manifest,
    };
    if event.reason != CAMPAIGN_CROSS_PROVENANCE_REFUSAL_REASON {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "fresh-lineage baseline event reason is unsupported",
        });
    }
    if event.fresh_lineage_id != campaign_lineage_id(&event.fresh_manifest)? {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "fresh-lineage baseline event lineage id is invalid",
        });
    }
    if event.run_provenance_key != campaign_provenance_key(&event.fresh_manifest.provenance)? {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "fresh-lineage baseline event provenance key is invalid",
        });
    }
    Ok(event)
}

fn parse_campaign_head_record(
    path: &Path,
    material: &str,
) -> Result<Option<CampaignHeadPointer>, CasError> {
    parse_campaign_head_log_record(path, material)
}

fn parse_campaign_head_log_record(
    path: &Path,
    material: &str,
) -> Result<Option<CampaignHeadPointer>, CasError> {
    let mut latest = None;
    for line in material.lines() {
        match parse_campaign_head_entry(path, line) {
            Ok(pointer) => {
                if latest
                    .map(|current: CampaignHeadPointer| pointer.generation > current.generation)
                    .unwrap_or(true)
                {
                    latest = Some(pointer);
                }
            }
            Err(error) if line.starts_with("entry ") => {
                let _ = error;
            }
            Err(error) => {
                let _ = error;
            }
        }
    }
    Ok(latest)
}

fn parse_campaign_head_entry(path: &Path, line: &str) -> Result<CampaignHeadPointer, CasError> {
    let Some(fields_material) = line.strip_prefix("entry ") else {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign head log line is unsupported",
        });
    };
    let mut fields = BTreeMap::new();
    for field in fields_material.split_whitespace() {
        let Some((key, value)) = field.split_once('=') else {
            return Err(CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason: "campaign head entry field is missing '='",
            });
        };
        fields.insert(key, value);
    }
    let generation = fields
        .get("generation")
        .ok_or_else(|| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign head entry is missing generation",
        })?
        .parse::<u64>()
        .map_err(|_| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign head entry generation is invalid",
        })?;
    let manifest_hash = parse_required_campaign_hash(path, &fields, "manifest")?;
    let checksum = parse_required_campaign_hash(path, &fields, "checksum")?;
    if checksum != campaign_head_entry_checksum(generation, manifest_hash) {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign head entry checksum is invalid",
        });
    }
    Ok(CampaignHeadPointer {
        generation,
        manifest_hash,
    })
}

fn parse_claim_lock_record(
    path: &Path,
    expected_node: &ContentHash,
    material: &str,
) -> Result<FrontierClaimLockRecord, CasError> {
    let mut fields = BTreeMap::new();
    for line in material.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(CasError::InvalidFrontierRecord {
                path: path.to_path_buf(),
                reason: "claim lock record line is missing '='",
            });
        };
        fields.insert(key, value);
    }
    if fields.get("format") != Some(&"crucible.frontier-claim-lock.v1") {
        return Err(CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim lock record format is unsupported",
        });
    }
    let node = parse_required_hash(path, &fields, "node")?;
    if node != *expected_node {
        return Err(CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim lock node does not match lock path",
        });
    }
    let expires_at_tick = fields
        .get("expires_at_tick")
        .ok_or_else(|| CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim lock record is missing expiry",
        })?
        .parse::<u64>()
        .map_err(|_| CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim lock record expiry is not a u64",
        })?;
    Ok(FrontierClaimLockRecord {
        node,
        expires_at_tick,
    })
}

fn parse_key_value_record<'a>(
    path: &Path,
    material: &'a str,
    label: &'static str,
) -> Result<BTreeMap<&'a str, &'a str>, CasError> {
    let mut fields = BTreeMap::new();
    for line in material.lines() {
        let Some((key, value)) = line.split_once('=') else {
            let reason = match label {
                "campaign manifest" => "campaign manifest line is missing '='",
                "campaign head" => "campaign head line is missing '='",
                _ => "record line is missing '='",
            };
            return Err(CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason,
            });
        };
        fields.insert(key, value);
    }
    Ok(fields)
}

fn parse_space_fields<'a>(
    path: &Path,
    material: &'a str,
    label: &'static str,
) -> Result<BTreeMap<&'a str, &'a str>, CasError> {
    let mut fields = BTreeMap::new();
    for field in material.split_whitespace() {
        let Some((key, value)) = field.split_once('=') else {
            let reason = match label {
                "campaign corpus entry" => "campaign corpus entry field is missing '='",
                _ => "record field is missing '='",
            };
            return Err(CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason,
            });
        };
        fields.insert(key, value);
    }
    Ok(fields)
}

fn parse_required_hash(
    path: &Path,
    fields: &BTreeMap<&str, &str>,
    name: &'static str,
) -> Result<ContentHash, CasError> {
    let value = fields
        .get(name)
        .ok_or_else(|| CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim record is missing hash field",
        })?;
    ContentHash::from_hex(value).ok_or_else(|| CasError::InvalidFrontierRecord {
        path: path.to_path_buf(),
        reason: "claim record hash field is invalid",
    })
}

fn parse_required_string(
    path: &Path,
    fields: &BTreeMap<&str, &str>,
    name: &'static str,
) -> Result<String, CasError> {
    let value = fields
        .get(name)
        .ok_or_else(|| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign record is missing string field",
        })?;
    Ok((*value).to_string())
}

fn parse_required_campaign_hash(
    path: &Path,
    fields: &BTreeMap<&str, &str>,
    name: &'static str,
) -> Result<ContentHash, CasError> {
    let value = fields
        .get(name)
        .ok_or_else(|| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign record is missing hash field",
        })?;
    ContentHash::from_hex(value).ok_or_else(|| CasError::InvalidCampaignRecord {
        path: path.to_path_buf(),
        reason: "campaign record hash field is invalid",
    })
}

fn decode_hex_field(
    path: &Path,
    fields: &BTreeMap<&str, &str>,
    name: &'static str,
) -> Result<Vec<u8>, CasError> {
    let value = fields
        .get(name)
        .ok_or_else(|| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign record is missing bytes field",
        })?;
    decode_hex(value).ok_or_else(|| CasError::InvalidCampaignRecord {
        path: path.to_path_buf(),
        reason: "campaign record bytes field is invalid",
    })
}

fn validate_campaign_manifest(manifest: &CampaignManifest) -> Result<(), CasError> {
    validate_campaign_provenance(&manifest.provenance)?;
    Ok(())
}

fn validate_campaign_provenance(provenance: &CampaignProvenance) -> Result<(), CasError> {
    validate_campaign_provenance_field(&provenance.crucible_version)?;
    validate_campaign_provenance_field(&provenance.qemu_build)?;
    validate_campaign_provenance_field(&provenance.abi_versions)?;
    Ok(())
}

fn validate_campaign_provenance_field(value: &str) -> Result<(), CasError> {
    if value.is_empty() {
        return Err(CasError::InvalidCampaignRecord {
            path: PathBuf::from("campaign-manifest"),
            reason: "campaign provenance field must not be empty",
        });
    }
    if value.contains('\n') {
        return Err(CasError::InvalidCampaignRecord {
            path: PathBuf::from("campaign-manifest"),
            reason: "campaign provenance field must not contain newlines",
        });
    }
    Ok(())
}

fn validate_campaign_lineage(
    current: &CampaignManifest,
    proposed: &CampaignManifest,
) -> Result<(), CasError> {
    if current.genesis_pin != proposed.genesis_pin {
        return Err(CasError::InvalidCampaignRecord {
            path: PathBuf::from("campaign-manifest"),
            reason: "campaign manifests with different genesis pins cannot merge",
        });
    }
    if current.provenance != proposed.provenance {
        return Err(CasError::InvalidCampaignRecord {
            path: PathBuf::from("campaign-manifest"),
            reason: "campaign manifests with different provenance cannot merge",
        });
    }
    Ok(())
}

fn validate_campaign_corpus_retention_policy(
    policy: &CampaignCorpusRetentionPolicy,
    path: PathBuf,
) -> Result<(), CasError> {
    if policy.cap == 0 {
        return Err(CasError::InvalidCampaignRecord {
            path,
            reason: "campaign corpus retention cap must be greater than zero",
        });
    }
    Ok(())
}

fn campaign_root_field(label: &str) -> &'static str {
    match label {
        "corpus" => "corpus_root",
        "coverage-map" => "coverage_map_root",
        "findings" => "findings_root",
        _ => "manifest_root",
    }
}

fn campaign_root_regression_reason(label: &str) -> &'static str {
    match label {
        "corpus" => "typed campaign corpus root cannot be replaced by an untyped root",
        "coverage-map" => "typed campaign coverage-map root cannot be replaced by an untyped root",
        "findings" => "typed campaign findings root cannot be replaced by an untyped root",
        _ => "typed campaign root cannot be replaced by an untyped root",
    }
}

fn is_typed_campaign_root_format(label: &str, format: &str) -> bool {
    match label {
        "corpus" => {
            matches!(
                format,
                "crucible.campaign-corpus.v1" | "crucible.campaign-corpus-retention.v1"
            )
        }
        "coverage-map" => format == "crucible.campaign-coverage-map.v1",
        "findings" => format == "crucible.campaign-findings-ledger.v1",
        _ => false,
    }
}

fn record_format(material: &str) -> Option<&str> {
    material.lines().next()?.strip_prefix("format=")
}

fn retain_campaign_corpus_entries(
    entries: &BTreeMap<ContentHash, ContentHash>,
    policy: &CampaignCorpusRetentionPolicy,
) -> BTreeMap<ContentHash, ContentHash> {
    let mut scored_entries = entries
        .iter()
        .map(|(artifact_hash, replay_hash)| {
            (
                campaign_corpus_retention_score(policy.seed, *artifact_hash, *replay_hash),
                *artifact_hash,
                *replay_hash,
            )
        })
        .collect::<Vec<_>>();
    scored_entries.sort();
    scored_entries
        .into_iter()
        .take(policy.cap)
        .map(|(_, artifact_hash, replay_hash)| (artifact_hash, replay_hash))
        .collect()
}

fn campaign_corpus_retention_score(
    seed: ContentHash,
    artifact_hash: ContentHash,
    replay_hash: ContentHash,
) -> ContentHash {
    ContentHash::from_bytes(
        format!(
            "crucible.campaign-corpus-retention-score.v1\nseed={}\nartifact={}\nreplay={}\n",
            seed.to_hex(),
            artifact_hash.to_hex(),
            replay_hash.to_hex()
        )
        .as_bytes(),
    )
}

fn campaign_root_merge_hash(label: &str, left: ContentHash, right: ContentHash) -> ContentHash {
    if left == right {
        return left;
    }
    let (first, second) = ordered_manifest_roots(left, right);
    ContentHash::from_bytes(campaign_root_merge_record_material(label, first, second).as_bytes())
}

fn campaign_root_merge_record_material(
    label: &str,
    first: ContentHash,
    second: ContentHash,
) -> String {
    format!(
        "format=crucible.campaign-root-merge.v1\nlabel={label}\nleft={}\nright={}\n",
        first.to_hex(),
        second.to_hex()
    )
}

fn ordered_manifest_roots(left: ContentHash, right: ContentHash) -> (ContentHash, ContentHash) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

fn insert_deduped_finding_entry(
    entries: &mut BTreeMap<ContentHash, ContentHash>,
    artifact_hash: ContentHash,
    finding_hash: ContentHash,
) {
    match entries.entry(artifact_hash) {
        Entry::Vacant(entry) => {
            entry.insert(finding_hash);
        }
        Entry::Occupied(mut entry) if finding_hash < *entry.get() => {
            entry.insert(finding_hash);
        }
        Entry::Occupied(_) => {}
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut decoded = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        decoded.push((high << 4) | low);
    }
    Some(decoded)
}

static FRONTIER_CLAIM_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn frontier_claim_temp_path(path: &Path, lease: &FrontierLease) -> PathBuf {
    let mut temp_path = path.to_path_buf();
    let sequence = FRONTIER_CLAIM_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    temp_path.set_file_name(format!(
        ".{}.{}.{}.claim.tmp",
        lease.lease_id.to_hex(),
        std::process::id(),
        sequence
    ));
    temp_path
}

fn frontier_claim_lock_temp_path(path: &Path, node: &ContentHash, expires_at_tick: u64) -> PathBuf {
    let mut temp_path = path.to_path_buf();
    let sequence = FRONTIER_CLAIM_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    temp_path.set_file_name(format!(
        ".{}.{}.{}.{}.claim-lock.tmp",
        node.to_hex(),
        expires_at_tick,
        std::process::id(),
        sequence
    ));
    temp_path
}
