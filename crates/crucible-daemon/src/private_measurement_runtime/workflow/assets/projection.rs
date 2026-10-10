//! Decodes the exact authored artifact and fixed row identities.
//!
//! This projection is read from the already-authenticated workflow bytes under
//! the same original decoder. Its data does not issue an execution entitlement.

pub(super) use crucible::owned_decode::json_profiles::assets::{
    Artifact, Attempt, CampaignCreation, GuestAssets, Projection, RootImageFormat,
};

use super::ArtifactCause;

trait CreationValidation {
    fn validate(&self, seed: u64) -> Result<(), ArtifactCause>;
}

impl CreationValidation for CampaignCreation {
    fn validate(&self, seed: u64) -> Result<(), ArtifactCause> {
        if self.schema != "crucible.measurement-campaign-creation.v1"
            || !named_seed(&self.request_file, "create-", ".bin", seed)
            || self.request_bytes == 0
            || self.request_bytes > crucible_campaign::MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES as u64
            || blake3::Hash::from_hex(&self.request_blake3).is_err()
            || self.generators.len() > crucible_campaign::MAX_CREATE_CAMPAIGN_GENERATORS
        {
            return Err(ArtifactCause::Identity);
        }
        let mut total = 0_u64;
        let mut prior = None;
        for (index, generator) in self.generators.iter().enumerate() {
            let name = generator
                .file
                .strip_prefix("generator-")
                .and_then(|name| name.strip_suffix(".bin"))
                .and_then(|name| name.split_once('-'));
            if name.is_none_or(|(actual_seed, actual_index)| {
                actual_seed.parse::<u64>().ok() != Some(seed)
                    || actual_index.parse::<usize>().ok() != Some(index)
                    || actual_seed.starts_with('0')
                    || (actual_index.len() > 1 && actual_index.starts_with('0'))
                    || !actual_seed.bytes().all(|byte| byte.is_ascii_digit())
                    || !actual_index.bytes().all(|byte| byte.is_ascii_digit())
            }) || generator.bytes == 0
                || generator.bytes > 4 << 20
                || blake3::Hash::from_hex(&generator.blake3).is_err()
                || prior.is_some_and(|prior| prior >= generator.id)
            {
                return Err(ArtifactCause::Identity);
            }
            total = total
                .checked_add(generator.bytes)
                .ok_or(ArtifactCause::Identity)?;
            prior = Some(generator.id);
        }
        if total > crucible_campaign::MAX_CREATE_CAMPAIGN_GENERATOR_BYTES as u64 {
            return Err(ArtifactCause::Identity);
        }
        Ok(())
    }
}

pub(super) trait ProjectionValidation {
    fn validate(&self) -> Result<usize, ArtifactCause>;
}

impl ProjectionValidation for Projection {
    fn validate(&self) -> Result<usize, ArtifactCause> {
        if self.schema != "crucible.measurement-resident-workflow.v2"
            || self.family != "residentThroughput"
            || ![1, 2, 4].contains(&self.native_count)
            || self.hot_fork.is_some()
            || self.world_memory_mib != 512
            || self.execution_quanta != 32
            || self.rows.len() != 9
            || self.guest_assets.architecture != "x86_64"
            || self.guest_assets.boot_mode != "directKernel"
            || self.guest_assets.kernel_cmdline.as_bytes().contains(&0)
        {
            return Err(ArtifactCause::Identity);
        }
        self.qemu.validate()?;
        self.plugin.validate()?;
        self.guest_assets.kernel.validate()?;
        self.guest_assets.root_image.validate()?;
        if let Some(initrd) = &self.guest_assets.initrd {
            initrd.validate()?;
        }
        let preceding = match self.native_count {
            1 => 0,
            2 => 1,
            4 => 3,
            _ => return Err(ArtifactCause::Identity),
        };
        for (index, row) in self.rows.iter().enumerate() {
            let target = index / 3;
            if row.target_divisor != [1, 2, 0][target]
                || row.repeat != index % 3
                || row.attempts.len() != self.native_count
            {
                return Err(ArtifactCause::Identity);
            }
            for (worker, attempt) in row.attempts.iter().enumerate() {
                let seed = 1000
                    + (target * 21 + preceding * 3 + row.repeat * self.native_count + worker)
                        as u64;
                attempt.campaign_creation.validate(seed)?;
                if attempt.seed != seed
                    || !named_seed(&attempt.campaign, "throughput-", "", seed)
                    || !named_seed(&attempt.scenario_file, "scenario-", ".bin", seed)
                    || !named_seed(&attempt.schedule_file, "schedule-", ".bin", seed)
                    || blake3::Hash::from_hex(&attempt.scenario_blake3).is_err()
                    || blake3::Hash::from_hex(&attempt.schedule_blake3).is_err()
                {
                    return Err(ArtifactCause::Identity);
                }
            }
        }
        Ok(9 * self.native_count)
    }
}

trait ArtifactValidation {
    fn validate(&self) -> Result<(), ArtifactCause>;
}

impl ArtifactValidation for Artifact {
    fn validate(&self) -> Result<(), ArtifactCause> {
        let path = std::path::Path::new(&self.path);
        if !path.is_absolute()
            || !path.starts_with("/nix/store")
            || path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
            || self.path.as_bytes().contains(&0)
            || self.bytes == 0
            || blake3::Hash::from_hex(&self.blake3).is_err()
        {
            return Err(ArtifactCause::Identity);
        }
        Ok(())
    }
}

fn named_seed(value: &str, prefix: &str, suffix: &str, seed: u64) -> bool {
    value
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(suffix))
        .is_some_and(|number| {
            !number.is_empty()
                && !number.starts_with('0')
                && number.bytes().all(|byte| byte.is_ascii_digit())
                && number.parse::<u64>().ok() == Some(seed)
        })
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- malformed wire assertions stop these controls.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crucible::owned_decode::json_profiles::assets::Generator;
    use crucible_campaign::{CampaignHash, ConfigurationArtifactId, ScenarioDefId};
    use crucible_cas::content_store::{ContentId, ObjectKind};

    fn fixture_content_id(tag: &str, kind: ObjectKind, schema: u32) -> String {
        format!(
            "{tag}@{}",
            ContentId::for_bytes(kind, schema, b"fixture").encode()
        )
    }

    #[test]
    fn an_old_attempt_without_canonical_creation_is_rejected() {
        let hash = CampaignHash::from_bytes([1; 32]);
        let old = serde_json::json!({
            "seed": 1000,
            "campaign": "throughput-1000",
            "scenarioFile": "scenario-1000.bin",
            "scheduleFile": "schedule-1000.bin",
            "scenarioId": ScenarioDefId::from_hash(hash),
            "configurationArtifactId": ConfigurationArtifactId::parse(&fixture_content_id(
                "crucible.campaign.configuration-artifact", ObjectKind::Configuration, 1
            )).unwrap(),
            "scenarioBlake3": "01".repeat(32),
            "scheduleBlake3": "02".repeat(32)
        });
        let refusal = serde_json::from_value::<Attempt>(old).err().unwrap();
        assert!(refusal.to_string().contains("campaignCreation"));
    }

    #[test]
    fn canonical_creation_requires_its_exact_leaf_names_and_sorted_generator_ids() {
        let hash = CampaignHash::from_bytes([1; 32]);
        let mut creation = CampaignCreation {
            schema: "crucible.measurement-campaign-creation.v1".into(),
            request_file: "create-1000.bin".into(),
            request_bytes: 1,
            request_blake3: "01".repeat(32),
            request_digest: hash,
            lineage_id: crucible_campaign::CampaignLineageId::parse(&fixture_content_id(
                "crucible.campaign.lineage",
                ObjectKind::CampaignFact,
                1,
            ))
            .unwrap(),
            policy_id: crucible_campaign::CampaignPolicyId::parse(&fixture_content_id(
                "crucible.campaign.policy",
                ObjectKind::Policy,
                5,
            ))
            .unwrap(),
            generators: vec![Generator {
                file: "generator-1000-0.bin".into(),
                bytes: 1,
                blake3: "02".repeat(32),
                id: crucible_campaign::CandidateGeneratorSpecId::parse(&fixture_content_id(
                    "crucible.campaign.candidate-generator-spec",
                    ObjectKind::Policy,
                    1,
                ))
                .unwrap(),
            }],
        };
        assert!(creation.validate(1000).is_ok());
        creation.request_file = "../create-1000.bin".into();
        assert!(creation.validate(1000).is_err());
        creation.request_file = "create-1000.bin".into();
        creation.generators[0].file = "generator-1001-0.bin".into();
        assert!(creation.validate(1000).is_err());
        creation.generators[0].file = "generator-1000-0.bin".into();
        creation.generators.push(Generator {
            file: "generator-1000-1.bin".into(),
            bytes: 1,
            blake3: "02".repeat(32),
            id: crucible_campaign::CandidateGeneratorSpecId::parse(&fixture_content_id(
                "crucible.campaign.candidate-generator-spec",
                ObjectKind::Policy,
                1,
            ))
            .unwrap(),
        });
        assert!(creation.validate(1000).is_err());
    }
}
