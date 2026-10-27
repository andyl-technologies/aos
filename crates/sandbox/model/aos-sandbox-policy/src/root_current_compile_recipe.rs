//! Shares the complete current-Create compiler comparison programme lexically.
//!
//! Macro expansion retains each owner's guarded source readers, private nominal
//! models and diagnostic custody at their actual original call sites. The
//! recipes define no native owner, runtime callback or public input adopter.

/// Expands the complete current-Create compiler programme in its owner's frame.
///
/// Source, publisher and signed-source expressions remain concrete lexical
/// owner operations at their original positions. Diagnostic paths are existing
/// owning projections, not callbacks or a new authority interface. The nominal
/// Source, Values and verifier remain private to the actual owning module.
///
/// # Errors
/// Preserves each original guarded read, decoder, comparison and compiler error.
#[macro_export]
macro_rules! compile_root_current_policy_data_v1 {
    (
        inputs = ($controller:ident, $root_policy:ident, $policy_data:ident,
            $source_current:ident, $cache_current:ident, $bundle:ident,
            $parent:ident, $assignment:ident, $now:ident),
        values = $values:ident, verifier = $verifier:ident,
        bindings = ($source:ident, $signed:ident),
        source = $source_expr:expr, publisher_expiry = $publisher_expiry:block,
        signed = $signed_expr:expr,
        changed = $changed:expr, preview_error = $preview_error:expr,
        capacity_error = $capacity_error:expr,
        layer_error = [$($layer_error:path)?], input_error = [$($input_error:path)?]
    ) => {{

        // These existing consuming readers validate full public authorization,
        // exact idempotency key/acceptance revision, Desired and publisher history.
        // They only read this actual already-replayed readonly Journal.
        let $source = $source_expr?;
        let publisher_expires_at = $publisher_expiry;
        let preview = aos_sandbox_protocol::domain_ledger::create_q04_history::transfer::Q04PreviewV1::decode($bundle.policy_sources, $parent.nonce())?;
        $policy_data.require_preview_data_v1(preview.fields()).map_err(|_| $preview_error)?;
        let $signed = $signed_expr?;
        let publisher = aos_sandbox_model::format::decode_policy($source.canonical_policy(), aos_sandbox_model::DecodeLimits::default())?;
        let (project, deployment_head, deployment) = &$signed;
        let project_head = project.head();
        if $source.operation_revision() != $parent.operation_revision()
            || $source.accepted_generation() != $parent.accepted_generation()
            || $source.projection_revision() != $parent.desired_precondition()
            || $source.project().as_bytes() != &$source_current.project
            || $source.sandbox().as_bytes() != &$source_current.sandbox
            || $source.commitment().as_bytes() != &$source_current.controller_source
            || $parent.ancestry().as_bytes() != &$source_current.tree_head
            || project_head.project() != $source.project()
            || project_head.publisher_generation() != $source.policy_generation()
            || project_head.publisher_digest() != $source.policy_digest()
            || project.cache_domain() != $source.cache_domain()
            || project.revocation() != publisher.revocation()
            || project_head.prerequisite_claims() != [
                aos_sandbox_model::ObjectDigest::from_bytes($source_current.tree_head),
                deployment_head.packet_digest(), $source.cache_domain_head(), $source.revocation_head(),
            ]
            || $now >= project_head.expires_at() || $now >= deployment_head.expires_at()
            || !deployment.endpoints().entries().is_empty()
            || !deployment.destinations().entries().is_empty()
            || $cache_current.snapshot.association.project != *$source.project().as_bytes()
            || $cache_current.snapshot.association.sandbox != *$source.sandbox().as_bytes()
        {
            return Err($changed.into());
        }

        let verifier = $verifier {
            source: &$source,
            fresh_source: $source_current,
            cache: $cache_current,
        };
        let domain = $crate::AuthenticatedCacheDomainV1::authenticate(
            project.cache_domain(),
            $crate::CacheDomainBindingV1::Project($source.project()),
            &verifier,
        )?;
        let layer = project
            .q04_layer_recipe()
            .materialize_with_authenticated_binding(domain)
            $(.map_err($layer_error))? ?;
        let relation = $crate::AuthenticatedSandboxProjectRelationV1::authenticate(
            $source.sandbox(), $source.project(), &verifier)?;
        let input = $crate::parentless_input::parentless_create_input_from_authenticated_layers_v1(
            relation, layer, deployment,
        )$(.map_err($input_error))? ?;
        let candidate = $crate::PolicyCompilerV1::compile_retained(&input)?;
        let origin = aos_sandbox_protocol::policy_data::RetainedPublisherCompilerOriginV3::from_record_bytes($bundle.compiler_origin)?;
        $crate::compare_publisher_compiler_derivation_v3(&origin, &input, &candidate)?;
        if origin.project() != $parent.project() || origin.original_target() != $parent.sandbox()
            || origin.candidate().as_bytes() != &$parent.bytes()[488..520]
        { return Err($changed.into()); }

        let specification = aos_sandbox_model::format::decode_sandbox_spec($bundle.specification, aos_sandbox_model::DecodeLimits::default())?;
        $crate::require_specification_resource_profile_v1(
            specification.resource_profile(), candidate.hard_resources().core_profile(),
        )?;
        let media = aos_sandbox_model::MediaType::new(aos_sandbox_model::format::sandbox_spec_media_type(&specification).as_str())?;
        let spec_descriptor = aos_sandbox_model::format::descriptor_for_bytes(media, $bundle.specification);
        let manifest = $assignment.manifest();
        let policy = candidate.portable().policy();
        let mut commitments = policy.input_commitments().to_vec();
        commitments.sort();
        commitments.dedup();
        let features = aos_sandbox_model::model::assignment_required_features_v1(policy, &specification)?;
        if manifest.sandbox_spec() != &spec_descriptor || manifest.policy() != candidate.portable().policy_descriptor()
            || manifest.environment() != specification.environment()
            || manifest.root_view() != specification.root_view()
            || manifest.source_commitments() != commitments
            || manifest.required_features() != features
            || manifest.resource_commitment() != aos_sandbox_model::resource_profile_digest_v1(policy.limits())
            || manifest.reservations() != $crate::q04_candidate_capacity_v1!(
                &candidate, $capacity_error
            )?
        { return Err($changed.into()); }
        Ok($values { source: $source, signed: $signed, publisher, specification, input, candidate, origin,
            publisher_expires_at })

    }};
}

/// Defines the existing private current-Create verifier in the owner's module.
///
/// The caller's Source type stays nominal and private. No public constructor,
/// relation/domain adopter or runtime verifier abstraction is added.
#[macro_export]
macro_rules! define_root_current_input_verifier_v1 {
    ($verifier:ident, $source_type:ty) => {
        // This private view can be created only inside the complete joined consumer.
        // It borrows the actual current Controller publisher observation and the fresh
        // independently verified Source/Cache results. It exposes no factory or grant.
        struct $verifier<'current> {
            source: &'current $source_type,
            fresh_source: aos_sandbox_protocol::domain_ledger::create_storage_history::source_current::SourceCurrentReplyFieldsV1,
            cache: &'current aos_sandbox_protocol::domain_ledger::create_storage_history::cache_held::current_proof::CacheCurrentProofBodyDataV1,
        }

        impl $crate::CacheDomainVerifierV1 for $verifier<'_> {
            fn verify(&self, descriptor: &aos_sandbox_model::ObjectDescriptor, canonical: &[u8]) -> bool {
                let expected = aos_sandbox_protocol::policy_data::canonical_bytes(
                    b"aos.sandbox.cache-domain-binding.v2",
                    &(self.source.cache_domain(), $crate::CacheDomainBindingV1::Project(self.source.project())),
                )
                .map_err($crate::PolicyModelError::from);
                let Ok(expected) = expected else { return false; };
                let Ok(media) = aos_sandbox_model::MediaType::new(aos_sandbox_model::PortableMediaType::Content.as_str()) else { return false; };
                canonical == expected && aos_sandbox_model::format::descriptor_for_bytes(media, canonical) == *descriptor
                    && self.cache.snapshot.association.project == *self.source.project().as_bytes()
                    && self.cache.snapshot.association.sandbox == *self.source.sandbox().as_bytes()
            }
        }

        impl $crate::SandboxProjectRelationVerifierV1 for $verifier<'_> {
            fn verify(&self, sandbox: aos_sandbox_model::SandboxId, project: aos_sandbox_model::ProjectId,
                descriptor: &aos_sandbox_model::ObjectDescriptor, canonical: &[u8]) -> bool
            {
                let Ok(media) = aos_sandbox_model::MediaType::new(aos_sandbox_model::PortableMediaType::Content.as_str()) else { return false; };
                sandbox == self.source.sandbox() && project == self.source.project()
                    && self.fresh_source.sandbox == *sandbox.as_bytes()
                    && self.fresh_source.project == *project.as_bytes()
                    && self.fresh_source.controller_source == *self.source.commitment().as_bytes()
                    && aos_sandbox_model::format::descriptor_for_bytes(media, canonical) == *descriptor
            }
        }
    };
}
