//! Tier-1 slot and promotion preflight builders, the finalized-code thunk
//! transmute helper, and the force-aware registered native thunk-call preflights.

use super::*;

/// Finalizes one artifact and installs its pointer into owned tier-1 slot metadata.
///
/// The returned preflight keeps the `JITModule` owner and the safe
/// [`JitTieredCodeSlot`] in the same value. The slot's code pointer is still
/// metadata only: this does not publish into an evaluator heap thunk, cast the
/// pointer to a function type, call native code, or lower generic IR.
///
/// # Errors
///
/// Returns any error from
/// [`jit_cranelift_artifact_finalization_preflight_for_artifact`]. Returns
/// [`JitCraneliftModuleSetupError::InstallTier1Code`] if the finalized pointer
/// metadata cannot be installed into the fresh slot.
///
/// # Panics
///
/// Panics under the same Cranelift unresolved-import and finalized-function
/// lookup conditions as [`jit_cranelift_artifact_finalization_preflight_for_artifact`].
pub fn jit_cranelift_tier1_slot_preflight_for_artifact(
    artifact: JitClifArtifact,
) -> Result<JitCraneliftTier1SlotPreflight, JitCraneliftModuleSetupError> {
    let finalization = jit_cranelift_artifact_finalization_preflight_for_artifact(artifact)?;
    tier1_slot_preflight_from_finalization(finalization, JitTieredCodeSlot::new())
}

pub(crate) fn thunk_entry_from_finalized_code(code_ptr: NonNull<u8>) -> JitThunkFn {
    // SAFETY: Cranelift returned this pointer for a function defined with the
    // frozen thunk signature lowered from `ratchet-core` metadata. The caller
    // validates the artifact kind and keeps the owning `JITModule` alive while
    // the returned entry is called.
    let entry = unsafe { mem::transmute::<*mut u8, JitThunkFn>(code_ptr.as_ptr()) };
    entry
}

/// Finalizes one registered artifact and installs it into owned tier-1 metadata.
///
/// The returned preflight composes
/// [`jit_cranelift_registered_artifact_finalization_preflight_with_candidates`]
/// with safe [`JitTieredCodeSlot`] installation. Registered addresses may be used
/// by Cranelift relocation during finalization, but this path does not
/// dereference or call those addresses, publish into evaluator heap thunk state,
/// cast the finalized code pointer, or call native code. Stable runtime symbols
/// outside the artifact's import set may remain registration gaps.
///
/// # Errors
///
/// Returns any error from
/// [`jit_cranelift_registered_artifact_finalization_preflight_with_candidates`].
/// Returns [`JitCraneliftModuleSetupError::InstallTier1Code`] if the finalized
/// pointer metadata cannot be installed into the fresh slot.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`jit_cranelift_registered_artifact_finalization_preflight_with_candidates`].
pub fn jit_cranelift_registered_tier1_slot_preflight_with_candidates(
    artifact: JitClifArtifact,
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<JitCraneliftRegisteredTier1SlotPreflight, JitCraneliftModuleSetupError> {
    let finalization = jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
        artifact, candidates,
    )?;
    registered_tier1_slot_preflight_from_finalization(finalization, JitTieredCodeSlot::new())
}

/// Records one invocation and compiles a supported IR root only when policy promotes.
///
/// This is the first safe compile-on-hotness composition point. It records one
/// invocation in `slot`, asks `policy` whether tier 1 should be selected, and
/// lowers/finalizes `root` only when the resulting [`TierUpDecision`] requests
/// promotion. Promoted results keep the finalized `JITModule` owner beside the
/// installed slot metadata. Non-promoted results return the updated slot without
/// lowering, module construction, finalization, or pointer installation.
///
/// # Errors
///
/// Returns [`JitCraneliftTier1PromotionError`] if policy requests promotion but
/// the current literal-only lowerer cannot lower `root`, or if artifact
/// finalization or tier-slot installation fails. The error preserves the
/// invocation-updated slot and the policy decision alongside the underlying
/// setup error.
///
/// # Panics
///
/// Panics under the same Cranelift unresolved-import and finalized-function
/// lookup conditions as [`jit_cranelift_artifact_finalization_preflight_for_artifact`]
/// when policy requests promotion.
pub fn jit_cranelift_tier1_promotion_preflight_for_ir_root(
    mut slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    arena: &IrArena,
    root: IrId,
) -> Result<JitCraneliftTier1PromotionPreflight, JitCraneliftTier1PromotionError> {
    let decision = slot.record_invocation_with_demand_hint(policy, demand_hint);
    if !decision.should_promote() {
        return Ok(JitCraneliftTier1PromotionPreflight::StayedInTier { slot, decision });
    }

    let artifact = match lower_constant_ir_thunk_body_artifact(arena, root) {
        Ok(artifact) => artifact,
        Err(source) => {
            return Err(JitCraneliftTier1PromotionError::new(
                slot,
                decision,
                JitCraneliftModuleSetupError::LowerTier1Artifact { root, source },
            ));
        }
    };
    let finalization = match jit_cranelift_artifact_finalization_preflight_for_artifact(artifact) {
        Ok(finalization) => finalization,
        Err(source) => return Err(JitCraneliftTier1PromotionError::new(slot, decision, source)),
    };
    let preflight = tier1_slot_preflight_from_finalization_preserving_slot(finalization, slot)
        .map_err(|(slot, source)| JitCraneliftTier1PromotionError::new(slot, decision, source))?;

    Ok(JitCraneliftTier1PromotionPreflight::Promoted {
        preflight,
        decision,
    })
}

/// Records one invocation and compiles a supported registered IR root on promotion.
///
/// This composes tier-up policy with the registered-symbol tier-1 slot path. It
/// supports the current literal roots, local environment-slot roots that lower
/// to `aos_env_get` runtime calls, direct local-slot application roots that
/// lower to `aos_env_get` plus `aos_apply` runtime calls, and bounded
/// local-slot update roots that lower to `aos_env_get`, `aos_force`, and
/// `aos_update` runtime calls. Non-promoted results return the updated slot
/// without lowering, module construction, finalization, or pointer
/// installation.
///
/// # Errors
///
/// Returns [`JitCraneliftTier1PromotionError`] if policy requests promotion but
/// the current registered lowerer cannot lower `root`, if required artifact
/// runtime imports lack matching candidates, or if finalization or tier-slot
/// installation fails. The error preserves the invocation-updated slot and the
/// policy decision alongside the underlying setup error.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`jit_cranelift_registered_artifact_finalization_preflight_with_candidates`]
/// when policy requests promotion.
pub fn jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
    mut slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    arena: &IrArena,
    root: IrId,
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<JitCraneliftRegisteredTier1PromotionPreflight, JitCraneliftTier1PromotionError> {
    let decision = slot.record_invocation_with_demand_hint(policy, demand_hint);
    if !decision.should_promote() {
        return Ok(JitCraneliftRegisteredTier1PromotionPreflight::StayedInTier { slot, decision });
    }

    let artifact = match lower_tier1_ir_thunk_body_artifact(arena, root) {
        Ok(artifact) => artifact,
        Err(source) => {
            return Err(JitCraneliftTier1PromotionError::new(
                slot,
                decision,
                JitCraneliftModuleSetupError::LowerTier1Artifact { root, source },
            ));
        }
    };
    let finalization =
        match jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
            artifact, candidates,
        ) {
            Ok(finalization) => finalization,
            Err(source) => {
                return Err(JitCraneliftTier1PromotionError::new(slot, decision, source));
            }
        };
    let preflight =
        registered_tier1_slot_preflight_from_finalization_preserving_slot(finalization, slot)
            .map_err(|(slot, source)| {
                JitCraneliftTier1PromotionError::new(slot, decision, source)
            })?;

    Ok(JitCraneliftRegisteredTier1PromotionPreflight::Promoted {
        preflight,
        decision,
    })
}

/// Records one invocation and compiles a supported registered full-IR root on promotion.
///
/// This is the full lowered-IR counterpart to
/// [`jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates`].
/// It preserves the arena-only literal, env-slot, apply, and bounded local-slot
/// update roots, and also admits bounded static attr selections because full IR
/// carries the attr-path side tables required by `aos_select_ic` lowering.
///
/// # Errors
///
/// Returns [`JitCraneliftTier1PromotionError`] if policy requests promotion but
/// the current full-IR lowerer cannot lower `root`, required artifact runtime
/// imports lack matching candidates, finalization fails, or tier-slot
/// installation fails. The error preserves the invocation-updated slot and the
/// policy decision alongside the underlying setup error.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`jit_cranelift_registered_artifact_finalization_preflight_with_candidates`]
/// when policy requests promotion and Cranelift finalizes an artifact.
pub fn jit_cranelift_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidates(
    mut slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    ir: &Ir,
    root: IrId,
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<JitCraneliftRegisteredTier1PromotionPreflight, JitCraneliftTier1PromotionError> {
    let decision = slot.record_invocation_with_demand_hint(policy, demand_hint);
    if !decision.should_promote() {
        return Ok(JitCraneliftRegisteredTier1PromotionPreflight::StayedInTier { slot, decision });
    }

    let artifact = match lower_tier1_ir_thunk_body_artifact_for_ir(ir, root) {
        Ok(artifact) => artifact,
        Err(source) => {
            return Err(JitCraneliftTier1PromotionError::new(
                slot,
                decision,
                JitCraneliftModuleSetupError::LowerTier1Artifact { root, source },
            ));
        }
    };
    let finalization =
        match jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
            artifact, candidates,
        ) {
            Ok(finalization) => finalization,
            Err(source) => {
                return Err(JitCraneliftTier1PromotionError::new(slot, decision, source));
            }
        };
    let preflight =
        registered_tier1_slot_preflight_from_finalization_preserving_slot(finalization, slot)
            .map_err(|(slot, source)| {
                JitCraneliftTier1PromotionError::new(slot, decision, source)
            })?;

    Ok(JitCraneliftRegisteredTier1PromotionPreflight::Promoted {
        preflight,
        decision,
    })
}

/// Records one invocation and compiles a force-aware registered IR root on promotion.
///
/// This composes tier-up policy with the registered-symbol tier-1 slot path, but
/// uses the force-call lowerer for local environment-slot roots. Literal roots
/// still lower through the constant path, and direct local-slot application
/// roots still lower through the `aos_apply` helper because apply owns the
/// function-call forcing boundary. Local-slot roots can finalize when the
/// candidate set contains both `aos_env_get` and `aos_force`; direct local-slot
/// application roots can finalize when the candidate set contains both
/// `aos_env_get` and `aos_apply`; bounded local-slot update roots can finalize
/// when the candidate set contains `aos_env_get`, `aos_force`, and
/// `aos_update`. Successful promotions install the resulting opaque code
/// pointer into owned tier-1 slot metadata.
///
/// Non-promoted results return the updated slot without lowering, module
/// construction, finalization, or pointer installation.
///
/// # Errors
///
/// Returns [`JitCraneliftTier1PromotionError`] if policy requests promotion but
/// the current force-aware lowerer cannot lower `root`, if required artifact
/// runtime imports lack matching candidates, or if finalization or tier-slot
/// installation fails. The error preserves the invocation-updated slot and the
/// policy decision alongside the underlying setup error.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`jit_cranelift_registered_artifact_finalization_preflight_with_candidates`]
/// when policy requests promotion and Cranelift finalizes an artifact.
pub fn jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates(
    mut slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    arena: &IrArena,
    root: IrId,
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<JitCraneliftRegisteredTier1PromotionPreflight, JitCraneliftTier1PromotionError> {
    let decision = slot.record_invocation_with_demand_hint(policy, demand_hint);
    if !decision.should_promote() {
        return Ok(JitCraneliftRegisteredTier1PromotionPreflight::StayedInTier { slot, decision });
    }

    let artifact = match lower_force_aware_tier1_ir_thunk_body_artifact(arena, root) {
        Ok(artifact) => artifact,
        Err(source) => {
            return Err(JitCraneliftTier1PromotionError::new(
                slot,
                decision,
                JitCraneliftModuleSetupError::LowerTier1Artifact { root, source },
            ));
        }
    };
    let finalization =
        match jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
            artifact, candidates,
        ) {
            Ok(finalization) => finalization,
            Err(source) => {
                return Err(JitCraneliftTier1PromotionError::new(slot, decision, source));
            }
        };
    let preflight =
        registered_tier1_slot_preflight_from_finalization_preserving_slot(finalization, slot)
            .map_err(|(slot, source)| {
                JitCraneliftTier1PromotionError::new(slot, decision, source)
            })?;

    Ok(JitCraneliftRegisteredTier1PromotionPreflight::Promoted {
        preflight,
        decision,
    })
}

/// Records one invocation and compiles a force-aware registered full-IR root on promotion.
///
/// This is the full lowered-IR counterpart to
/// [`jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates`].
/// It preserves the arena-only literal, forced env-slot, apply, and bounded
/// local-slot update roots, and additionally admits bounded static attr
/// selections that import `aos_env_get`, `aos_force`, and `aos_select_ic`.
///
/// # Errors
///
/// Returns [`JitCraneliftTier1PromotionError`] if policy requests promotion but
/// the current full-IR force-aware lowerer cannot lower `root`, required
/// artifact runtime imports lack matching candidates, finalization fails, or
/// tier-slot installation fails. The error preserves the invocation-updated
/// slot and the policy decision alongside the underlying setup error.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`jit_cranelift_registered_artifact_finalization_preflight_with_candidates`]
/// when policy requests promotion and Cranelift finalizes an artifact.
pub fn jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_lowered_ir_root_with_candidates(
    mut slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    ir: &Ir,
    root: IrId,
    candidates: &[JitRuntimeSymbolAddressCandidate],
) -> Result<JitCraneliftRegisteredTier1PromotionPreflight, JitCraneliftTier1PromotionError> {
    let decision = slot.record_invocation_with_demand_hint(policy, demand_hint);
    if !decision.should_promote() {
        return Ok(JitCraneliftRegisteredTier1PromotionPreflight::StayedInTier { slot, decision });
    }

    let artifact = match lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(ir, root) {
        Ok(artifact) => artifact,
        Err(source) => {
            return Err(JitCraneliftTier1PromotionError::new(
                slot,
                decision,
                JitCraneliftModuleSetupError::LowerTier1Artifact { root, source },
            ));
        }
    };
    let finalization =
        match jit_cranelift_registered_artifact_finalization_preflight_with_candidates(
            artifact, candidates,
        ) {
            Ok(finalization) => finalization,
            Err(source) => {
                return Err(JitCraneliftTier1PromotionError::new(slot, decision, source));
            }
        };
    let preflight =
        registered_tier1_slot_preflight_from_finalization_preserving_slot(finalization, slot)
            .map_err(|(slot, source)| {
                JitCraneliftTier1PromotionError::new(slot, decision, source)
            })?;

    Ok(JitCraneliftRegisteredTier1PromotionPreflight::Promoted {
        preflight,
        decision,
    })
}

/// Records one invocation, compiles a force-aware registered IR root, and calls it on promotion.
///
/// This is the first promotion-gated native execution composition point. It
/// records one invocation in `slot`, asks `policy` whether tier 1 should be
/// selected, and only when promotion is requested lowers a currently supported
/// force-aware registered IR root, finalizes it with explicit native-address
/// candidates, calls the resulting thunk entry, and installs the finalized code
/// pointer into the updated slot metadata.
///
/// Non-promoted results return the updated slot without lowering, requiring
/// candidates, constructing a module, finalizing code, or crossing the native
/// call boundary. This function does not publish into evaluator thunk state or
/// perform atomic thunk-state transitions.
///
/// # Safety
///
/// The caller must either prove this attempt cannot promote, or uphold the same
/// candidate, runtime/environment pointer, host ABI, non-unwinding, and valid
/// returned-tag requirements as
/// [`jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates`]
/// for any path that may promote and enter native code.
///
/// # Errors
///
/// Returns [`JitCraneliftRegisteredTier1NativeCallError`] if policy requests
/// promotion but the current force-aware lowerer cannot lower `root`, required
/// artifact runtime imports lack matching candidates, the host native `Value`
/// ABI is not supported, finalization or native invocation fails, the returned
/// valid-tag value has an invalid payload, or tier-slot metadata installation
/// fails. The error preserves the invocation-updated slot and the policy
/// decision alongside the underlying native-call error.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates`]
/// when policy requests promotion and Cranelift finalizes an artifact.
pub unsafe fn jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_ir_root_with_candidates(
    mut slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    arena: &IrArena,
    root: IrId,
    candidates: &[JitRuntimeSymbolAddressCandidate],
    rt: JitRuntimeContextPtr,
    env: JitEnvFramePtr,
) -> Result<
    JitCraneliftRegisteredTier1NativeCallPreflight,
    JitCraneliftRegisteredTier1NativeCallError,
> {
    let decision = slot.record_invocation_with_demand_hint(policy, demand_hint);
    if !decision.should_promote() {
        return Ok(JitCraneliftRegisteredTier1NativeCallPreflight::StayedInTier { slot, decision });
    }

    let artifact =
        lower_force_aware_tier1_ir_thunk_body_artifact(arena, root).map_err(|source| {
            JitCraneliftRegisteredTier1NativeCallError::new(
                slot.clone(),
                decision,
                JitCraneliftNativeCallError::FinalizeArtifact {
                    source: JitCraneliftModuleSetupError::LowerTier1Artifact { root, source },
                },
            )
        })?;
    // SAFETY: This function forwards its caller's native-address, runtime,
    // environment, host-ABI, non-unwinding, and valid returned-tag obligations
    // to the registered native thunk-call boundary.
    let promotion_gated_registered_native_thunk_invocation = unsafe {
        jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates(
            artifact, candidates, rt, env,
        )
    }
    .map_err(|source| {
        JitCraneliftRegisteredTier1NativeCallError::new(slot.clone(), decision, source)
    })?;

    let code_ptr = promotion_gated_registered_native_thunk_invocation
        .finalized_function()
        .compiled_code_ptr();
    if let Err(source) = slot.install_tier1_code(code_ptr) {
        return Err(JitCraneliftRegisteredTier1NativeCallError::new(
            slot,
            decision,
            JitCraneliftNativeCallError::FinalizeArtifact {
                source: JitCraneliftModuleSetupError::InstallTier1Code {
                    symbol_name: promotion_gated_registered_native_thunk_invocation
                        .finalized_function()
                        .symbol_name()
                        .to_owned(),
                    source,
                },
            },
        ));
    }

    Ok(
        JitCraneliftRegisteredTier1NativeCallPreflight::PromotedAndCalled {
            slot,
            invocation: promotion_gated_registered_native_thunk_invocation,
            decision,
        },
    )
}

/// Records one invocation, compiles a force-aware registered full-IR root, and calls it on promotion.
///
/// This is the full lowered-IR counterpart to
/// [`jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_ir_root_with_candidates`].
/// It preserves the arena-only native-call subset and adds bounded static attr
/// selections through the registered `aos_env_get`, `aos_force`, and
/// `aos_select_ic` helper path.
///
/// Non-promoted results return the updated slot without lowering, requiring
/// candidates, constructing a module, finalizing code, or crossing the native
/// call boundary. This function does not publish into evaluator thunk state or
/// perform atomic thunk-state transitions.
///
/// # Safety
///
/// The caller must either prove this attempt cannot promote, or uphold the same
/// candidate, runtime/environment pointer, host ABI, non-unwinding, and valid
/// returned-tag requirements as
/// [`jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates`]
/// for any path that may promote and enter native code.
///
/// # Errors
///
/// Returns [`JitCraneliftRegisteredTier1NativeCallError`] if policy requests
/// promotion but the current full-IR force-aware lowerer cannot lower `root`,
/// required artifact runtime imports lack matching candidates, the host native
/// `Value` ABI is not supported, finalization or native invocation fails, the
/// returned valid-tag value has an invalid payload, or tier-slot metadata
/// installation fails. The error preserves the invocation-updated slot and the
/// policy decision alongside the underlying native-call error.
///
/// # Panics
///
/// Panics under the same Cranelift finalized-function lookup conditions as
/// [`jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates`]
/// when policy requests promotion and Cranelift finalizes an artifact.
pub unsafe fn jit_cranelift_force_aware_registered_tier1_native_thunk_call_preflight_for_lowered_ir_root_with_candidates(
    mut slot: JitTieredCodeSlot,
    policy: TierUpPolicy,
    demand_hint: TierUpDemandHint,
    ir: &Ir,
    root: IrId,
    candidates: &[JitRuntimeSymbolAddressCandidate],
    rt: JitRuntimeContextPtr,
    env: JitEnvFramePtr,
) -> Result<
    JitCraneliftRegisteredTier1NativeCallPreflight,
    JitCraneliftRegisteredTier1NativeCallError,
> {
    let decision = slot.record_invocation_with_demand_hint(policy, demand_hint);
    if !decision.should_promote() {
        return Ok(JitCraneliftRegisteredTier1NativeCallPreflight::StayedInTier { slot, decision });
    }

    let artifact =
        lower_force_aware_tier1_ir_thunk_body_artifact_for_ir(ir, root).map_err(|source| {
            JitCraneliftRegisteredTier1NativeCallError::new(
                slot.clone(),
                decision,
                JitCraneliftNativeCallError::FinalizeArtifact {
                    source: JitCraneliftModuleSetupError::LowerTier1Artifact { root, source },
                },
            )
        })?;
    // SAFETY: This function forwards its caller's native-address, runtime,
    // environment, host-ABI, non-unwinding, and valid returned-tag obligations
    // to the registered native thunk-call boundary.
    let promotion_gated_registered_native_thunk_invocation = unsafe {
        jit_cranelift_registered_native_thunk_call_for_artifact_with_candidates(
            artifact, candidates, rt, env,
        )
    }
    .map_err(|source| {
        JitCraneliftRegisteredTier1NativeCallError::new(slot.clone(), decision, source)
    })?;

    let code_ptr = promotion_gated_registered_native_thunk_invocation
        .finalized_function()
        .compiled_code_ptr();
    if let Err(source) = slot.install_tier1_code(code_ptr) {
        return Err(JitCraneliftRegisteredTier1NativeCallError::new(
            slot,
            decision,
            JitCraneliftNativeCallError::FinalizeArtifact {
                source: JitCraneliftModuleSetupError::InstallTier1Code {
                    symbol_name: promotion_gated_registered_native_thunk_invocation
                        .finalized_function()
                        .symbol_name()
                        .to_owned(),
                    source,
                },
            },
        ));
    }

    Ok(
        JitCraneliftRegisteredTier1NativeCallPreflight::PromotedAndCalled {
            slot,
            invocation: promotion_gated_registered_native_thunk_invocation,
            decision,
        },
    )
}
