// Read-only custody observations for the isolated controlled runtime wrapper.
// This module is never imported by the deployed ordinary Worker.

/** Reads selected durable facts without clearing, reconciling or listing state. */
export async function guardState(storage, claimId) {
  if (typeof claimId !== "string" || !/^[a-zA-Z0-9_.:-]{1,128}$/.test(claimId)) {
    throw new Error("invalid controlled delete claim selector");
  }
  const [pendingMutation, pendingDelete, receipt, mirrorOwner] = await Promise.all([
    storage.get("pending-mutation"),
    storage.get("pending-delete"),
    storage.get(`delete-receipt:${claimId}`),
    storage.get("mirror-owner"),
  ]);
  // These are the closed production journal fields. Do not return arbitrary
  // storage values or environment bindings through fixture observations.
  const claim = value => value ? {
    claim_id: value.claim_id,
    expected_etag: value.expected_etag,
    expected_size: value.expected_size,
    expected_hash: value.expected_hash ?? null,
    expected_provider_version: value.expected_provider_version ?? null,
  } : null;
  return {
    pendingMutation: pendingMutation ? {
      operation_id: pendingMutation.operation_id,
      key: pendingMutation.key,
      kind: pendingMutation.kind,
      fingerprint: pendingMutation.fingerprint,
    } : null,
    pendingDelete: claim(pendingDelete),
    deleteReceipt: receipt ? {
      claim: claim(receipt.claim),
      outcome: { kind: receipt.outcome.kind, etag: receipt.outcome.etag ?? null },
    } : null,
    mirrorOwnerJobId: mirrorOwner?.job_id ?? null,
  };
}
