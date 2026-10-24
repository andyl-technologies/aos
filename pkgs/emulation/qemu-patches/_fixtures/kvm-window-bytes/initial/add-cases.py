"""Add original lineage and effect-before-admission regression cases."""
from pathlib import Path

path = Path(__file__).parent / 'initial-cases.inc'
body = path.read_text()
marker = 'int main(void)\n{\n'
assert body.count(marker) == 1
cases = r'''
static void refuse_unborn_or_changed_originals(void)
{
    for (unsigned defect = 0; defect < 12; defect++) {
        reset_initial(false);
        switch (defect) {
        case 0: initial_record.issued = false; break;
        case 1: initial_record.receipt_known = false; break;
        case 2: initial_record.no_birth_known = true; break;
        case 3: initial_record.receipt.native_vcpu_id++; break;
        case 4: initial_record.receipt.generation_begin++; break;
        case 5: initial_record.receipt.generation_end++; break;
        case 6: initial_record.receipt.flags &= ~KVM_CRUCIBLE_RUN_RETURN_CLOCK_ENTERED; break;
        case 7: initial_record.receipt.flags &= ~KVM_CRUCIBLE_RUN_RETURN_BEGIN_ACTIVE; break;
        case 8: initial_record.receipt.response_phase = KVM_CRUCIBLE_COMPLETION_MORE; break;
        case 9: initial_record.receipt.response_flags = KVM_CRUCIBLE_COMPLETION_UNCERTAIN; break;
        case 10: initial_record.receipt.response_sequence++; break;
        case 11: initial_record.receipt.response_consumed++; break;
        }
        /* Match the retained row copy so each predicate is tested independently
         * of the separately authenticated last-receipt equality guard. */
        initial_owner.last_receipt = initial_record.receipt;
        assert(!initial_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT,
                                0, 7, 11, true));
        assert(slot_submissions == 0 && device_transactions == 0);
    }

    reset_initial(false);
    initial_owner.original_cpu = NULL;
    assert(!initial_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT,
                            0, 7, 11, true));
    assert(slot_submissions == 0 && device_transactions == 0);
    reset_initial(false);
    original_service.attributes_known = false;
    assert(!initial_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT,
                            0, 7, 11, true));
    reset_initial(false);
    original_service.service_id = UINT64_MAX;
    assert(!initial_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT,
                            0, 7, 11, true));
    assert(slot_submissions == 0 && device_transactions == 0);
}

static void original_callback_revalidates_birth(void)
{
    reset_initial(false);
    g_free(initial_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT,
                           0, 7, 11, false));
    initial_record.receipt.native_vcpu_id++;
    initial_owner.last_receipt = initial_record.receipt;
    execute_callback();
    assert(device_transactions == 0 && original_entry.uncertain_effects &&
           original_entry.phase == CRUCIBLE_KVM_USERSPACE_UNKNOWN);
    assert(native.crucible_response_service_active && model_slot.active);
}

static void initial_geometry_and_arm_receipt(void)
{
    reset_initial(false);
    fixture_cpu.kvm_run->mmio.len = 0;
    original_entry.response.prepared = false;
    assert(!kvm_crucible_response_service_retain_attrs(
        &native, &fixture_cpu, (MemTxAttrs){0}));
    assert(original_entry.uncertain_effects && native.crucible_userspace_faulted);
    assert(device_transactions == 0 && slot_submissions == 0);

    reset_initial(false);
    native.crucible_clock_kernel_edition = 2;
    initial_record.receipt.pending_mask = KVM_CRUCIBLE_RUN_PENDING_MMIO;
    initial_owner.last_receipt = initial_record.receipt;
    g_free(initial_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT,
                           0, 7, 11, false));
    execute_callback();
    g_free(initial_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_POLL,
                           0, 7, 11, false));
    assert(device_transactions == 1 && !model_slot.active);

    reset_initial(true);
    native.crucible_clock_kernel_edition = 2;
    assert(!initial_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT,
                            0, 7, 11, true));
    assert(device_transactions == 0 && slot_submissions == 0);
}

'''
body = body.replace(marker, cases + marker)
body = body.replace('    first_fragment_refusals();\n', '    first_fragment_refusals();\n    refuse_unborn_or_changed_originals();\n    original_callback_revalidates_birth();\n    initial_geometry_and_arm_receipt();\n')
path.write_text(body)
