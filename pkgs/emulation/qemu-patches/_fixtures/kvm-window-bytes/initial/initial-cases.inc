
static CrucibleKvmOriginalReturn initial_record;
static CrucibleKvmWindowVcpu initial_owner;

static void reset_initial(bool io)
{
    reset();
    memset(&original_service, 0, sizeof(original_service));
    memset(&model_slot, 0, sizeof(model_slot));
    memset(&initial_record, 0, sizeof(initial_record));
    memset(&initial_owner, 0, sizeof(initial_owner));
    slot_busy = fail_transaction = false;
    slot_submissions = device_transactions = 0;
    model_stopped = true;
    model_clock_generation = 7;
    model_bql = true;
    native.crucible_response_service_configured = true;
    native.crucible_response_services = &original_service;
    native.crucible_clock_kernel_edition = 3;
    native.crucible_window_configured = true;
    native.crucible_window_roster_sealed = true;
    native.crucible_window_generation = 7;
    native.crucible_window_phase = CRUCIBLE_KVM_WINDOW_CLOSED;
    native.crucible_window_return_count = 1;
    native.crucible_window_returns = &initial_record;
    native.crucible_window_vcpus = &initial_owner;
    fixture_cpu.created = false;
    assert(kvm_crucible_response_service_bind_vcpu(&native, &fixture_cpu) == 0);
    fixture_cpu.created = true;
    original_entry.phase = CRUCIBLE_KVM_USERSPACE_HANDLING;
    original_entry.reserved_revisions = 1;
    native.crucible_userspace_reserved_revisions = 1;
    if (io) {
        fixture_cpu.kvm_run->exit_reason = KVM_EXIT_IO;
        fixture_cpu.kvm_run->io.direction = KVM_EXIT_IO_IN;
        fixture_cpu.kvm_run->io.size = 2;
        fixture_cpu.kvm_run->io.count = 3;
        fixture_cpu.kvm_run->io.port = 0x72;
        fixture_cpu.kvm_run->io.data_offset = 4096;
    }
    original_entry.exit_reason = fixture_cpu.kvm_run->exit_reason;
    assert(kvm_crucible_response_service_retain_attrs(&native, &fixture_cpu,
        (MemTxAttrs){ .secure = 1, .user = 1, .requester_id = 123 }));
    initial_record = (CrucibleKvmOriginalReturn) {
        .generation = 7, .expected_invocation = 11, .vcpu_index = 0,
        .native_result = 0, .issued = true, .receipt_known = true,
        .receipt = {
            .version = 1, .operation = KVM_CRUCIBLE_RUN_RETURN_QUERY,
            .expected_invocation = 11, .invocation = 11,
            .generation_begin = 7, .generation_end = 7,
            .native_vcpu_id = 42, .response_sequence = 1,
            .response_phase = KVM_CRUCIBLE_COMPLETION_PENDING,
            .flags = KVM_CRUCIBLE_RUN_RETURN_RETURNED |
                     KVM_CRUCIBLE_RUN_RETURN_CLOCK_ENTERED |
                     KVM_CRUCIBLE_RUN_RETURN_BEGIN_ACTIVE,
            .pending_mask = KVM_CRUCIBLE_RUN_PENDING_CALLBACK |
                (io ? KVM_CRUCIBLE_RUN_PENDING_PIO : KVM_CRUCIBLE_RUN_PENDING_MMIO),
        },
    };
    initial_owner = (CrucibleKvmWindowVcpu) {
        .assigned = true, .original_cpu = &fixture_cpu,
        .last_invocation = 11, .last_receipt = initial_record.receipt,
    };
}

static CrucibleKvmInitialResponseInfo *initial_command(
    CrucibleKvmInitialResponseOperation operation, uint32_t row,
    uint64_t generation, uint64_t invocation, bool refused)
{
    Error error = {0}, *pointer = &error;
    CrucibleKvmInitialResponseInfo *info = qmp_x_crucible_kvm_initial_response(
        operation, row, generation, invocation, &pointer);

    assert(error.set == refused && (info == NULL) == refused);
    if (info) {
        assert(info->schema_version == 1 && info->record_index == row &&
               info->generation == generation &&
               info->expected_invocation == invocation);
        assert(!info->profile_qualified && !info->device_closure &&
               !info->input_custody && !info->output_custody);
    }
    return info;
}

static void first_fragment_tests(bool io)
{
    CrucibleKvmInitialResponseInfo *info;
    unsigned steps;

    reset_initial(io);
    steps = kernel_steps;
    assert(!initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_POLL,
                            0, 7, 11, true));
    assert(!initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_SUBMIT,
                            0, 7, 12, true));
    model_clock_generation = 8;
    assert(!initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_SUBMIT,
                            0, 7, 11, true));
    model_clock_generation = 7;
    native.crucible_window_phase = CRUCIBLE_KVM_WINDOW_CLOSING;
    assert(!initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_SUBMIT,
                            0, 7, 11, true));
    native.crucible_window_phase = CRUCIBLE_KVM_WINDOW_CLOSED;
    model_stopped = false;
    assert(!initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_SUBMIT,
                            0, 7, 11, true));
    model_stopped = true;
    assert(slot_submissions == 0 && device_transactions == 0 && kernel_steps == steps);

    info = initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_SUBMIT,
                           0, 7, 11, false);
    assert(info->submitted && !info->completed && !info->result_known);
    assert(info->exit_sequence == 1 && info->service_id == 1);
    g_free(info);
    assert(original_service.initial_return && original_service.completion_id == 0);
    assert(native.crucible_response_service_active && model_slot.active);
    assert(!service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT,
                            1, 1, true));
    /* A lost Submit reply retains one actual slot, rather than a new callback. */
    g_free(initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_SUBMIT,
                           0, 7, 11, false));
    assert(slot_submissions == 1 && device_transactions == 0);
    info = initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_POLL,
                           0, 7, 11, false);
    assert(!info->completed && !info->result_known);
    g_free(info);

    execute_callback();
    assert(device_transactions == (io ? 3 : 1));
    assert(observed_attributes.secure && observed_attributes.user &&
           observed_attributes.requester_id == 123);
    assert(original_entry.phase == CRUCIBLE_KVM_USERSPACE_PENDING);
    assert(original_entry.reserved_revisions == 0 && kernel_steps == steps);
    info = initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_POLL,
                           0, 7, 11, false);
    assert(info->completed && info->result_known && info->callback_result == 0);
    g_free(info);
    assert(!native.crucible_response_service_active && !model_slot.active);
    /* A lost collected result never dispatches the original handler twice. */
    g_free(initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_POLL,
                           0, 7, 11, false));
    assert(slot_submissions == 1 && device_transactions == (io ? 3 : 1));
    assert(kernel_steps == steps);

    /* The existing actual kernel STEP consumes the prepared first response.
     * Genuine More uses the unchanged separate original completion namespace. */
    native_more = true;
    model_more_io = io;
    g_free(command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, false));
    assert(kernel_steps == steps + 1 &&
           original_entry.phase == CRUCIBLE_KVM_USERSPACE_HANDLING);
    /* The initial row remains recoverable after STEP changed the current
     * response sequence. Retried Submit cannot create a second native slot. */
    info = initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_POLL,
                           0, 7, 11, false);
    assert(info->result_known && info->callback_result == 0 &&
           info->exit_sequence == 1 && info->service_id == 1);
    g_free(info);
    g_free(initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_SUBMIT,
                           0, 7, 11, false));
    assert(slot_submissions == 1 && kernel_steps == steps + 1);

    g_free(service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT,
                           1, 2, false));
    assert(!original_service.initial_return && original_service.completion_id == 1);
    unsigned submissions = slot_submissions;
    unsigned effects = device_transactions;
    info = initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_POLL,
                           0, 7, 11, false);
    assert(info->result_known && info->service_id == 1 &&
           info->exit_sequence == 1 && info->callback_result == 0);
    g_free(info);
    assert(native.crucible_response_service_active && model_slot.active &&
           slot_submissions == submissions && device_transactions == effects);
    execute_callback();
    g_free(service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_POLL,
                           1, 2, false));
    native_more = false;
    g_free(command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 2, 2, false));
    assert(original_entry.phase == CRUCIBLE_KVM_USERSPACE_READY &&
           original_entry.consumed_sequence == original_entry.exit_sequence);
    /* Later native owner lineage and generations cannot replace the old row.
     * This models later original RUN birth, not another native guest entry. */
    initial_owner.last_invocation++;
    initial_owner.last_receipt.invocation++;
    initial_owner.current_reserved = true;
    native.crucible_window_generation++;
    model_clock_generation++;
    effects = device_transactions;
    info = initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_SUBMIT,
                           0, 7, 11, false);
    assert(info->result_known && info->service_id == 1 &&
           info->exit_sequence == 1 && info->callback_result == 0 &&
           !info->uncertain_effects && !info->opaque_effects);
    g_free(info);
    assert(slot_submissions == submissions && device_transactions == effects);
    assert(!initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_POLL,
                            0, 7, 12, true));
    assert(!initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_POLL,
                            0, 8, 11, true));
    initial_record.receipt.native_vcpu_id++;
    assert(!initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_POLL,
                            0, 7, 11, true));
}

static void first_fragment_refusals(void)
{
    reset_initial(false);
    initial_record.receipt.pending_mask |= KVM_CRUCIBLE_RUN_PENDING_OPAQUE;
    initial_owner.last_receipt = initial_record.receipt;
    assert(!initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_SUBMIT,
                            0, 7, 11, true));
    assert(slot_submissions == 0 && device_transactions == 0);

    reset_initial(false);
    fixture_cpu.kvm_run->mmio.data[0] ^= 1;
    assert(!initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_SUBMIT,
                            0, 7, 11, true));
    assert(slot_submissions == 0 && device_transactions == 0);

    reset_initial(false);
    g_free(initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_SUBMIT,
                           0, 7, 11, false));
    fail_transaction = true;
    execute_callback();
    assert(original_entry.uncertain_effects &&
           original_entry.phase == CRUCIBLE_KVM_USERSPACE_UNKNOWN);
    CrucibleKvmInitialResponseInfo *info = initial_command(
        CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_POLL, 0, 7, 11, false);
    assert(info->result_known && info->callback_result < 0 && info->uncertain_effects);
    g_free(info);
    assert(native.crucible_response_service_active && model_slot.active);
    assert(slot_submissions == 1 && device_transactions == 1);
}


static void refuse_unborn_or_changed_originals(void)
{
    for (unsigned defect = 0; defect < 14; defect++) {
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
        case 12:
            initial_record.native_result = -EIO;
            initial_record.receipt.run_result = -EIO;
            break;
        case 13:
            initial_record.receipt.pending_mask = KVM_CRUCIBLE_RUN_PENDING_CALLBACK;
            break;
        }
        /* Match the retained row copy so each predicate is tested independently
         * of the separately authenticated last-receipt equality guard. */
        initial_owner.last_receipt = initial_record.receipt;
        assert(!initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_SUBMIT,
                                0, 7, 11, true));
        assert(slot_submissions == 0 && device_transactions == 0);
    }

    reset_initial(false);
    initial_owner.original_cpu = NULL;
    assert(!initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_SUBMIT,
                            0, 7, 11, true));
    assert(slot_submissions == 0 && device_transactions == 0);
    reset_initial(false);
    original_service.attributes_known = false;
    assert(!initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_SUBMIT,
                            0, 7, 11, true));
    reset_initial(false);
    original_service.service_id = UINT64_MAX;
    assert(!initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_SUBMIT,
                            0, 7, 11, true));
    assert(slot_submissions == 0 && device_transactions == 0);
}

static void original_callback_revalidates_birth(void)
{
    reset_initial(false);
    g_free(initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_SUBMIT,
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
    g_free(initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_SUBMIT,
                           0, 7, 11, false));
    execute_callback();
    g_free(initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_POLL,
                           0, 7, 11, false));
    assert(device_transactions == 1 && !model_slot.active);

    reset_initial(true);
    native.crucible_clock_kernel_edition = 2;
    assert(!initial_command(CRUCIBLE_KVM_INITIAL_RESPONSE_OPERATION_SUBMIT,
                            0, 7, 11, true));
    assert(device_transactions == 0 && slot_submissions == 0);
}

int main(void)
{
    assert(legacy_response_tests() == 0);
    first_fragment_tests(false);
    first_fragment_tests(true);
    first_fragment_refusals();
    refuse_unborn_or_changed_originals();
    original_callback_revalidates_birth();
    initial_geometry_and_arm_receipt();
    return 0;
}
