static void free_inventory(CrucibleKvmOriginalReturnInventory *inventory)
{
    CrucibleKvmOriginalReturnIdentityList *entry = inventory->entries;

    while (entry) {
        CrucibleKvmOriginalReturnIdentityList *next = entry->next;

        free(entry->value);
        free(entry);
        entry = next;
    }
    free(inventory);
}

static void inventory_original_lineage(void)
{
    KVMState state;
    CPUState cpu;
    struct kvm_vcpu kernel;
    struct kvm vm;
    Error *error = NULL;
    CrucibleKvmWindowInfo *window;
    CrucibleKvmOriginalReturnInfo *returned;
    CrucibleKvmOriginalReturnInventory *inventory;

    initialize(&state, &cpu, &kernel, &vm);
    open_original(&state, 1, 0, 20);
    actual_return(&state, &cpu, -EINTR, false);
    assert(kvm_crucible_window_after_run(&state, &cpu, -EINTR));
    kvm_crucible_window_leave(&state, &cpu);
    returned = qmp_x_crucible_kvm_original_return(
        CRUCIBLE_KVM_ORIGINAL_RETURN_OPERATION_ACK, 0, 1, 1, &error);
    assert(returned && !error); free(returned);
    window = qmp_x_crucible_kvm_original_window(
        CRUCIBLE_KVM_WINDOW_OPERATION_CLOSE, 1, 0, 0, 1000, &error);
    assert(window && !error); free(window);

    open_original(&state, 2, 5, 20);
    assert(kvm_crucible_window_enter(&state, &cpu));
    assert(kvm_crucible_userspace_before_run(&state, &cpu));
    /* The actual source QUERY/ACK path authenticates a prior original receipt.
     * This modeled syscall is rejected before native arch RUN admission. */
    assert(kvm_crucible_window_after_run(&state, &cpu, -EAGAIN));
    kvm_crucible_window_leave(&state, &cpu);
    assert(state.crucible_window_returns[1].no_birth_known);
    window = qmp_x_crucible_kvm_original_window(
        CRUCIBLE_KVM_WINDOW_OPERATION_CLOSE, 2, 0, 0, 1000, &error);
    assert(window && !error); free(window);

    open_original(&state, 3, 5, 20);
    actual_return(&state, &cpu, -EINTR, false);
    assert(kvm_crucible_window_after_run(&state, &cpu, -EINTR));
    kvm_crucible_window_leave(&state, &cpu);

    unsigned queries = native_queries, acknowledgements = native_acks;
    unsigned mutations = clock_mutations;
    inventory = qmp_x_crucible_kvm_original_returns(3, 0, 2, &error);
    assert(inventory && !error && inventory->schema_version == 1);
    assert(inventory->generation == 3 && inventory->first_record == 0);
    assert(inventory->next_record == 2 && inventory->retained_returns == 3);
    assert(!inventory->profile_qualified);
    assert(inventory->entries && inventory->entries->next);
    assert(!inventory->entries->next->next);
    CrucibleKvmOriginalReturnIdentity *first = inventory->entries->value;
    CrucibleKvmOriginalReturnIdentity *second = inventory->entries->next->value;
    assert(first->record_index == 0 && first->generation == 1);
    assert(first->vcpu_index == 0 && first->native_vcpu_id == 37);
    assert(first->expected_invocation == 1 && first->receipt_known && first->ack_known);
    assert(second->record_index == 1 && second->generation == 2);
    assert(second->expected_invocation == 2 && second->no_birth_known);
    assert(!second->receipt_known && second->ack_known);
    free_inventory(inventory);

    inventory = qmp_x_crucible_kvm_original_returns(3, 2, 128, &error);
    assert(inventory && !error && inventory->next_record == 3);
    assert(inventory->entries && !inventory->entries->next);
    first = inventory->entries->value;
    assert(first->record_index == 2 && first->generation == 3);
    assert(first->expected_invocation == 2 && first->receipt_known && !first->ack_known);
    free_inventory(inventory);
    inventory = qmp_x_crucible_kvm_original_returns(3, 3, 1, &error);
    assert(inventory && !error && !inventory->entries && inventory->next_record == 3);
    free_inventory(inventory);

    assert(!qmp_x_crucible_kvm_original_returns(2, 0, 1, &error)); error = NULL;
    assert(!qmp_x_crucible_kvm_original_returns(3, 4, 1, &error)); error = NULL;
    assert(!qmp_x_crucible_kvm_original_returns(3, 0, 0, &error)); error = NULL;
    assert(!qmp_x_crucible_kvm_original_returns(3, 0, 129, &error)); error = NULL;
    model_work_active = true;
    assert(!qmp_x_crucible_kvm_original_returns(3, 0, 1, &error)); error = NULL;
    model_work_active = false;
    state.crucible_response_service_active = true;
    assert(!qmp_x_crucible_kvm_original_returns(3, 0, 1, &error)); error = NULL;
    state.crucible_response_service_active = false;
    assert(native_queries == queries && native_acks == acknowledgements);
    assert(clock_mutations == mutations && vm.crucible_uncollected_returns == 1);
    assert(state.crucible_window_return_count == 3);
    assert(state.crucible_window_returns[0].ack_known);
    assert(state.crucible_window_returns[1].no_birth_known);
    assert(!state.crucible_window_returns[2].ack_known);
    dispose(&state);
}

static void clean_interrupt_predicates(void)
{
    struct kvm_crucible_run_return receipt = {
        .version = 1, .operation = KVM_CRUCIBLE_RUN_RETURN_QUERY,
        .expected_invocation = 1, .invocation = 1,
        .generation_begin = 7, .generation_end = 7,
        .current_begin_ns = 10, .current_end_ns = 15,
        .run_result = -EINTR, .native_vcpu_id = 37,
        .flags = KVM_CRUCIBLE_RUN_RETURN_RETURNED | KVM_CRUCIBLE_RUN_RETURN_BEGIN_ACTIVE,
    };
    assert(run_receipt_clean_interrupt(&receipt, 7, 10, 20, 37, -EINTR));
    receipt.pending_mask = KVM_CRUCIBLE_RUN_PENDING_CALLBACK;
    assert(!run_receipt_clean_interrupt(&receipt, 7, 10, 20, 37, -EINTR));
    receipt.pending_mask = 0;
    receipt.response_flags = KVM_CRUCIBLE_COMPLETION_UNCERTAIN;
    assert(!run_receipt_clean_interrupt(&receipt, 7, 10, 20, 37, -EINTR));
    receipt.response_flags = 0;
    receipt.generation_end = 8;
    assert(!run_receipt_clean_interrupt(&receipt, 7, 10, 20, 37, -EINTR));
    receipt.generation_end = 7;
    receipt.current_end_ns = 21;
    assert(!run_receipt_clean_interrupt(&receipt, 7, 10, 20, 37, -EINTR));
    receipt.current_end_ns = 15;
    receipt.native_vcpu_id = 38;
    assert(!run_receipt_clean_interrupt(&receipt, 7, 10, 20, 37, -EINTR));
    receipt.native_vcpu_id = 37;
    receipt.flags &= ~KVM_CRUCIBLE_RUN_RETURN_RETURNED;
    assert(!run_receipt_clean_interrupt(&receipt, 7, 10, 20, 37, -EINTR));
    receipt.flags |= KVM_CRUCIBLE_RUN_RETURN_RETURNED;
    receipt.response_sequence = 1;
    assert(!run_receipt_clean_interrupt(&receipt, 7, 10, 20, 37, -EINTR));
    receipt.response_sequence = 0;
    receipt.run_result = -EFAULT;
    assert(!run_receipt_clean_interrupt(&receipt, 7, 10, 20, 37, -EFAULT));
}

static void admission_and_prior_lineage(void)
{
    KVMState state;
    CPUState cpu;
    struct kvm_vcpu kernel;
    struct kvm vm;
    Error *error = NULL;
    CrucibleKvmWindowInfo *window;
    CrucibleKvmOriginalReturnInfo *retained;

    initialize(&state, &cpu, &kernel, &vm);
    open_original(&state, 1, 0, 20);
    state.crucible_window_phase = CRUCIBLE_KVM_WINDOW_CLOSING;
    assert(!kvm_crucible_window_enter(&state, &cpu));
    assert(state.crucible_window_return_count == 0);
    dispose(&state);

    initialize(&state, &cpu, &kernel, &vm);
    open_original(&state, 1, 0, 20);
    assert(kvm_crucible_window_enter(&state, &cpu));
    state.crucible_window_phase = CRUCIBLE_KVM_WINDOW_CLOSING;
    assert(!kvm_crucible_userspace_before_run(&state, &cpu));
    assert(kernel.crucible_run_return.original.invocation == 0);
    kvm_crucible_window_leave(&state, &cpu);
    assert(state.crucible_window_phase == CRUCIBLE_KVM_WINDOW_UNKNOWN);
    assert(!state.crucible_window_returns[0].issued);
    dispose(&state);

    initialize(&state, &cpu, &kernel, &vm);
    state.crucible_window_return_count = QEMU_CRUCIBLE_WINDOW_MAX_RETURNS;
    unsigned mutations = clock_mutations;
    window = qmp_x_crucible_kvm_original_window(
        CRUCIBLE_KVM_WINDOW_OPERATION_BEGIN, 1, 0, 20, 0, &error);
    assert(!window && error); error = NULL;
    assert(clock_mutations == mutations && sealed_generation == 0);
    dispose(&state);

    initialize(&state, &cpu, &kernel, &vm);
    open_original(&state, 1, 0, 20);
    actual_return(&state, &cpu, -EINTR, false);
    assert(kvm_crucible_window_after_run(&state, &cpu, -EINTR));
    kvm_crucible_window_leave(&state, &cpu);
    state.crucible_window_vcpus[0].last_receipt.response_revision++;
    unsigned acknowledgements = native_acks;
    retained = qmp_x_crucible_kvm_original_return(
        CRUCIBLE_KVM_ORIGINAL_RETURN_OPERATION_ACK, 0, 1, 1, &error);
    assert(!retained && error); error = NULL;
    assert(native_acks == acknowledgements && vm.crucible_uncollected_returns == 1);
    state.crucible_window_vcpus[0].last_receipt.response_revision--;
    retained = qmp_x_crucible_kvm_original_return(
        CRUCIBLE_KVM_ORIGINAL_RETURN_OPERATION_ACK, 0, 1, 1, &error);
    assert(retained && !error); free(retained);
    window = qmp_x_crucible_kvm_original_window(
        CRUCIBLE_KVM_WINDOW_OPERATION_CLOSE, 1, 0, 0, 1000, &error);
    assert(window && !error); free(window);
    open_original(&state, 2, 5, 30);
    assert(kvm_crucible_window_enter(&state, &cpu));
    assert(kvm_crucible_userspace_before_run(&state, &cpu));
    vm.crucible_active = false;
    vm.arch.crucible_clock.active = false;
    state.crucible_window_vcpus[0].last_receipt.response_revision++;
    assert(kvm_crucible_run_return_admit(&kernel) == -EAGAIN);
    assert(!kvm_crucible_window_after_run(&state, &cpu, -EAGAIN));
    assert(!state.crucible_window_returns[1].no_birth_known);
    assert(state.crucible_window_phase == CRUCIBLE_KVM_WINDOW_UNKNOWN);
    kvm_crucible_window_leave(&state, &cpu);
    dispose(&state);
}

static void arm_clock_selection(void)
{
    KVMState state;
    CPUState cpu;
    struct kvm_vcpu kernel;
    struct kvm vm;
    Error *error = NULL;

    initialize(&state, &cpu, &kernel, &vm);
    state.crucible_clock_kernel_edition = 2;
    model_clock_components = 228;
    open_original(&state, 1, 0, 20);
    actual_return(&state, &cpu, -EINTR, false);
    assert(kvm_crucible_window_after_run(&state, &cpu, -EINTR));
    kvm_crucible_window_leave(&state, &cpu);
    CrucibleKvmWindowInfo *info = qmp_x_crucible_kvm_original_window(
        CRUCIBLE_KVM_WINDOW_OPERATION_CLOSE, 1, 0, 0, 1000, &error);
    assert(info && !error && info->clock_closed && !info->profile_qualified);
    free(info);
    dispose(&state);

    initialize(&state, &cpu, &kernel, &vm);
    state.crucible_clock_kernel_edition = 2;
    model_clock_components = 31;
    info = qmp_x_crucible_kvm_original_window(
        CRUCIBLE_KVM_WINDOW_OPERATION_BEGIN, 1, 0, 20, 0, &error);
    assert(!info && error && !sealed_generation);
    assert(state.crucible_window_generation == 0);
    dispose(&state);
}

static void deferred_original_mmio(void)
{
    KVMState state;
    CPUState cpu;
    struct kvm_vcpu kernel;
    struct kvm vm;
    Error *error = NULL;

    initialize(&state, &cpu, &kernel, &vm);
    open_original(&state, 1, 0, 20);
    assert(kvm_crucible_window_enter(&state, &cpu));
    assert(kvm_crucible_userspace_before_run(&state, &cpu));
    assert(kvm_crucible_run_return_admit(&kernel) == 0);
    assert(kvm_crucible_response_birth(&kernel.crucible_response));
    kernel.mmio_needed = true;
    kernel.arch.complete_userspace_io = &kernel;
    kernel.crucible_run_return.original.flags |= KVM_CRUCIBLE_RUN_RETURN_CLOCK_ENTERED;
    vm.arch.crucible_clock.sampled_ns = 5;
    cpu.kvm_run->exit_reason = KVM_EXIT_MMIO;
    kvm_crucible_run_return_finish(&kernel, 0);
    assert(kvm_crucible_window_after_run(&state, &cpu, 0));
    assert(state.crucible_userspace_exits[0].phase == CRUCIBLE_KVM_USERSPACE_HANDLING);
    assert(state.crucible_userspace_exits[0].reserved_revisions == 1);
    assert(state.crucible_window_returns[0].receipt.response_phase == KVM_CRUCIBLE_COMPLETION_PENDING);
    assert(kernel.mmio_needed && kernel.arch.complete_userspace_io);
    assert(state.crucible_userspace_exits[0].exit_sequence == 1);
    assert(state.crucible_userspace_exits[0].consumed_sequence == 0);
    kvm_crucible_window_leave(&state, &cpu);
    CrucibleKvmWindowInfo *info = qmp_x_crucible_kvm_original_window(
        CRUCIBLE_KVM_WINDOW_OPERATION_CLOSE, 1, 0, 0, 1000, &error);
    assert(info && !error && info->clock_closed && !info->device_custody_known);
    free(info);
    assert(kernel.mmio_needed && kernel.arch.complete_userspace_io);
    info = qmp_x_crucible_kvm_original_window(
        CRUCIBLE_KVM_WINDOW_OPERATION_BEGIN, 2, 5, 30, 0, &error);
    assert(!info && error);
    assert(kernel.crucible_run_return.original.invocation == 1);
    dispose(&state);
}

static void composite_original_cut(void)
{
    KVMState state;
    CPUState cpu;
    struct kvm_vcpu kernel;
    struct kvm vm;
    Error *error = NULL;
    CrucibleKvmWindowInfo *window;
    CrucibleKvmOriginalReturnInfo *retained;

    /* A returned inactive clock still cannot be labeled under the source
     * generation if the actual kernel names a different original window. */
    initialize(&state, &cpu, &kernel, &vm);
    vm.arch.crucible_clock.window_generation = 1;
    unsigned mutations = clock_mutations;
    window = qmp_x_crucible_kvm_original_window(
        CRUCIBLE_KVM_WINDOW_OPERATION_QUERY, 0, 0, 0, 0, &error);
    assert(!window && error);
    assert(state.crucible_window_phase == CRUCIBLE_KVM_WINDOW_UNKNOWN);
    assert(clock_mutations == mutations);
    dispose(&state);
    error = NULL;

    initialize(&state, &cpu, &kernel, &vm);
    open_original(&state, 1, 0, 20);
    vm.arch.crucible_clock.window_generation = 2;
    window = qmp_x_crucible_kvm_original_window(
        CRUCIBLE_KVM_WINDOW_OPERATION_CLOSE, 1, 0, 0, 1000, &error);
    assert(!window && error);
    assert(state.crucible_window_phase == CRUCIBLE_KVM_WINDOW_UNKNOWN);
    assert(!vm.arch.crucible_clock.active);
    dispose(&state);
    error = NULL;

    /* A stopped CPU flag alone cannot acknowledge or observe original return
     * custody while another original service obligation remains active. */
    initialize(&state, &cpu, &kernel, &vm);
    open_original(&state, 1, 0, 20);
    actual_return(&state, &cpu, -EINTR, false);
    assert(kvm_crucible_window_after_run(&state, &cpu, -EINTR));
    kvm_crucible_window_leave(&state, &cpu);
    CrucibleKvmOriginalReturn original = state.crucible_window_returns[0];
    unsigned acknowledgements = native_acks;
    model_work_active = true;
    retained = qmp_x_crucible_kvm_original_return(
        CRUCIBLE_KVM_ORIGINAL_RETURN_OPERATION_QUERY, 0, 1, 1, &error);
    assert(!retained && error);
    error = NULL;
    retained = qmp_x_crucible_kvm_original_return(
        CRUCIBLE_KVM_ORIGINAL_RETURN_OPERATION_ACK, 0, 1, 1, &error);
    assert(!retained && error);
    assert(native_acks == acknowledgements);
    assert(vm.crucible_uncollected_returns == 1);
    assert(!memcmp(&original, &state.crucible_window_returns[0], sizeof(original)));
    model_work_active = false;
    error = NULL;
    retained = qmp_x_crucible_kvm_original_return(
        CRUCIBLE_KVM_ORIGINAL_RETURN_OPERATION_ACK, 0, 1, 1, &error);
    assert(retained && !error && retained->ack_known);
    assert(native_acks == acknowledgements + 1);
    assert(vm.crucible_uncollected_returns == 0);
    free(retained);
    dispose(&state);
}
