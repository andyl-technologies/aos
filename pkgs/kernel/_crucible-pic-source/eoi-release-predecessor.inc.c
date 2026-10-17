/* SPDX-License-Identifier: GPL-2.0-only */
/* Original guest EOI effects are distinct from later PIT low/ACK completion.
 * An early EOI retains its native byte, RUN identity and receiver until the
 * original low callback finishes. This does not admit a dual-route board. */

static bool pic_pit_only_route(struct kvm_pic *pic)
{
	struct kvm_kernel_irq_routing_entry routes[KVM_NR_IRQCHIPS];
	struct kvm *kvm = pic->kvm;
	int count, srcu;

	if (!kvm->arch.vpit || kvm->arch.vpit->kvm != kvm ||
	    !atomic_read(&kvm->arch.vpit->pit_state.reinject))
		return false;
	srcu = srcu_read_lock(&kvm->irq_srcu);
	count = kvm_irq_map_gsi(kvm, routes, 0);
	srcu_read_unlock(&kvm->irq_srcu, srcu);
	return count == 1 && routes[0].type == KVM_IRQ_ROUTING_IRQCHIP &&
		routes[0].gsi == 0 && routes[0].irqchip.irqchip == KVM_IRQCHIP_PIC_MASTER &&
		routes[0].irqchip.pin == 0 && routes[0].set == kvm_pic_set_irq;
}

/* Caller owns PIC and either the original PIO lease/vCPU mutex or the exact
 * original LOW worker's source/timer leases. No ambient worker adopts an EOI. */
static bool pic_pit_eoi_complete_locked(struct kvm_pic *pic,
	const struct kvm_crucible_pit_irq_birth *low)
{
	struct kvm *kvm = pic->kvm;
	struct kvm_crucible_pic_pit_line *row = &pic->crucible_pit[0];
	unsigned long flags;
	bool valid;

	lockdep_assert_held(&pic->lock);
	if (row->phase != CRUCIBLE_PIC_PIT_EOI_PENDING || !row->eoi_native_known ||
	    !row->low_tail_known)
		return true;

	valid = kvm_crucible_pit_pic_ack(kvm, low);
	raw_spin_lock_irqsave(&kvm->crucible_gate_lock, flags);
	valid = valid && row->phase == CRUCIBLE_PIC_PIT_EOI_PENDING &&
		row->eoi_native_known && row->low_known && row->low_tail_known &&
		row->original.generation == kvm->arch.crucible_clock.window_generation &&
		row->geometry == pic_pit_geometry(&pic->pics[0]) &&
		!pic->pics[0].irr && !pic->pics[0].isr && !pic->irq_states[0] &&
		!kvm->crucible_irq_input.tainted && !kvm->crucible_memory_tainted &&
		!kvm->arch.crucible_clock.continuation.uncertain &&
		kvm_crucible_clock_admission_live(kvm->arch.crucible_clock.active,
			kvm->crucible_host_ceiling_ns, ktime_get_ns());
	row->phase = valid ? CRUCIBLE_PIC_PIT_ACKED : CRUCIBLE_PIC_PIT_UNKNOWN;
	if (!valid)
		kvm_arch_crucible_irq_taint_locked(kvm);
	raw_spin_unlock_irqrestore(&kvm->crucible_gate_lock, flags);
	return valid;
}

static int pic_pit_original_eoi(struct kvm_vcpu *vcpu, struct kvm_pic *pic,
	unsigned char data)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_crucible_pic_pit_line *row;
	struct kvm_crucible_pit_journal *journal;
	struct crucible_irq_device_lease lease;
	unsigned long flags;
	u64 sequence;
	bool valid, route, completed;

	lockdep_assert_held(&vcpu->mutex);
	route = pic_pit_only_route(pic);
	pic_lock(pic);
	row = &pic->crucible_pit[0];
	valid = route && pic == kvm->arch.vpic && pic->kvm == kvm &&
		(data == 0x20 || data == 0x60) &&
		row->phase == CRUCIBLE_PIC_PIT_CONSUMED && row->high_known &&
		row->target_id == vcpu->vcpu_id && row->consume_invocation &&
		row->original.sequence && row->original.invocation &&
		row->geometry == pic_pit_geometry(&pic->pics[0]) &&
		row->vector == pic->pics[0].irq_base &&
		!pic->pics[0].auto_eoi && !pic->pics[0].rotate_on_auto_eoi &&
		!pic->pics[0].poll && !pic->pics[0].init_state &&
		!(pic->pics[0].elcr & 1) && !pic->pics[0].irr && pic->pics[0].isr == 1 &&
		!pic->pics[1].irr && !pic->pics[1].isr &&
		(row->low_known ? (!pic->irq_states[0] && !pic->pics[0].last_irr) :
			(pic->irq_states[0] == BIT(KVM_PIT_IRQ_SOURCE_ID) &&
			 pic->pics[0].last_irr == 1));
	if (!crucible_irq_device_begin(kvm, vcpu, valid, &lease)) {
		spin_unlock(&pic->lock);
		kvm_vm_dead(kvm);
		return -EAGAIN;
	}

	raw_spin_lock_irqsave(&kvm->crucible_gate_lock, flags);
	journal = &kvm->arch.vpit->pit_state.crucible;
	valid = row->original.generation == lease.generation &&
		crucible_irq_device_run_locked(kvm, vcpu) &&
		journal->awaiting_ack &&
		journal->ack_generation == row->original.generation &&
		journal->ack_sequence == row->original.sequence &&
		journal->ack_invocation == row->original.invocation &&
		pic->crucible_eoi_issued < CRUCIBLE_PIC_PIT_ISSUED;
	if (valid) {
		sequence = ++pic->crucible_eoi_issued;
		row->phase = CRUCIBLE_PIC_PIT_EOI_PENDING;
		row->eoi_sequence = sequence;
		row->ack_invocation = lease.invocation;
		row->eoi_byte = data;
		row->eoi_host_ns = ktime_get_ns();
		row->eoi_native_known = false;
	} else {
		sequence = 0;
		row->phase = CRUCIBLE_PIC_PIT_UNKNOWN;
		kvm_arch_crucible_irq_taint_locked(kvm);
	}
	raw_spin_unlock_irqrestore(&kvm->crucible_gate_lock, flags);
	if (valid) {
		/* Real EOI register effect; the generic scalar ACK notifier is bypassed.
		 * The ordinary native PIC wake tail still runs exactly once. */
		pic->pics[0].isr &= ~1;
		pic_update_irq(pic);
		pic_unlock(pic);
		pic_lock(pic);
	}

	raw_spin_lock_irqsave(&kvm->crucible_gate_lock, flags);
	valid = valid && row->phase == CRUCIBLE_PIC_PIT_EOI_PENDING &&
		row->eoi_sequence == sequence && row->eoi_byte == data &&
		row->ack_invocation == lease.invocation &&
		row->geometry == pic_pit_geometry(&pic->pics[0]) &&
		!pic->pics[0].irr && !pic->pics[0].isr &&
		crucible_irq_device_run_locked(kvm, vcpu) &&
		lease.generation == kvm->arch.crucible_clock.window_generation;
	if (valid)
		row->eoi_native_known = true;
	else {
		row->phase = CRUCIBLE_PIC_PIT_UNKNOWN;
		kvm_arch_crucible_irq_taint_locked(kvm);
	}
	raw_spin_unlock_irqrestore(&kvm->crucible_gate_lock, flags);

	completed = valid && pic_pit_eoi_complete_locked(pic, NULL);
	spin_unlock(&pic->lock);
	if (crucible_irq_device_finish(kvm, vcpu, &lease)) {
		pic_lock(pic);
		raw_spin_lock_irqsave(&kvm->crucible_gate_lock, flags);
		row->phase = CRUCIBLE_PIC_PIT_UNKNOWN;
		kvm_arch_crucible_irq_taint_locked(kvm);
		raw_spin_unlock_irqrestore(&kvm->crucible_gate_lock, flags);
		spin_unlock(&pic->lock);
		return -EAGAIN;
	}
	if (!completed) {
		kvm_vm_dead(kvm);
		return -EAGAIN;
	}
	/* This is the known EOI register/wake result. If LOW has not returned,
	 * the original ACK obligation remains EOI_PENDING; no new EOI is adopted. */
	return 0;
}
