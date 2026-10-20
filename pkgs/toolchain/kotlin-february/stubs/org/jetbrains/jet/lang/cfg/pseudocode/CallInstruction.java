package org.jetbrains.jet.lang.cfg.pseudocode;

import org.jetbrains.jet.lang.psi.JetElement;
import org.jetbrains.jet.lang.resolve.calls.model.ResolvedCall;

// Build-only signature; instructions.kt replaces this class before installation.
public final class CallInstruction extends InstructionWithNext {
    public CallInstruction(JetElement element, ResolvedCall<?> resolvedCall) {
        super(element);
    }

    public ResolvedCall<?> getResolvedCall() {
        throw new UnsupportedOperationException("build-only signature");
    }

    @Override
    public void accept(InstructionVisitor visitor) {
        throw new UnsupportedOperationException("build-only signature");
    }

    @Override
    public <R> R accept(InstructionVisitorWithResult<R> visitor) {
        throw new UnsupportedOperationException("build-only signature");
    }

    @Override
    protected Instruction createCopy() {
        throw new UnsupportedOperationException("build-only signature");
    }
}
