package org.jetbrains.jet.lang.cfg.pseudocode;

import org.jetbrains.jet.lang.psi.JetElement;

// Build-only signature; instructions.kt replaces this class before installation.
public final class CompilationErrorInstruction extends InstructionWithNext {
    public CompilationErrorInstruction(JetElement element, String message) {
        super(element);
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
