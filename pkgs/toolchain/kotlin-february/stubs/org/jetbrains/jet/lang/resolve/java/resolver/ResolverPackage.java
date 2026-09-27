package org.jetbrains.jet.lang.resolve.java.resolver;

import org.jetbrains.jet.lang.resolve.constants.CompileTimeConstant;
import org.jetbrains.jet.lang.types.JetType;

// Build-only signature; the source-built Kotlin package class replaces it.
public final class ResolverPackage {
    public static CompileTimeConstant<?> resolveCompileTimeConstantValue(
            Object value, boolean canBeUsedInAnnotations, JetType expectedType) {
        throw new UnsupportedOperationException("build-only signature");
    }
}
