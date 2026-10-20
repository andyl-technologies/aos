package org.jetbrains.jet.lang.evaluate;

import org.jetbrains.jet.lang.resolve.constants.CompileTimeConstant;
import org.jetbrains.jet.lang.resolve.constants.IntegerValueTypeConstructor;
import org.jetbrains.jet.lang.types.JetType;

// Build-only signature; the source-built Kotlin package class replaces it.
public final class EvaluatePackage {
    public static CompileTimeConstant<?> getCompileTimeConstantForNumberType(
            IntegerValueTypeConstructor value, JetType expectedType) {
        throw new UnsupportedOperationException("build-only signature");
    }

    public static Object getValueForNumberType(IntegerValueTypeConstructor value, JetType expectedType) {
        throw new UnsupportedOperationException("build-only signature");
    }
}
