package org.jetbrains.jet.lang.evaluate;

import org.jetbrains.jet.lang.resolve.constants.CompileTimeConstant;
import org.jetbrains.jet.lang.resolve.constants.IntegerValueTypeConstant;
import org.jetbrains.jet.lang.descriptors.VariableDescriptor;
import org.jetbrains.jet.lang.psi.JetExpression;
import org.jetbrains.jet.lang.resolve.BindingTrace;
import org.jetbrains.jet.lang.types.JetType;

// Build-only signature; the source-built Kotlin package class replaces it.
public final class EvaluatePackage {
    public static CompileTimeConstant<?> createCompileTimeConstantWithType(
            IntegerValueTypeConstant value, JetType expectedType) {
        throw new UnsupportedOperationException("build-only signature");
    }

    public static void recordCompileTimeValueForInitializerIfNeeded(
            VariableDescriptor variableDescriptor,
            JetExpression initializer,
            JetType variableType,
            BindingTrace trace) {
        throw new UnsupportedOperationException("build-only signature");
    }
}
