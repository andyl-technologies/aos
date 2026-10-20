package org.jetbrains.jet.lang.evaluate;

import org.jetbrains.jet.lang.psi.JetExpression;
import org.jetbrains.jet.lang.resolve.BindingTrace;
import org.jetbrains.jet.lang.resolve.constants.CompileTimeConstant;
import org.jetbrains.jet.lang.types.JetType;

// Build-only signature for the Java/Kotlin bootstrap cycle. The real Kotlin
// class overwrites this class before installation.
public final class ConstantExpressionEvaluator {
    public static final ConstantExpressionEvaluator object$ = null;

    public CompileTimeConstant<?> evaluate(JetExpression expression, BindingTrace trace, JetType expectedType) {
        throw new UnsupportedOperationException("build-only signature");
    }
}
