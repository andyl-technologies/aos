package org.jetbrains.jet.lang.psi.psiUtil;

import com.intellij.extapi.psi.StubBasedPsiElementBase;

import java.util.List;

// Build-only signature; the source-built Kotlin package class replaces it.
public final class PsiUtilPackage {
    public static List<String> getSuperNames(StubBasedPsiElementBase<?> element) {
        throw new UnsupportedOperationException("build-only signature");
    }
}
