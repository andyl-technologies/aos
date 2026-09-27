package org.jetbrains.jet.lang.psi.psiUtil;

import com.intellij.extapi.psi.StubBasedPsiElementBase;
import com.intellij.psi.PsiElement;
import org.jetbrains.jet.lang.psi.JetElement;
import org.jetbrains.jet.lang.psi.JetSimpleNameExpression;

import java.util.List;

// Build-only signature; the source-built Kotlin package class replaces it.
public final class PsiUtilPackage {
    public static List<String> getSuperNames(StubBasedPsiElementBase<?> element) {
        throw new UnsupportedOperationException("build-only signature");
    }

    public static JetElement getQualifiedElement(JetSimpleNameExpression expression) {
        throw new UnsupportedOperationException("build-only signature");
    }

    public static boolean isExtensionDeclaration(PsiElement element) {
        throw new UnsupportedOperationException("build-only signature");
    }
}
