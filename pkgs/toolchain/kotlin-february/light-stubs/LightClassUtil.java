package org.jetbrains.jet.asJava;

import com.intellij.psi.PsiClass;
import com.intellij.psi.PsiMethod;
import com.intellij.psi.PsiTypeParameterList;
import com.intellij.psi.PsiTypeParameterListOwner;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.jet.lang.psi.JetClassOrObject;
import org.jetbrains.jet.lang.psi.JetDeclaration;
import org.jetbrains.jet.lang.psi.JetNamedFunction;
import org.jetbrains.jet.lang.psi.JetParameter;
import org.jetbrains.jet.lang.psi.JetProperty;
import org.jetbrains.jet.lang.psi.JetPropertyAccessor;

import java.util.Collections;
import java.util.Iterator;

// Build-only signature; the complete source-built CLI class replaces it.
public final class LightClassUtil {
    public static PsiClass getPsiClass(JetClassOrObject declaration) {
        throw new UnsupportedOperationException("build-only signature");
    }

    public static PsiMethod getLightClassMethod(JetNamedFunction declaration) {
        throw new UnsupportedOperationException("build-only signature");
    }

    public static PsiMethod getLightClassAccessorMethod(JetPropertyAccessor declaration) {
        throw new UnsupportedOperationException("build-only signature");
    }

    @NotNull
    public static PropertyAccessorsPsiMethods getLightClassPropertyMethods(JetProperty declaration) {
        throw new UnsupportedOperationException("build-only signature");
    }

    @NotNull
    public static PropertyAccessorsPsiMethods getLightClassPropertyMethods(JetParameter declaration) {
        throw new UnsupportedOperationException("build-only signature");
    }

    public static PsiTypeParameterList buildLightTypeParameterList(
            PsiTypeParameterListOwner owner, JetDeclaration declaration) {
        throw new UnsupportedOperationException("build-only signature");
    }

    public static final class PropertyAccessorsPsiMethods implements Iterable<PsiMethod> {
        public PsiMethod getGetter() {
            throw new UnsupportedOperationException("build-only signature");
        }

        public PsiMethod getSetter() {
            throw new UnsupportedOperationException("build-only signature");
        }

        @Override
        public Iterator<PsiMethod> iterator() {
            return Collections.<PsiMethod>emptyList().iterator();
        }
    }
}
