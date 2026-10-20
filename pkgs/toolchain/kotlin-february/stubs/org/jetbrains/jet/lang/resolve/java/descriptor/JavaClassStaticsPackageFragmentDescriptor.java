package org.jetbrains.jet.lang.resolve.java.descriptor;

// Build-only signature; the matching Kotlin interface replaces it.
public interface JavaClassStaticsPackageFragmentDescriptor extends JavaPackageFragmentDescriptor {
    JavaClassDescriptor getCorrespondingClass();
}
