package org.jetbrains.jet.lang.resolve.java.lazy;

import java.util.Collection;
import java.util.List;
import org.jetbrains.jet.lang.descriptors.ClassDescriptor;
import org.jetbrains.jet.lang.descriptors.ModuleDescriptor;
import org.jetbrains.jet.lang.descriptors.PackageFragmentDescriptor;
import org.jetbrains.jet.lang.resolve.java.descriptor.JavaPackageFragmentDescriptor;
import org.jetbrains.jet.lang.resolve.java.resolver.JavaPackageFragmentProvider;
import org.jetbrains.jet.lang.resolve.name.FqName;
import org.jetbrains.jet.lang.resolve.name.Name;

// Build-only signature; the matching Kotlin class replaces it.
public class LazyJavaPackageFragmentProvider implements JavaPackageFragmentProvider {
    public LazyJavaPackageFragmentProvider(GlobalJavaResolverContext context, ModuleDescriptor module) {
        throw new UnsupportedOperationException("build-only signature");
    }

    @Override
    public JavaPackageFragmentDescriptor getPackageFragment(FqName fqName) {
        throw new UnsupportedOperationException("build-only signature");
    }

    @Override
    public List<PackageFragmentDescriptor> getPackageFragments(FqName fqName) {
        throw new UnsupportedOperationException("build-only signature");
    }

    @Override
    public Collection<FqName> getSubPackagesOf(FqName fqName) {
        throw new UnsupportedOperationException("build-only signature");
    }

    @Override
    public Collection<Name> getClassNamesInPackage(FqName packageName) {
        throw new UnsupportedOperationException("build-only signature");
    }

    @Override
    public ModuleDescriptor getModule() {
        throw new UnsupportedOperationException("build-only signature");
    }

    public ClassDescriptor getClass(FqName fqName) {
        throw new UnsupportedOperationException("build-only signature");
    }
}
