package org.jetbrains.jet.lang.resolve.java.lazy;

import org.jetbrains.jet.lang.resolve.java.JavaClassFinder;
import org.jetbrains.jet.lang.resolve.java.resolver.ErrorReporter;
import org.jetbrains.jet.lang.resolve.java.resolver.ExternalAnnotationResolver;
import org.jetbrains.jet.lang.resolve.java.resolver.ExternalSignatureResolver;
import org.jetbrains.jet.lang.resolve.java.resolver.JavaResolverCache;
import org.jetbrains.jet.lang.resolve.java.resolver.MethodSignatureChecker;
import org.jetbrains.jet.lang.resolve.kotlin.DeserializedDescriptorResolver;
import org.jetbrains.jet.lang.resolve.kotlin.KotlinClassFinder;
import org.jetbrains.jet.storage.StorageManager;

// Build-only signature; the matching Kotlin class replaces it.
public class GlobalJavaResolverContext {
    public GlobalJavaResolverContext(
            StorageManager storageManager,
            JavaClassFinder finder,
            KotlinClassFinder kotlinClassFinder,
            DeserializedDescriptorResolver deserializedDescriptorResolver,
            ExternalAnnotationResolver externalAnnotationResolver,
            ExternalSignatureResolver externalSignatureResolver,
            ErrorReporter errorReporter,
            MethodSignatureChecker methodSignatureChecker,
            JavaResolverCache javaResolverCache) {
        throw new UnsupportedOperationException("build-only signature");
    }
}
