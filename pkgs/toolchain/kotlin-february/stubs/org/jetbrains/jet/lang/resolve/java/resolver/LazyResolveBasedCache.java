package org.jetbrains.jet.lang.resolve.java.resolver;

import org.jetbrains.jet.lang.resolve.lazy.ResolveSession;

// Build-only signature; the matching Kotlin class replaces it.
public class LazyResolveBasedCache extends TraceBasedJavaResolverCache {
    public void setSession(ResolveSession session) {
        throw new UnsupportedOperationException("build-only signature");
    }
}
