package org.jetbrains.jet.storage;

import com.intellij.openapi.util.ModificationTracker;

// Build-only signature; the matching Kotlin class replaces it.
public class ExceptionTracker implements ModificationTracker, LockBasedStorageManager.ExceptionHandlingStrategy {
    @Override
    public RuntimeException handleException(Throwable throwable) {
        throw new UnsupportedOperationException("build-only signature");
    }

    @Override
    public long getModificationCount() {
        throw new UnsupportedOperationException("build-only signature");
    }
}
