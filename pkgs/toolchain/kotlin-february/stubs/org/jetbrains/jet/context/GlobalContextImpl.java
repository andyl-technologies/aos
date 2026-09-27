package org.jetbrains.jet.context;

import org.jetbrains.jet.storage.ExceptionTracker;
import org.jetbrains.jet.storage.LockBasedStorageManager;

// Build-only signature; the matching Kotlin class replaces it.
public class GlobalContextImpl implements GlobalContext {
    public GlobalContextImpl(LockBasedStorageManager storageManager, ExceptionTracker exceptionTracker) {
        throw new UnsupportedOperationException("build-only signature");
    }

    @Override
    public LockBasedStorageManager getStorageManager() {
        throw new UnsupportedOperationException("build-only signature");
    }

    @Override
    public ExceptionTracker getExceptionTracker() {
        throw new UnsupportedOperationException("build-only signature");
    }
}
