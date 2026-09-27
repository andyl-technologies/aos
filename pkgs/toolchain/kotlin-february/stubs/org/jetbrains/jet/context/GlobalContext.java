package org.jetbrains.jet.context;

import org.jetbrains.jet.storage.ExceptionTracker;
import org.jetbrains.jet.storage.StorageManager;

// Build-only signature; the matching Kotlin interface replaces it.
public interface GlobalContext {
    StorageManager getStorageManager();
    ExceptionTracker getExceptionTracker();
}
