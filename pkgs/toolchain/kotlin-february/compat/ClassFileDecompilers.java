package com.intellij.psi.compiled;

import com.intellij.openapi.extensions.ExtensionPointName;
import com.intellij.openapi.vfs.VirtualFile;

// TODO: Build the complete 2014 IDEA decompiler API from source when the
// bootstrap IDEA package advances beyond its 2012 snapshot. The headless
// compiler uses this contract only to register the extension point.
public final class ClassFileDecompilers {
    public interface Decompiler {
        boolean accepts(VirtualFile file);
    }

    public static final ExtensionPointName<Decompiler> EP_NAME =
            ExtensionPointName.create("com.intellij.psi.classFileDecompiler");

    private ClassFileDecompilers() {
    }
}
