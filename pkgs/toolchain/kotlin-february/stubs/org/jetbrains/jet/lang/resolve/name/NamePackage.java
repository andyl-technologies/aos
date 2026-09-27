package org.jetbrains.jet.lang.resolve.name;

// Build-only signature; the source-built Kotlin package class replaces it.
public final class NamePackage {
    public static FqName tail(FqName fqName, FqName head) {
        throw new UnsupportedOperationException("build-only signature");
    }

    public static boolean isOneSegmentFQN(FqName fqName) {
        throw new UnsupportedOperationException("build-only signature");
    }

    public static Name getFirstSegment(FqName fqName) {
        throw new UnsupportedOperationException("build-only signature");
    }

    public static FqName withoutFirstSegment(FqName fqName) {
        throw new UnsupportedOperationException("build-only signature");
    }

    public static boolean isSubpackageOf(FqName fqName, FqName packageName) {
        throw new UnsupportedOperationException("build-only signature");
    }

    public static int numberOfSegments(FqName fqName) {
        throw new UnsupportedOperationException("build-only signature");
    }
}
