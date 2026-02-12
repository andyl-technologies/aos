# Unpack and patch the bootstrap tools tarball.
# Adapted from nixpkgs pkgs/stdenv/linux/bootstrap-tools/glibc/unpack-bootstrap-tools.sh
#
# Uses busybox ($builder) as the only external dependency.
# After unpacking, uses patchelf (from inside the tarball) to fix
# interpreter and RPATH in all ELF binaries to point at $out/lib.

echo "Unpacking bootstrap tools..."
$builder mkdir $out
< $tarball $builder unxz | $builder tar x -C $out

echo "Patching bootstrap tools..."

# Find the dynamic linker for this architecture.
if test -f $out/lib/ld.so.?; then
   # MIPS
   LD_BINARY=$out/lib/ld.so.?
elif test -f $out/lib/ld64.so.?; then
   # ppc64(le)
   LD_BINARY=$out/lib/ld64.so.?
else
   # x86_64, i686, aarch64, armv5tel
   LD_BINARY=$out/lib/ld-*so.?
fi

# Path to version-specific libraries (libstdc++, etc.)
LIBSTDCXX_SO_DIR=$(echo $out/lib/gcc/*/*)

# Move version-specific libraries to avoid mixing when upgrading gcc.
LD_LIBRARY_PATH=$out/lib $LD_BINARY $out/bin/mv $out/lib/libstdc++.* $LIBSTDCXX_SO_DIR/

# Make a working copy of patchelf (can't patchelf the same binary you're running).
LD_LIBRARY_PATH=$out/lib $LD_BINARY $out/bin/cp $out/bin/patchelf .

# Same for libgcc_s — patchelf might link against it.
LD_LIBRARY_PATH=$out/lib $LD_BINARY $out/bin/cp $out/lib/libgcc_s.so.1 .
LD_LIBRARY_PATH=.:$out/lib:$LIBSTDCXX_SO_DIR $LD_BINARY \
  ./patchelf --set-rpath $out/lib --force-rpath $out/lib/libgcc_s.so.1

# Patch all ELF executables.
for i in $out/bin/* $out/libexec/gcc/*/*/*; do
    if [ -L "$i" ]; then continue; fi
    if [ -z "${i##*/liblto*}" ]; then continue; fi
    echo "patching $i"
    LD_LIBRARY_PATH=$out/lib:$LIBSTDCXX_SO_DIR $LD_BINARY \
        ./patchelf --set-interpreter $LD_BINARY --set-rpath $out/lib:$LIBSTDCXX_SO_DIR --force-rpath "$i"
done

# Patch shared libraries that need RPATH fixes.
for i in $out/lib/librt-*.so $out/lib/libpcre*; do
    if [ -L "$i" ]; then continue; fi
    echo "patching $i"
    $out/bin/patchelf --set-rpath $out/lib --force-rpath "$i"
done

export PATH=$out/bin

# Provide sh symlink (needed by many build scripts).
ln -s bash $out/bin/sh
ln -s bzip2 $out/bin/bunzip2

# Provide gunzip script.
cat > $out/bin/gunzip <<EOF
#!$out/bin/sh
exec $out/bin/gzip -d "\$@"
EOF
chmod +x $out/bin/gunzip

# Provide egrep/fgrep scripts.
echo "#! $out/bin/sh" > $out/bin/egrep
echo "exec $out/bin/grep -E \"\$@\"" >> $out/bin/egrep
echo "#! $out/bin/sh" > $out/bin/fgrep
echo "exec $out/bin/grep -F \"\$@\"" >> $out/bin/fgrep

# Provide xz wrapper (uses busybox unxz).
echo "#! $out/bin/sh" > $out/bin/xz
echo "exec $builder unxz \"\$@\"" >> $out/bin/xz

chmod +x $out/bin/egrep $out/bin/fgrep $out/bin/xz

echo "Bootstrap tools ready in $out"
