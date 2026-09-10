##! avahi-core — Multicast DNS libraries and daemon without desktop frontends
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  gettext,
  file,
  bash,
  expat,
  dbus,
  glib,
  libcap,
  libdaemon,
  libevent,
  gdbm,
}: let
  version = "0.8";
in
  mkDerivation {
    pname = "avahi-core";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/avahi/avahi/releases/download/v${version}/avahi-${version}.tar.gz"
      ];
      hash = "sha256-BgMJ16Mz042VG8J1mMZ3rxeWk029mOECTnrY3nmP7do=";
    };

    buildDeps = [gnumake pkg-config gettext file glib.tools];
    runtimeDeps = [bash expat dbus glib glib.dev libcap libdaemon libevent gdbm];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd avahi-${version}

          sed -i 's|/usr/bin/file|${file}/bin/file|g' configure
        '';
      }
      {
        name = "configure";
        script = ''
          # This deliberately narrow package owns Avahi's complete C service
          # and client surface: daemons, CLI utilities, event-loop adapters,
          # and DNS-SD/Howl compatibility APIs. Desktop UIs and language
          # bindings are outside the `avahi-core` contract.
          "$CONFIG_SHELL" ./configure \
            $configureFlags \
            --prefix="$out" \
            --sysconfdir=/etc \
            --localstatedir=/var \
            --runstatedir=/run \
            --with-distro=none \
            --with-xml=expat \
            --enable-compat-libdns_sd \
            --enable-compat-howl \
            --enable-shared \
            --enable-static \
            --enable-manpages \
            --disable-qt5 \
            --disable-gtk3 \
            --disable-python \
            --disable-pygobject \
            --disable-python-dbus \
            --disable-doxygen-doc \
            --disable-mono \
            --disable-monodoc
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          make install DESTDIR="$out"

          if [ -d "$out$out" ]; then
            cp -a "$out$out"/. "$out"/
            rm -rf "$out/nix"
          fi

          find "$out" -type f | while read file; do
            [ "$(head -c 2 "$file")" = '#!' ] || continue

            firstLine=$(head -n 1 "$file")
            case "$firstLine" in
              '#!/bin/sh'*|'#!/bin/bash'*|'#!/usr/bin/env sh'*|'#!/usr/bin/env bash'*)
                sed -i '1s|.*|#!${bash}/bin/bash|' "$file"
                ;;
            esac
          done

          ! find "$out" -type f -exec \
            grep -aEl '(^|[^[:alnum:]_./-])(/bin/(sh|bash)|/usr/bin/env[[:space:]]+(sh|bash))' {} + \
            | grep .

          test -f "$out/lib/libavahi-client.so"
          test -f "$out/lib/libavahi-core.so"
          test -f "$out/lib/libavahi-glib.so"
          test -f "$out/lib/libavahi-gobject.so"
          test -f "$out/lib/libavahi-libevent.so"
          test -f "$out/lib/libdns_sd.so"
          test -f "$out/lib/libhowl.so"
          test -x "$out/sbin/avahi-daemon"
          test -x "$out/sbin/avahi-autoipd"
          test -x "$out/sbin/avahi-dnsconfd"
          test -x "$out/bin/avahi-browse"
          test -x "$out/bin/avahi-publish"
          test -x "$out/bin/avahi-resolve"
          test -f "$out/lib/pkgconfig/avahi-client.pc"
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      client-link = testing.mkLinkCheck {
        pname = "lib-avahi-core-client";
        library = self;
        libs = ["-lavahi-client" "-lavahi-common"];
        testSource = ''
          #include <avahi-client/client.h>
          #include <avahi-common/error.h>

          int main(void) {
              return avahi_strerror(AVAHI_OK) == NULL;
          }
        '';
      };
    };

    meta = {
      description = "Core multicast DNS C libraries, daemons, utilities, and compatibility APIs";
      homepage = "https://avahi.org/";
      license = "LGPL-2.1-or-later";
    };
  }
