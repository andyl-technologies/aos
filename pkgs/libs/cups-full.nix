##! cups-full — Common UNIX Printing System libraries and services
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  bash,
  acl,
  avahi-core,
  dbus,
  gnutls,
  libusb1,
  linux-pam,
  zlib,
}: let
  version = "2.4.12";
in
  mkDerivation {
    pname = "cups-full";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/OpenPrinting/cups/releases/download/v${version}/cups-${version}-source.tar.gz"
      ];
      hash = "sha256-sd3hkaSuJ2DEciDILKYVWijDgnAebBoBWdEFSZAjHVk=";
    };

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [
      acl
      avahi-core
      bash
      dbus
      gnutls
      libusb1
      linux-pam
      zlib
    ];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          cd cups-${version}

          # AOS exposes optional mail transports through the composed system
          # profile. Keep the notifier feature while avoiding an undeclared
          # FHS sendmail path.
          sed -i \
            's|/usr/sbin/sendmail|/run/current-system/sw/bin/sendmail|g' \
            notifier/mailto.c scheduler/process.c
        '';
      }
      {
        name = "configure";
        script = ''
          "$CONFIG_SHELL" ./configure \
            $configureFlags \
            --prefix="$out" \
            --sysconfdir=/etc \
            --localstatedir=/var \
            --runstatedir=/run \
            --with-components=all \
            --with-tls=gnutls \
            --with-dnssd=avahi \
            --enable-libusb \
            --enable-acl \
            --enable-shared \
            --disable-static
        '';
      }
      {
        name = "build";
        script = ''make -j"$NIX_BUILD_CORES"'';
      }
      {
        name = "install";
        script = ''
          make install BUILDROOT="$out"

          # BUILDROOT redirects runtime /etc and /var paths and also prefixes
          # the Nix store program path. Flatten that latter prefix only.
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
            grep -aEl '(^|[^[:alnum:]_./-])(/bin/(sh|bash)|/usr/sbin/sendmail)' {} + \
            | grep .
        '';
      }
    ];

    checks = {
      testing,
      self,
      ...
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-cups";
        library = self;
        libs = ["-lcups"];
        testSource = ''
          #include <cups/cups.h>

          int main(void) {
              return cupsGetDefault() == NULL ? 0 : 0;
          }
        '';
      };
    };

    meta = {
      description = "Common UNIX Printing System libraries and services";
      homepage = "https://openprinting.github.io/cups/";
      license = "Apache-2.0";
    };
  }
