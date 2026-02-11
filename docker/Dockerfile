# =============================================================================
# docker/Dockerfile
# ANDYL OS -- Guix build environment via binary tarball installation
#
# This Dockerfile sets up a GNU Guix build environment by installing the
# official Guix binary tarball. This provides a working guix-daemon and CLI
# tool for building packages from our custom ANDYL channel.
#
# The hex0 full-source bootstrap chain (hex0 -> hex1 -> hex2 -> M0 -> M1 ->
# M2-Planet -> Mes -> MesCC -> TinyCC -> GCC -> glibc -> Guix) is documented
# in docs/brainstorm/01-guix-bootstrap.md as a theoretical/educational
# reference but is not implemented in this Dockerfile due to its multi-hour
# build time.
#
# Build the image:
#   docker build -f docker/Dockerfile -t andyl-os/guix-builder .
#
# =============================================================================

FROM debian:bookworm-slim@sha256:1537a6a1cbc4b4fd401da800ee9480207e7dc1f23560c21e0f4652e7b3c9ba8a AS guix-builder

# Pin the Guix binary tarball version
ARG GUIX_VERSION=1.4.0
ARG GUIX_ARCH=x86_64-linux

# Install runtime dependencies for guix-daemon.
# guix-daemon needs: bash and coreutils for build scripts, curl and git for
# channel operations, gnupg for signature verification, nscd for name
# resolution caching, and xz-utils for archive compression.
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        coreutils \
        curl \
        git \
        gnupg \
        less \
        locales \
        nscd \
        wget \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Generate en_US.UTF-8 locale (Guix requires a UTF-8 locale)
RUN sed -i 's/^# *\(en_US.UTF-8\)/\1/' /etc/locale.gen && locale-gen
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

# ---------------------------------------------------------------------------
# Install Guix from the official binary tarball
#
# The tarball contains a pre-built /gnu/store and /var/guix with a working
# guix-daemon and CLI. This is the standard installation method documented
# at https://guix.gnu.org/manual/en/html_node/Binary-Installation.html
# ---------------------------------------------------------------------------

# Download and extract the Guix binary tarball
RUN cd /tmp \
    && wget -q "https://ftp.gnu.org/gnu/guix/guix-binary-${GUIX_VERSION}.${GUIX_ARCH}.tar.xz" \
        -O guix-binary.tar.xz \
    && tar --warning=no-timestamp -xf guix-binary.tar.xz -C / \
    && rm guix-binary.tar.xz

# Create the guix profile symlink so `guix` is on PATH
RUN mkdir -p ~root/.config/guix \
    && ln -sf /var/guix/profiles/per-user/root/current-guix/bin/guix \
        /usr/local/bin/guix \
    && ln -sf /var/guix/profiles/per-user/root/current-guix/bin/guix-daemon \
        /usr/local/bin/guix-daemon

# Create the guixbuild group and 10 build users.
# guix-daemon runs each build as a separate unprivileged user for isolation.
# Users are named guixbuilder01 through guixbuilder10.
RUN groupadd --system guixbuild \
    && for i in $(seq -w 1 10); do \
        useradd \
            -g guixbuild \
            -G guixbuild \
            -d /var/empty \
            -s /usr/sbin/nologin \
            -c "Guix build user ${i}" \
            "guixbuilder${i}"; \
    done

# Ensure the store and var directories have correct permissions
RUN mkdir -p /gnu/store /var/guix/db \
    && chmod 1775 /gnu/store

# IMPORTANT: We do NOT authorize the upstream Guix substitute server key.
# We explicitly refuse all upstream substitutes. Only packages built through
# our own channel are trusted.
#
# We do NOT run:
#   guix archive --authorize < ci.guix.gnu.org.pub

# Configure guix-daemon to refuse all substitutes.
# --no-substitutes: never download pre-built binaries from any server
# --max-jobs=4: number of parallel build jobs
# --cores=0: use all available cores per build (0 = auto-detect)
ENV GUIX_DAEMON_OPTS="--no-substitutes --max-jobs=4 --cores=0"

# Copy and configure the entrypoint script
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["guix", "repl"]
