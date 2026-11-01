# syntax=docker/dockerfile:1.7

# =============================================================================
# ARKHEOS — Containerfile bootc + composefs + sealed UKI
# Base: Debian Trixie (snapshot pinado)
# =============================================================================

ARG DEBIAN_SNAPSHOT=20261031T000000Z
ARG SOURCE_DATE_EPOCH=1787836800

# -----------------------------------------------------------------------------
# Stage 1: rootfs base (Debian snapshot pinado)
# -----------------------------------------------------------------------------
FROM debian:trixie AS rootfs

ARG DEBIAN_SNAPSHOT
ARG SOURCE_DATE_EPOCH

# Reprodutibilidade: pin do snapshot + epoch
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
ENV DEB_BUILD_OPTIONS=reproducible=+fixfilepath
ENV TZ=UTC
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

# Snapshot imutável (nunca deb.debian.org)
RUN echo "deb [snapshot=${DEBIAN_SNAPSHOT}] http://snapshot.debian.org/debian trixie main" \
    > /etc/apt/sources.list && \
    echo "deb [snapshot=${DEBIAN_SNAPSHOT}] http://snapshot.debian.org/debian trixie-updates main" \
    >> /etc/apt/sources.list && \
    echo "deb [snapshot=${DEBIAN_SNAPSHOT}] http://snapshot.debian.org/debian-security trixie-security main" \
    >> /etc/apt/sources.list

RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd systemd-boot systemd-resolved \
        linux-image-amd64 \
        systemd-boot-efi \
        dracut \
        composefs \
        erofs-utils \
        fsverity-utils \
        ca-certificates \
        curl \
        jq \
        openssl \
        tpm2-tools \
        systemd-cryptenroll \
        bootc \
    && rm -rf /var/lib/apt/lists/*

# Configuração de composefs (backend nativo)
RUN mkdir -p /usr/lib/ostree && \
    cat > /usr/lib/ostree/prepare-root.conf <<'INNER_EOF'
[composefs]
enabled = true
INNER_EOF

# Configuração de fs-verity (obrigatório por omissão)
RUN cat > /etc/composefs.conf <<'INNER_EOF'
[composefs]
verity = require
INNER_EOF

# systemd-pcrlock (política TPM)
RUN mkdir -p /etc/systemd && \
    cat > /etc/systemd/pcrlock.json <<'INNER_EOF'
{
  "pcr_banks": ["sha256"],
  "pcrs": [0, 4, 7, 11]
}
INNER_EOF

# UKI: kernel + initramfs + cmdline (o digest composefs é injectado no build)
RUN mkdir -p /usr/lib/modules/$(ls /usr/lib/modules | head -1)/ && \
    dracut --force --no-hostonly \
      --add "composefs systemd" \
      --omit "nfs cifs iscsi" \
      /usr/lib/modules/$(ls /usr/lib/modules | head -1)/initramfs.img

# Limpeza de artefactos não reprodutíveis
RUN find / -xdev -name '*.pyc' -delete 2>/dev/null || true && \
    find / -xdev -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true

# -----------------------------------------------------------------------------
# Stage 2: UKI selada (sealed image)
# -----------------------------------------------------------------------------
FROM rootfs AS uki-builder

ARG SOURCE_DATE_EPOCH

# Copia a árvore para /target (rootfs completo)
COPY --from=rootfs / /target

# Gera a UKI com o digest composefs pinado na cmdline.
# O bootc container ukify calcula o digest do composefs e gera a UKI.
# A assinatura Secure Boot é feita fora do container (CI com chave).
RUN bootc container ukify \
        --rootfs /target \
        --karg "rw" \
        --karg "console=ttyS0" \
        --karg "systemd.show_status=1" \
        -- \
        --output /target/EFI/Linux/arkhe-$(uname -r).efi \
        --json pretty

# Lint fail-closed
RUN bootc container lint --fatal-warnings

# -----------------------------------------------------------------------------
# Stage 3: imagem final bootc
# -----------------------------------------------------------------------------
FROM rootfs

ARG SOURCE_DATE_EPOCH

# Copia a UKI selada
COPY --from=uki-builder /target/EFI/Linux/*.efi /usr/lib/modules/$(ls /usr/lib/modules | head -1)/uki.efi

# Configuração de bootc (composefs backend)
RUN mkdir -p /usr/lib/bootc && \
    cat > /usr/lib/bootc/install.conf <<'INNER_EOF'
[install]
composefs = true
bootloader = systemd
INNER_EOF

# Configuração de boot (UKI)
RUN mkdir -p /etc/kernel && \
    cat > /etc/kernel/install.conf <<'INNER_EOF'
layout=uki
initrd_generator=dracut
uki_generator=ukify
INNER_EOF

# Label OCI
LABEL org.opencontainers.image.title="arkheos" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.source="https://github.com/arkhe-os/arkhe" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.revision="${SOURCE_DATE_EPOCH}" \
      org.opencontainers.image.created="${SOURCE_DATE_EPOCH}"

# Entrada (bootc não usa CMD, mas é boa prática)
CMD ["/sbin/init"]
