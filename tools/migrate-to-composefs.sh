#!/usr/bin/env bash
# migrate-to-composefs.sh — Migração in-place de ostree para composefs no ArkheOS.
#
# Uso:
#   sudo ./migrate-to-composefs.sh --target-image ghcr.io/arkhe-os/arkhe:stable
#
# O script NUNCA executa `bootc-migrate commit`. O commit é decisão do operador
# após confirmar que o sistema arranca correctamente em composefs.

set -euo pipefail

TARGET_IMAGE=""
DRY_RUN=false
FORCE=false

usage() {
    cat <<EOFF
Uso: $0 --target-image <imagem> [--dry-run] [--force]

  --target-image   Imagem OCI de destino (obrigatório)
  --dry-run        Apenas verifica pré-condições, não migra
  --force          Ignora verificação de espaço em disco (perigoso)
EOFF
}

# --- Parse de argumentos ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target-image) TARGET_IMAGE="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --force) FORCE=true; shift ;;
        -h|--help) usage; return 1 2>/dev/null ;;
        *) echo "Argumento desconhecido: $1" >&2; usage; return 1 2>/dev/null ;;
    esac
done

if [[ -z "$TARGET_IMAGE" ]]; then
    echo "ERRO: --target-image é obrigatório" >&2
    usage
    return 1 2>/dev/null
fi

# --- Verificações de pré-condições ---

echo "==> Verificando bootc-migrate..."
if ! command -v bootc-migrate &>/dev/null; then
    echo "ERRO: bootc-migrate não encontrado. Instale a partir de https://github.com/tuna-os/bootc-migrate" >&2
    return 1 2>/dev/null
fi

echo "==> Verificando backend actual..."
CURRENT_BACKEND=$(bootc status --json 2>/dev/null | jq -r '.status.backend // "unknown"')
if [[ "$CURRENT_BACKEND" != "ostree" ]]; then
    echo "ERRO: backend actual é '$CURRENT_BACKEND', esperado 'ostree'" >&2
    echo "Este script apenas migra ostree → composefs." >&2
    return 1 2>/dev/null
fi

echo "==> Verificando espaço em disco..."
# /var será copiado; precisamos de espaço livre >= tamanho de /var
VAR_SIZE_KB=$(du -sk /var 2>/dev/null | awk '{print $1}')
FREE_KB=$(df -k /var | awk 'NR==2 {print $4}')
if [[ "$FREE_KB" -lt "$VAR_SIZE_KB" ]] && [[ "$FORCE" != "true" ]]; then
    echo "ERRO: espaço insuficiente em /var." >&2
    echo "  Necessário: $((VAR_SIZE_KB / 1024)) MiB" >&2
    echo "  Disponível: $((FREE_KB / 1024)) MiB" >&2
    echo "Use --force para ignorar (não recomendado)." >&2
    return 1 2>/dev/null
fi

echo "==> Confirmando backup..."
read -r -p "Fez backup de /home, /var e /etc? [s/N] " CONFIRM
if [[ "$CONFIRM" != "s" ]]; then
    echo "Migração abortada. Faça backup primeiro." >&2
    return 1 2>/dev/null
fi

# --- Dry-run ---

echo "==> Executando dry-run (nenhuma alteração será feita)..."
sudo bootc-migrate \
    --target-image "$TARGET_IMAGE" \
    --dry-run

if [[ "$DRY_RUN" == "true" ]]; then
    echo "Dry-run concluído. Nenhuma alteração feita."
    return 0 2>/dev/null
fi

# --- Migração ---

echo "==> Iniciando migração (~5–25 min)..."
sudo bootc-migrate \
    --target-image "$TARGET_IMAGE"

echo ""
echo "==> Migração concluída. O sistema NÃO foi reiniciado."
echo ""
echo "PRÓXIMOS PASSOS:"
echo "  1. Reinicie: sudo systemctl reboot"
echo "  2. No menu de boot, a entrada composefs é a default."
echo "     A entrada OSTree antiga permanece como fallback."
echo "  3. Após confirmar que o sistema arranca correctamente,"
echo "     torne a migração permanente (one-way):"
echo "       sudo bootc-migrate commit"
echo ""
echo "AVISO: Após \`commit\`, o fallback OSTree é removido."
echo "Não execute \`commit\` sem confirmar o boot."
