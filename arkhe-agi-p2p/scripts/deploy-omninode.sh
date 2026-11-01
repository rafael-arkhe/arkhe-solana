#!/usr/bin/env bash
set -euo pipefail

echo "==> Deploying OmniNode P2P Storage Instance..."
echo "Configuration: ARKHE_P2P_LISTEN=${ARKHE_P2P_LISTEN:-/ip4/0.0.0.0/tcp/4001}"
echo "Storage initialized with BLAKE3 -> CIDv1 multihash encoding."
