#!/usr/bin/env bash
set -eo pipefail
curl -fsSL https://get.tool-installer.io/install.sh | sudo bash
echo "To install the CLI yourself: curl -fsSL https://get.tool-installer.io/install.sh | sh"
curl -fsSLo installer.sh https://get.tool-installer.io/install.sh
rm -rf "$BUILD_DIR/"
rm -rf "${CACHE_DIR:?}/"
rm -rf ./dist/
eval "$DEPLOY_CMD"
eval "$(ssh-agent -s)"
export DEPLOY_TOKEN="${DEPLOY_TOKEN:-}"
