#!/bin/bash
# Deploy $VOTE contract to Dusk Testnet
#
# Prerequisites:
# 1. Install dusk-deploy-cli: cargo install dusk-deploy-cli
# 2. Have a Dusk wallet with testnet tDUSK tokens
# 3. Know your 12-word seed phrase
#
# Usage:
#   ./deploy.sh "your twelve word seed phrase here"
#
# Or with Moonlight account:
#   ./deploy.sh "your twelve word seed phrase here" "your_moonlight_secret_key_base58"

set -e

SEED="${1:-}"
MOONLIGHT_KEY="${2:-}"

if [ -z "$SEED" ]; then
    echo "Error: Please provide your 12-word seed phrase"
    echo "Usage: ./deploy.sh \"your twelve word seed phrase\""
    exit 1
fi

WASM_PATH="./target/wasm32-unknown-unknown/release/vote_contract.wasm"

if [ ! -f "$WASM_PATH" ]; then
    echo "Error: WASM file not found. Please run 'cargo build --release --target wasm32-unknown-unknown' first"
    exit 1
fi

echo "Deploying $VOTE contract to Dusk Testnet..."
echo "WASM file: $WASM_PATH"
echo "Config: ./deploy-config.toml"

# Build deploy command
CMD="dusk-deploy-cli --contract-path $WASM_PATH --seed \"$SEED\" --config-path ./deploy-config.toml --gas-limit 1000000000"

if [ -n "$MOONLIGHT_KEY" ]; then
    CMD="$CMD --moonlight \"$MOONLIGHT_KEY\""
fi

echo "Running: $CMD"
eval $CMD

echo "Deployment complete!"
echo "Save the contract ID for frontend integration."
