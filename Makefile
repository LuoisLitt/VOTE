COMPILER_VERSION=v0.2.0

all: contracts

help: ## Display this help
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup-compiler: ## Setup the dusk compiler
	@./scripts/setup-compiler.sh $(COMPILER_VERSION)

contracts: setup-compiler vote-contract mock-token ## Build all contracts

vote-contract: setup-compiler ## Build the vote contract
	@RUSTFLAGS="-C link-args=-zstack-size=65536" \
	cargo +dusk build \
	  --release \
	  --manifest-path=contract/Cargo.toml \
	  --color=always \
	  -Z build-std=core,alloc \
	  --target wasm64-unknown-unknown

mock-token: setup-compiler ## Build the mock token contract
	@RUSTFLAGS="-C link-args=-zstack-size=65536" \
	cargo +dusk build \
	  --release \
	  --manifest-path=tests/mock-token/Cargo.toml \
	  --color=always \
	  -Z build-std=core,alloc \
	  --target wasm64-unknown-unknown

test: contracts ## Run the tests
	cargo test --manifest-path=tests/Cargo.toml

clean: ## Clean build artifacts
	cargo clean

.PHONY: all help setup-compiler contracts vote-contract mock-token test clean
