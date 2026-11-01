.PHONY: all build test clean wasm lint

all: build test

build:
	cargo build --workspace

test:
	cargo test --workspace

wasm:
	./scripts/build-wasm.sh

lint:
	cargo clippy --workspace -- -D warnings
	cargo fmt --all -- --check

clean:
	cargo clean
