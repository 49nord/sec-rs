#!/bin/sh

set -e

cargo fmt -- --check
cargo clippy --all-features
cargo clippy
cargo test --all-features
