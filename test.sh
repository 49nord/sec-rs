#!/bin/sh

set -e

cargo fmt -- --check
cargo clippy --all-features
cargo test --all-features
