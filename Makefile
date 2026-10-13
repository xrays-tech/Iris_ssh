# ssh-gateway - build / test / CI entrypoints.
#
#   make help           show this help
#   make build          cargo build  (produces target/debug/ssh-gw)
#   make lint           cargo fmt --check + cargo clippy -D warnings
#   make test           unit tests (cargo test)
#   make integration    black-box integration suite (scripts/run_integration.sh)
#   make selftest       infra-only health check (backend sshd + control plane)
#   make soak           A5 long-run stability soak (scripts/run_soak.sh; SOAK_DURATION)
#   make ha-drain       B5 HA drain rollout rehearsal (scripts/ha_drain.sh)
#   make bench          gateway-vs-direct performance benchmark (scripts/bench.sh; BENCH_FILE_MB/BENCH_ITERS)
#   make all            lint + test + build + integration
#
# The integration suite is self-contained: a local sshd backend + a mock
# control plane on random ports; no external network required. To point it
# at a real backend for manual validation (NOT part of CI):
#   SSH_GW_BACKEND_TARGET=user@host:port make integration

SHELL := /bin/bash
.DEFAULT_GOAL := all

.PHONY: help build lint test integration selftest soak ha-drain bench all

help:
	@grep -E '^#   make' $(MAKEFILE_LIST) | sed 's/^#   //'

build:
	cargo build

lint:
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings

test:
	cargo test

selftest:
	scripts/run_integration.sh --selftest

integration:
	scripts/run_integration.sh

all: lint test build integration

soak:
	SOAK_DURATION=$${SOAK_DURATION:-60} scripts/run_soak.sh

ha-drain:
	scripts/ha_drain.sh

bench:
	BENCH_FILE_MB=$${BENCH_FILE_MB:-64} BENCH_ITERS=$${BENCH_ITERS:-5} \
	BENCH_ROUNDS=$${BENCH_ROUNDS:-5} BENCH_STRICT=$${BENCH_STRICT:-1} scripts/bench.sh
