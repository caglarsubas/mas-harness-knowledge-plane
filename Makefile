.DEFAULT_GOAL := help

.PHONY: help prefetch common-contract security

help prefetch common-contract security:
	@python3 ci/run_make_target.py "$@"

%:
	@python3 ci/run_make_target.py "$@"
