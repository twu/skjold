.PHONY: hooks
hooks:
	# Ensure the hook is installed and executed before pushing to a remote.
	test -f .git/hooks/pre-commit || pre-commit install --hook-type pre-commit -f
	pre-commit run --all-files

.PHONY: run
run:
	poetry export --dev -f requirements.txt | poetry run skjold --verbose audit --report-format=json -

.PHONY: tests
tests:
	PYTHONPATH=src pytest -x --cov=src tests

.PHONY: watch
watch:
	PYTHONPATH=src ptw -q -c

.PHONY: audit
audit:
	poetry export --dev -f requirements.txt | poetry run skjold audit -

.PHONY: report-cli
report-cli:
	poetry export --dev -f requirements.txt | poetry run skjold --verbose audit -

.PHONY: report-json
report-json:
	poetry export --dev -f requirements.txt | poetry run skjold --verbose audit --report-format=json --report-only - | jq '.[]'

.PHONY: build
build: clean audit tests hooks
	poetry build

.PHONY: prerelease
prerelease: build
	poetry publish -r testpypi

.PHONY: release
release: build
	poetry publish -r pypi

.PHONY: clean
clean:
	find . -type f -name '*.py[co]' -delete -o -type d -name __pycache__ -delete
	rm -rf .skjold_cache/
	rm -rf ~/.skjold
