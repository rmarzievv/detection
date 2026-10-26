.PHONY: all lint validate test build

all: lint validate test build

lint:
	yamllint rules tests/fixtures

validate:
	python3 scripts/validate.py

test:
	python3 -m pytest -v

build:
	python3 scripts/convert.py
	python3 scripts/coverage.py
