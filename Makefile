.PHONY: install lint format format-check typecheck test evaluate check pre-commit clean

VENV ?= .venv
PYTHON ?= $(VENV)/bin/python
PIP ?= $(VENV)/bin/pip
RUFF ?= $(VENV)/bin/ruff
MYPY ?= $(VENV)/bin/mypy
PYTEST ?= $(VENV)/bin/pytest
PRE_COMMIT ?= $(VENV)/bin/pre-commit

install:
	$(PIP) install -e ".[dev]"

lint:
	$(RUFF) check src/ tests/

format:
	$(RUFF) format src/ tests/

format-check:
	$(RUFF) format --check src/ tests/

typecheck:
	$(MYPY) src/

test:
	$(PYTEST)

evaluate:
	$(PYTHON) -m occulens.evaluation --output evaluation/baseline_report.json

check: lint format-check typecheck test

pre-commit:
	$(PRE_COMMIT) run --all-files

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info .coverage htmlcov
