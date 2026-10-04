PYTHON ?= python3
PY := .venv/bin/python

.PHONY: install test parts realtime runs clean

install:            ## venv, package, detector model (about 600 MB for the model)
	$(PYTHON) -m venv .venv
	$(PY) -m pip install -q --upgrade pip
	$(PY) -m pip install -q -e '.[dev]'
	$(PY) -m spacy download en_core_web_lg

test:               ## 35 tests: article claims, library, scenarios (~20s)
	$(PY) -m pytest

parts:              ## re-run every article's examples, part by part
	@for f in parts/p*.py; do printf '\n##### %s\n' $$f; $(PY) $$f || exit 1; done

realtime:           ## the ten real-world scenarios
	@for f in realtime/rt*.py; do printf '\n##### %s\n' $$f; $(PY) $$f || exit 1; done

runs:               ## capture every script's output into runs/ (commit these)
	@mkdir -p runs
	@for f in parts/p*.py realtime/rt*.py; do \
		$(PY) $$f > runs/$$(basename $$f .py).out 2>&1 || exit 1; done
	@ls runs

clean:
	rm -rf .pytest_cache src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
