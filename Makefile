# Full pipeline: ~10 minutes on a laptop, no API keys or GPUs required.
PY = uv run python

all: fetch trees scan signals stats figures paper

fetch:   ; $(PY) scripts/01_fetch.py
trees:   ; $(PY) scripts/02_build_trees.py
scan:    ; $(PY) scripts/03_scan.py
signals: ; $(PY) scripts/04_signals.py
stats:   ; $(PY) scripts/05_stats.py
figures: ; $(PY) scripts/06_figures.py
paper:
	cd paper && pdflatex -interaction=nonstopmode main.tex >/dev/null && bibtex main >/dev/null && \
	pdflatex -interaction=nonstopmode main.tex >/dev/null && pdflatex -interaction=nonstopmode main.tex >/dev/null
	cp paper/main.pdf docs/paper.pdf

.PHONY: all fetch trees scan signals stats figures paper
