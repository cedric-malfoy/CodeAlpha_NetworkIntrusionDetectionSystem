# IEEE manuscript scaffold

`main.tex` uses IEEEtran conference format. It is an incomplete research draft, not a submission-ready manuscript. The research runner produces figures and a LaTeX results table from actual measurements; review those outputs and their limitations before inserting them here.

Build from this directory in an environment with IEEEtran and a LaTeX installation:

```bash
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

The author list, abstract, contributions, result discussion, conclusion and target-conference requirements remain to be completed after the evidence gate. Keep the baseline, exploratory comparisons and fresh-capture results distinct. A favorable pilot result alone does not establish novelty or guarantee acceptance.
