"""Validate the checked-in notebook structure and executed-cell status without Jupyter."""
import argparse
import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executed", action="store_true", help="Require every code cell to have a successful execution count.")
    args = parser.parse_args()
    path = ROOT / "notebooks/01_training_evaluation.ipynb"
    notebook = json.loads(path.read_text())
    assert notebook["nbformat"] == 4
    cells = notebook["cells"]
    assert cells and len({cell["id"] for cell in cells}) == len(cells)
    counts = []
    for index, cell in enumerate(cells, 1):
        assert cell["cell_type"] in ("markdown", "code")
        source = cell["source"]
        source = "".join(source) if isinstance(source, list) else source
        assert isinstance(source, str) and source.strip()
        if cell["cell_type"] != "code":
            continue
        ast.parse(source, filename=f"notebook-cell-{index}")
        assert not any(output.get("output_type") == "error" for output in cell["outputs"]), f"Error output in cell {index}"
        if args.executed:
            count = cell["execution_count"]
            assert type(count) is int and count > 0, f"Unexecuted cell {index}"
            counts.append(count)
    if args.executed:
        assert counts == list(range(1, len(counts) + 1)), "Run All from a fresh kernel before publishing."
    print(f"Validated {len(cells)} cells" + (f", {len(counts)} successful code executions." if args.executed else "."))


if __name__ == "__main__":
    main()
