"""Resolve a run's scope in a cancellable child process, before any scanner starts."""

import json
import sys
from pathlib import Path

from .scope import ScanInput, ScopePreparationError, prepare_run_config


def main():
    issues = []
    try:
        config = ScanInput.model_validate_json(Path(sys.argv[1]).read_text())
        prepared = prepare_run_config(config, issues)
        result = {"config": prepared.model_dump(), "issues": issues}
    except ScopePreparationError as exc:
        result = {"error": str(exc), "issues": exc.issues}
    except (ValueError, OSError):
        result = {
            "error": "Scope preparation failed; check the supplied targets and DNS configuration",
            "issues": issues,
        }
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
