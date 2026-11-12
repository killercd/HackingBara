"""Independent queue outbox and lease reconciliation; runs even when every worker is busy."""

import json
import time

from .tasks import reconcile


def main():
    while True:
        try:
            reconcile.run()
        except Exception as exc:
            print(json.dumps({"event": "dispatch_error", "type": type(exc).__name__}), flush=True)
        time.sleep(2)


if __name__ == "__main__":
    main()
