"""Small structured operational events on the daemon's journald stderr stream."""
import json
import sys


def emit(event, **fields):
    # Callers pass IDs, phases and durations, never environments/commands or secrets.
    try:
        print(json.dumps(dict(event=event, **fields), sort_keys=True), file=sys.stderr, flush=True)
    except OSError:
        pass  # Observability must not change the persisted operation outcome.
