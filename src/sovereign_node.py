"""
Sovereign Node Execution Daemon (rev 7).

Deterministic: the timestamp is supplied by the caller (an integer), never read from the wall
clock, so identical inputs reproduce identical commitments. Inputs must be integers; failures,
including ledger I/O errors, are returned as Res values and leave the chain head unchanged.
"""

import hashlib
import json
from collections import namedtuple
from typing import Any, Dict

ZERO_HASH = "0x" + "0" * 64

Res = namedtuple("Res", "ok value reason")


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


class SovereignNodeDaemon:
    def __init__(self, node_id: int, ledger_path: str):
        self.node_id = node_id
        self.ledger_path = ledger_path
        self.current_state_hash = ZERO_HASH

    def compute_wad18_state_hash(self, payload: Dict[str, Any]) -> str:
        """Deterministic SHA-256 of the canonical (sorted-key) JSON payload. Precondition: JSON-able."""
        canonical_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
        return hashlib.sha256(canonical_bytes).hexdigest()

    def step_refinement_loop(self, input_vector: Dict[str, int], timestamp: int):
        """Appends a hash-chained commitment to the local ledger. Returns Res(hash)."""
        if not is_int(timestamp) or timestamp < 0:
            return Res(False, None, "BAD_TIMESTAMP")
        if not isinstance(input_vector, dict):
            return Res(False, None, "BAD_INPUTS")
        for key, val in input_vector.items():
            if not isinstance(key, str) or not is_int(val):
                return Res(False, None, "NON_INTEGER_INPUT")
        state_payload = {
            "node_id": self.node_id,
            "timestamp": timestamp,
            "inputs": input_vector,
            "prev_hash": self.current_state_hash
        }
        new_hash = self.compute_wad18_state_hash(state_payload)
        try:
            with open(self.ledger_path, "a") as f:
                f.write(json.dumps({"hash": new_hash, "payload": state_payload}) + "\n")
        except OSError:
            return Res(False, None, "LEDGER_WRITE_FAILED")
        self.current_state_hash = new_hash
        return Res(True, new_hash, "")
