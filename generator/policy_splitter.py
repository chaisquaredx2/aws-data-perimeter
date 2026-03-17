"""Split SCP policies that exceed the 5,120 byte AWS limit.

Strategy: split by statement. Each output policy gets a subset of statements
that fits within the size limit. Statement order is preserved. Sids are
suffixed with the part number (e.g., _Part1, _Part2).
"""

import json
import math

SCP_MAX_BYTES = 5120

# Overhead for the policy wrapper: {"Version":"2012-10-17","Statement":[]}
_WRAPPER_OVERHEAD = len(
    json.dumps({"Version": "2012-10-17", "Statement": []}, separators=(",", ":")).encode("utf-8")
)


def _statement_size(stmt: dict) -> int:
    """Size of a single statement when minified, including the comma separator."""
    return len(json.dumps(stmt, separators=(",", ":")).encode("utf-8")) + 1  # +1 for comma


def needs_splitting(policy: dict) -> bool:
    """Check if a policy exceeds the SCP size limit."""
    minified = json.dumps(policy, separators=(",", ":"))
    return len(minified.encode("utf-8")) > SCP_MAX_BYTES


def split_policy(policy: dict, base_name: str) -> list[tuple[str, dict]]:
    """Split a policy into multiple policies that each fit within size limits.

    Returns list of (filename, policy_doc) tuples.
    If the policy doesn't need splitting, returns a single-element list.
    """
    if not needs_splitting(policy):
        return [(base_name, policy)]

    statements = policy["Statement"]
    parts = []
    current_statements = []
    current_size = _WRAPPER_OVERHEAD

    for stmt in statements:
        stmt_size = _statement_size(stmt)

        # If a single statement exceeds the limit, we can't split further
        if stmt_size + _WRAPPER_OVERHEAD > SCP_MAX_BYTES:
            raise ValueError(
                f"Statement '{stmt.get('Sid', '<no sid>')}' is {stmt_size} bytes, "
                f"which exceeds the {SCP_MAX_BYTES} byte limit even alone."
            )

        if current_size + stmt_size > SCP_MAX_BYTES:
            # Flush current batch
            parts.append(current_statements)
            current_statements = [stmt]
            current_size = _WRAPPER_OVERHEAD + stmt_size
        else:
            current_statements.append(stmt)
            current_size += stmt_size

    if current_statements:
        parts.append(current_statements)

    # Build output policies
    total_parts = len(parts)
    result = []
    for i, stmts in enumerate(parts, 1):
        suffix = f"-part{i}" if total_parts > 1 else ""
        name = f"{base_name}{suffix}"
        doc = {
            "Version": "2012-10-17",
            "Statement": stmts,
        }
        result.append((name, doc))

    return result


def split_all(policies: dict[str, dict]) -> dict[str, dict]:
    """Split all oversized policies. Returns new dict with split results.

    Input keys are base filenames, output may have more keys if splitting occurred.
    """
    result = {}
    for base_name, policy in policies.items():
        for name, doc in split_policy(policy, base_name):
            result[name] = doc
    return result
