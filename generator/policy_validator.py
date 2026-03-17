"""Validate generated SCP/RCP policy documents."""

import json
from dataclasses import dataclass, field
from pathlib import Path

# AWS SCP maximum size in bytes
SCP_MAX_BYTES = 5120

# AWS RCP maximum size in bytes
RCP_MAX_BYTES = 5120


@dataclass
class ValidationResult:
    path: str
    valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    size_bytes: int = 0


def validate_policy(policy: dict, path: str = "<inline>") -> ValidationResult:
    """Validate a single policy document."""
    result = ValidationResult(path=path)

    # Check required fields
    if "Version" not in policy:
        result.errors.append("Missing 'Version' field")
        result.valid = False

    if "Statement" not in policy:
        result.errors.append("Missing 'Statement' field")
        result.valid = False
        return result

    if not isinstance(policy["Statement"], list):
        result.errors.append("'Statement' must be a list")
        result.valid = False
        return result

    if len(policy["Statement"]) == 0:
        result.errors.append("'Statement' must contain at least one statement")
        result.valid = False

    # Validate each statement
    sids = set()
    for i, stmt in enumerate(policy["Statement"]):
        prefix = f"Statement[{i}]"

        if "Effect" not in stmt:
            result.errors.append(f"{prefix}: Missing 'Effect'")
            result.valid = False

        if "Action" not in stmt and "NotAction" not in stmt:
            result.errors.append(f"{prefix}: Missing 'Action' or 'NotAction'")
            result.valid = False

        if stmt.get("Effect") == "Allow" and "Principal" not in stmt:
            # SCPs should not have Allow statements (they don't grant permissions)
            result.warnings.append(
                f"{prefix}: SCP 'Allow' statement detected. "
                "SCPs cannot grant permissions — consider restructuring "
                "as exclusion conditions on Deny."
            )

        # Check for duplicate Sids
        sid = stmt.get("Sid")
        if sid:
            if sid in sids:
                result.errors.append(f"{prefix}: Duplicate Sid '{sid}'")
                result.valid = False
            sids.add(sid)

    # Check size
    minified = json.dumps(policy, separators=(",", ":"))
    result.size_bytes = len(minified.encode("utf-8"))

    if result.size_bytes > SCP_MAX_BYTES:
        result.errors.append(
            f"Policy size {result.size_bytes} bytes exceeds SCP limit "
            f"of {SCP_MAX_BYTES} bytes. Must be split."
        )
        result.valid = False
    elif result.size_bytes > SCP_MAX_BYTES * 0.8:
        result.warnings.append(
            f"Policy size {result.size_bytes} bytes is >80% of "
            f"{SCP_MAX_BYTES} byte limit."
        )

    return result


def validate_policy_file(path: str | Path) -> ValidationResult:
    """Validate a policy JSON file."""
    path = Path(path)
    try:
        with open(path) as f:
            policy = json.load(f)
    except json.JSONDecodeError as e:
        result = ValidationResult(path=str(path), valid=False)
        result.errors.append(f"Invalid JSON: {e}")
        return result

    return validate_policy(policy, path=str(path))


def validate_all(policy_dir: str | Path) -> list[ValidationResult]:
    """Validate all JSON policy files in a directory."""
    policy_dir = Path(policy_dir)
    results = []

    for path in sorted(policy_dir.glob("*.json")):
        results.append(validate_policy_file(path))

    return results
