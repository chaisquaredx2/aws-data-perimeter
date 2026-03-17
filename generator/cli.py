"""CLI entry point for the data perimeter policy generator."""

import argparse
import sys

from generator.intent_parser import parse_intent
from generator.policy_generator import generate_policies, write_policies
from generator.policy_splitter import split_all
from generator.policy_validator import validate_all, validate_policy


def cmd_generate(args):
    """Generate policies from intent configuration."""
    print(f"Parsing intent: {args.intent}")
    config = parse_intent(args.intent)
    print(f"  Organization: {config.org_name} ({config.org_id})")
    print(f"  OUs: {', '.join(config.ou_mapping.keys())}")

    print("Generating policies...")
    policies = generate_policies(config)

    # Validate before splitting
    for name, policy in policies.items():
        result = validate_policy(policy, path=name)
        if result.warnings:
            for w in result.warnings:
                print(f"  WARN [{name}]: {w}")

    # Split oversized policies
    policies = split_all(policies)

    # Validate after splitting
    all_valid = True
    for name, policy in policies.items():
        result = validate_policy(policy, path=name)
        if not result.valid:
            all_valid = False
            for e in result.errors:
                print(f"  ERROR [{name}]: {e}")

    if not all_valid:
        print("Validation failed. Not writing policies.")
        sys.exit(1)

    written = write_policies(policies, args.output)
    for path in written:
        print(f"  Written: {path}")

    print(f"Generated {len(written)} policy file(s) in {args.output}/")


def cmd_validate(args):
    """Validate existing policy files."""
    results = validate_all(args.policies)

    if not results:
        print(f"No JSON files found in {args.policies}/")
        sys.exit(1)

    all_valid = True
    for result in results:
        status = "OK" if result.valid else "FAIL"
        print(f"  [{status}] {result.path} ({result.size_bytes} bytes)")

        for e in result.errors:
            print(f"    ERROR: {e}")
        for w in result.warnings:
            print(f"    WARN: {w}")

        if not result.valid:
            all_valid = False

    if all_valid:
        print(f"All {len(results)} policies valid.")
    else:
        print("Validation failed.")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="AWS Data Perimeter Policy Generator"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # generate command
    gen_parser = subparsers.add_parser("generate", help="Generate policies from intent config")
    gen_parser.add_argument(
        "--intent", required=True, help="Path to data_perimeter_intent.yaml"
    )
    gen_parser.add_argument(
        "--output",
        default="terraform/policies",
        help="Output directory for generated JSON policies",
    )
    gen_parser.set_defaults(func=cmd_generate)

    # validate command
    val_parser = subparsers.add_parser("validate", help="Validate generated policies")
    val_parser.add_argument(
        "--policies",
        default="terraform/policies",
        help="Directory containing policy JSON files",
    )
    val_parser.set_defaults(func=cmd_validate)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
