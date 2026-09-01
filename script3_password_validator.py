#!/usr/bin/env python3
"""
Script 3 - Password Strength Validator
========================================
Evaluates whether a password is secure by applying the following rules:

    Rule 1 – Minimum length   : at least 8 characters
    Rule 2 – Uppercase letter : at least one A-Z character
    Rule 3 – Lowercase letter : at least one a-z character
    Rule 4 – Digit            : at least one 0-9 character
    Rule 5 – Special char     : at least one of !@#$%^&*()-_=+[]{};:'",.<>?/|\\`~

A strength score (0–5) is computed and mapped to a human-readable label.

Usage:
    python script3_password_validator.py
    python script3_password_validator.py --password "MyP@ssw0rd"
    python script3_password_validator.py --batch  # interactive multi-password mode
"""

import argparse
import re
import sys
from dataclasses import dataclass, field
from getpass import getpass
from typing import List


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Minimum password length required to pass the length rule
MIN_LENGTH: int = 8

# Set of special characters considered valid for rule 5
SPECIAL_CHARS: str = r"!@#$%^&*()\-_=+\[\]{};:'\",.<>?/|\\`~"

# ANSI color codes
BOLD   = "\033[1m"
RESET  = "\033[0m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RED    = "\033[91m"
WHITE  = "\033[97m"
MAGENTA = "\033[95m"

# Strength score → label mapping
STRENGTH_LABELS = {
    0: (RED,    "Very Weak   "),
    1: (RED,    "Weak        "),
    2: (YELLOW, "Fair        "),
    3: (YELLOW, "Moderate    "),
    4: (GREEN,  "Strong      "),
    5: (GREEN,  "Very Strong "),
}


# ---------------------------------------------------------------------------
# Data class for validation results
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    """
    Stores the outcome of a single password validation run.

    Attributes:
        password:           The password that was evaluated (masked in output).
        length_ok:          True if the password meets the minimum length rule.
        has_uppercase:      True if the password contains at least one A-Z char.
        has_lowercase:      True if the password contains at least one a-z char.
        has_digit:          True if the password contains at least one digit.
        has_special:        True if the password contains at least one special char.
        failed_rules:       List of human-readable descriptions of failed rules.
        score:              Integer score from 0 (all rules failed) to 5 (all passed).
        is_secure:          True only when all 5 rules pass (score == 5).
    """
    password:       str
    length_ok:      bool = False
    has_uppercase:  bool = False
    has_lowercase:  bool = False
    has_digit:      bool = False
    has_special:    bool = False
    failed_rules:   List[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        """Returns the total number of rules that passed (0–5)."""
        return sum([
            self.length_ok,
            self.has_uppercase,
            self.has_lowercase,
            self.has_digit,
            self.has_special,
        ])

    @property
    def is_secure(self) -> bool:
        """Returns True only when ALL five validation rules pass."""
        return self.score == 5


# ---------------------------------------------------------------------------
# Core validation logic
# ---------------------------------------------------------------------------

def validate_password(password: str) -> ValidationResult:
    """
    Validates a password against all five security rules.

    Args:
        password: The plain-text password string to evaluate.

    Returns:
        A ValidationResult instance populated with rule outcomes,
        a list of failed rules, a score, and an overall pass/fail flag.
    """
    result = ValidationResult(password=password)
    failed: List[str] = []

    # Rule 1 – Minimum length
    if len(password) >= MIN_LENGTH:
        result.length_ok = True
    else:
        failed.append(
            f"Minimum length of {MIN_LENGTH} characters "
            f"(current: {len(password)})"
        )

    # Rule 2 – At least one uppercase letter
    if re.search(r"[A-Z]", password):
        result.has_uppercase = True
    else:
        failed.append("At least one uppercase letter (A-Z)")

    # Rule 3 – At least one lowercase letter
    if re.search(r"[a-z]", password):
        result.has_lowercase = True
    else:
        failed.append("At least one lowercase letter (a-z)")

    # Rule 4 – At least one digit
    if re.search(r"[0-9]", password):
        result.has_digit = True
    else:
        failed.append("At least one digit (0-9)")

    # Rule 5 – At least one special character
    if re.search(rf"[{SPECIAL_CHARS}]", password):
        result.has_special = True
    else:
        failed.append(
            "At least one special character "
            "(!@#$%^&*()-_=+[]{};:'\",.<>?/|\\`~)"
        )

    result.failed_rules = failed
    return result


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def rule_indicator(passed: bool) -> str:
    """
    Returns a colored pass/fail indicator symbol.

    Args:
        passed: Boolean indicating whether the rule was satisfied.

    Returns:
        A green checkmark string if passed, red cross string otherwise.
    """
    return f"{GREEN}✔{RESET}" if passed else f"{RED}✘{RESET}"


def strength_bar(score: int, total: int = 5, bar_width: int = 20) -> str:
    """
    Builds an ASCII progress bar representing the password strength score.

    Args:
        score:      Number of passed rules (0 to total).
        total:      Maximum possible score (default: 5).
        bar_width:  Character width of the full bar (default: 20).

    Returns:
        Formatted bar string, e.g. '████████░░░░░░░░░░░░'.
    """
    filled   = int((score / total) * bar_width)
    empty    = bar_width - filled
    color, _ = STRENGTH_LABELS.get(score, (RESET, ""))
    bar      = f"{color}{'█' * filled}{RESET}{'░' * empty}"
    return bar


def display_result(result: ValidationResult) -> None:
    """
    Prints a formatted validation report for a single password to stdout.

    Args:
        result: The ValidationResult produced by validate_password().
    """
    # Mask the password for display (show first and last char only if len > 2)
    pwd     = result.password
    masked  = (pwd[0] + "*" * (len(pwd) - 2) + pwd[-1]) if len(pwd) > 2 else "**"

    color, label = STRENGTH_LABELS.get(result.score, (RESET, "Unknown"))
    bar          = strength_bar(result.score)

    print(f"\n{WHITE}{BOLD}{'─' * 50}{RESET}")
    print(f"  Password  : {CYAN}{masked}{RESET}")
    print(f"  Length    : {len(result.password)} characters")
    print(f"  Strength  : {bar}  {color}{BOLD}{label.strip()}{RESET}  ({result.score}/5)")
    print(f"{WHITE}{'─' * 50}{RESET}\n")

    print(f"  {'Rule':<45} {'Status'}")
    print(f"  {'─'*45} {'──────'}")
    print(
        f"  {'Minimum length (≥8 characters)':<45} "
        f"{rule_indicator(result.length_ok)}"
    )
    print(
        f"  {'Uppercase letter (A-Z)':<45} "
        f"{rule_indicator(result.has_uppercase)}"
    )
    print(
        f"  {'Lowercase letter (a-z)':<45} "
        f"{rule_indicator(result.has_lowercase)}"
    )
    print(
        f"  {'Digit (0-9)':<45} "
        f"{rule_indicator(result.has_digit)}"
    )
    print(
        f"  {'Special character (!@#$%^&*…)':<45} "
        f"{rule_indicator(result.has_special)}"
    )

    print()

    if result.is_secure:
        print(f"  {GREEN}{BOLD}✔ Password is SECURE – all rules satisfied.{RESET}")
    else:
        print(f"  {RED}{BOLD}✘ Password is NOT SECURE. Fix the following:{RESET}")
        for rule in result.failed_rules:
            print(f"    {YELLOW}→{RESET} {rule}")

    print(f"\n{WHITE}{'─' * 50}{RESET}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_arguments() -> argparse.Namespace:
    """
    Parses command-line arguments.

    Returns:
        Namespace with attributes: password (str or None), batch (bool).
    """
    parser = argparse.ArgumentParser(
        description="Password Strength Validator – checks 5 security rules.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python script3_password_validator.py\n"
            "  python script3_password_validator.py --password 'MyP@ss1!'\n"
            "  python script3_password_validator.py --batch\n"
        ),
    )
    parser.add_argument(
        "--password",
        type=str,
        default=None,
        help="Password to validate (if omitted, prompted interactively).",
    )
    parser.add_argument(
        "--batch",
        action="store_true",
        default=False,
        help="Interactive mode: validate multiple passwords until 'quit' is entered.",
    )
    return parser.parse_args()


def main() -> None:
    """
    Main entry point for the Password Strength Validator.

    Handles three modes:
        - Single password via --password argument.
        - Interactive single prompt (default).
        - Batch mode via --batch flag.
    """
    args = parse_arguments()

    print(f"\n{CYAN}{BOLD}  Password Strength Validator{RESET}")
    print(f"  Checking: length, uppercase, lowercase, digits, special chars\n")

    if args.password:
        # Non-interactive: validate the password provided on the command line
        result = validate_password(args.password)
        display_result(result)
        sys.exit(0 if result.is_secure else 1)

    if args.batch:
        # Batch mode: keep prompting until the user types 'quit'
        print(f"  {YELLOW}Batch mode – type 'quit' to exit.{RESET}\n")
        while True:
            try:
                pwd = getpass("  Enter password to validate (hidden input): ")
            except (EOFError, KeyboardInterrupt):
                print(f"\n{CYAN}Exiting.{RESET}\n")
                break

            if pwd.lower() in ("quit", "exit", "q"):
                print(f"\n{CYAN}Goodbye!{RESET}\n")
                break

            result = validate_password(pwd)
            display_result(result)
    else:
        # Default: single interactive prompt
        try:
            pwd = getpass("  Enter password to validate (hidden input): ")
        except (EOFError, KeyboardInterrupt):
            print(f"\n{CYAN}Exiting.{RESET}\n")
            sys.exit(0)

        result = validate_password(pwd)
        display_result(result)
        sys.exit(0 if result.is_secure else 1)


if __name__ == "__main__":
    main()
