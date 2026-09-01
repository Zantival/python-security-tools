#!/usr/bin/env python3
"""
Script 2 - Fernet Cryptography Tool
=====================================
Provides symmetric encryption/decryption using Fernet (AES-128-CBC + HMAC-SHA256).

Fixes applied:
    - ANSI color codes removed from input() prompts → prevents empty-read bug.
    - KeyboardInterrupt handled gracefully in the main loop (no traceback).
    - Last encrypted token stored in session so option 4 can auto-fill it.
    - Option 3 now also offers to decrypt the result immediately (quick test).

Dependencies:
    pip install cryptography

Usage:
    python script2_fernet_crypto.py
"""

import os
import sys
from pathlib import Path

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    print("[ERROR] cryptography is not installed. Run: pip install cryptography")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Constants & ANSI colors
# ---------------------------------------------------------------------------
DEFAULT_KEY_FILE = Path("fernet.key")

BOLD   = "\033[1m"
RESET  = "\033[0m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RED    = "\033[91m"
WHITE  = "\033[97m"
DIM    = "\033[2m"


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def generate_key() -> bytes:
    """
    Generates a new cryptographically-secure Fernet key.

    Returns:
        URL-safe base64-encoded 32-byte key as bytes.
    """
    return Fernet.generate_key()


def save_key(key: bytes, filepath: Path = DEFAULT_KEY_FILE) -> None:
    """
    Saves a Fernet key to a file and restricts permissions to owner only.

    Args:
        key:      Fernet key bytes to persist.
        filepath: Destination file path (default: fernet.key).
    """
    filepath.write_bytes(key)
    try:
        os.chmod(filepath, 0o600)   # rw------- on Unix
    except AttributeError:
        pass                        # Windows does not support POSIX chmod
    print(f"{GREEN}[OK]{RESET} Key saved to '{filepath}'")


def load_key(filepath: Path = DEFAULT_KEY_FILE) -> bytes:
    """
    Loads a Fernet key from disk.

    Args:
        filepath: Source file containing the key (default: fernet.key).

    Returns:
        Raw key bytes.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError:        If the file content is not a valid Fernet key.
    """
    if not filepath.exists():
        raise FileNotFoundError(f"Key file '{filepath}' not found.")
    raw = filepath.read_bytes().strip()
    print(f"{GREEN}[OK]{RESET} Key loaded from '{filepath}'")
    return raw


# ---------------------------------------------------------------------------
# Encrypt / Decrypt
# ---------------------------------------------------------------------------

def encrypt_message(message: str, key: bytes) -> bytes:
    """
    Encrypts a plain-text string using Fernet symmetric encryption.

    Fernet guarantees:
        - Confidentiality  : AES-128 in CBC mode
        - Integrity        : HMAC-SHA256 signature
        - Timestamped token: readable only with the originating key

    Args:
        message: UTF-8 string to encrypt.
        key:     Valid Fernet key bytes.

    Returns:
        Encrypted token as URL-safe base64 bytes.
    """
    f     = Fernet(key)
    token = f.encrypt(message.encode("utf-8"))
    return token


def decrypt_message(token: bytes, key: bytes) -> str:
    """
    Decrypts a Fernet token back to its original plain text.

    Args:
        token: Encrypted Fernet token bytes.
        key:   The same Fernet key that was used during encryption.

    Returns:
        Decrypted UTF-8 string.

    Raises:
        InvalidToken: If the token is tampered, corrupted, or the key is wrong.
    """
    f = Fernet(key)
    return f.decrypt(token).decode("utf-8")


# ---------------------------------------------------------------------------
# Interactive CLI
# ---------------------------------------------------------------------------

def prompt(label: str) -> str:
    """
    Displays a plain (no ANSI codes) input prompt and returns stripped input.

    Using ANSI escape codes directly inside input() can cause the terminal
    to miscount the prompt length, which occasionally results in an empty
    string being returned before the user types anything.  Printing the
    label separately with print() and then calling input() with a neutral
    symbol avoids this issue entirely.

    Args:
        label: Human-readable description of what is being requested.

    Returns:
        Stripped string entered by the user (never raises on empty input).
    """
    print(f"{YELLOW}{label}{RESET}", end="", flush=True)
    return input().strip()


def print_menu(session_key: bytes | None, last_token: bytes | None) -> None:
    """
    Prints the interactive menu, showing session state hints.

    Args:
        session_key: Current in-memory key (None if not yet set).
        last_token:  Most recently encrypted token (None if none yet).
    """
    key_status   = f"{GREEN}✔ active{RESET}" if session_key else f"{RED}✘ none{RESET}"
    token_status = f"{GREEN}✔ available{RESET}" if last_token else f"{DIM}none{RESET}"

    print(f"\n{WHITE}{BOLD}=== Fernet Crypto Tool ==={RESET}")
    print(f"  Key in session : {key_status}")
    print(f"  Last token     : {token_status}")
    print()
    print(f"  {CYAN}[1]{RESET} Generate a new Fernet key")
    print(f"  {CYAN}[2]{RESET} Load key from file")
    print(f"  {CYAN}[3]{RESET} Encrypt a message")
    print(f"  {CYAN}[4]{RESET} Decrypt a token")
    print(f"  {CYAN}[5]{RESET} Show current key")
    print(f"  {CYAN}[6]{RESET} Save current key to file")
    print(f"  {CYAN}[0]{RESET} Exit")
    print()


def run_interactive(initial_key: bytes = None) -> None:
    """
    Runs the main interactive loop for encrypting and decrypting messages.

    Maintains an in-memory session key and a reference to the last encrypted
    token, so the user can immediately decrypt what was just encrypted without
    having to manually copy-paste the token.

    Args:
        initial_key: Optional pre-loaded Fernet key to begin the session with.
    """
    session_key: bytes | None = initial_key
    last_token:  bytes | None = None          # Last token produced by option 3

    print(f"\n{CYAN}{BOLD}  Fernet Cryptography Tool{RESET}")
    if session_key:
        print(f"  {YELLOW}Key auto-loaded from '{DEFAULT_KEY_FILE}'{RESET}")

    while True:
        print_menu(session_key, last_token)

        # ----------------------------------------------------------------
        # IMPORTANT: do NOT put ANSI codes inside input() itself.
        # The label is printed with print() and input() receives only "> ".
        # ----------------------------------------------------------------
        try:
            choice = prompt("Select an option [0-6]: ")
        except (EOFError, KeyboardInterrupt):
            print(f"\n\n{CYAN}Interrupted. Goodbye!{RESET}\n")
            break

        # --- [1] Generate a new key ---
        if choice == "1":
            session_key = generate_key()
            last_token  = None          # Old token no longer decryptable with new key
            print(f"\n{GREEN}[NEW KEY GENERATED]{RESET}")
            print(f"  {CYAN}{session_key.decode()}{RESET}")
            print(f"  {DIM}(use option 6 to save it to disk){RESET}")

        # --- [2] Load key from file ---
        elif choice == "2":
            path_input = prompt(f"Key file path (press Enter for default '{DEFAULT_KEY_FILE}'): ")
            filepath   = Path(path_input) if path_input else DEFAULT_KEY_FILE
            try:
                new_key    = load_key(filepath)
                session_key = new_key
                last_token  = None      # Token from previous key is now invalid
            except (FileNotFoundError, ValueError) as exc:
                print(f"{RED}[ERROR]{RESET} {exc}")

        # --- [3] Encrypt ---
        elif choice == "3":
            if not session_key:
                print(f"\n{RED}[ERROR]{RESET} No key in session.")
                print(f"  → Use option {CYAN}[1]{RESET} to generate one or {CYAN}[2]{RESET} to load from file.")
                continue

            plain = prompt("Plain text to encrypt: ")
            if not plain:
                print(f"{YELLOW}[WARN]{RESET} Empty input – nothing encrypted.")
                continue

            last_token = encrypt_message(plain, session_key)
            print(f"\n{GREEN}[ENCRYPTED TOKEN]{RESET}")
            print(f"  {last_token.decode()}")
            print(f"  {DIM}(token saved in session – use option [4] to decrypt it){RESET}")

        # --- [4] Decrypt ---
        elif choice == "4":
            if not session_key:
                print(f"\n{RED}[ERROR]{RESET} No key in session.")
                print(f"  → Use option {CYAN}[1]{RESET} to generate one or {CYAN}[2]{RESET} to load from file.")
                continue

            # If a token was just encrypted, offer to use it automatically
            if last_token:
                print(f"  {DIM}Last token available. Press Enter to use it, or paste a different one.{RESET}")

            raw_input = prompt("Fernet token to decrypt (Enter = use last token): ")

            # Decide which token to decrypt
            if not raw_input:
                if last_token:
                    token_bytes = last_token
                    print(f"  {DIM}Using last encrypted token…{RESET}")
                else:
                    print(f"{YELLOW}[WARN]{RESET} No token provided and no previous token in session.")
                    continue
            else:
                token_bytes = raw_input.encode()

            try:
                plain = decrypt_message(token_bytes, session_key)
                print(f"\n{GREEN}[DECRYPTED TEXT]{RESET}")
                print(f"  {plain}")
            except InvalidToken:
                print(
                    f"\n{RED}[ERROR]{RESET} Decryption failed.\n"
                    "  Possible causes:\n"
                    "    • Wrong key (different from the one used to encrypt)\n"
                    "    • Token is corrupted or truncated\n"
                    "    • Token was generated with a different Fernet key\n"
                    f"  → Regenerate or reload the correct key with option {CYAN}[1]{RESET} / {CYAN}[2]{RESET}."
                )

        # --- [5] Show current key ---
        elif choice == "5":
            if session_key:
                print(f"\n{GREEN}[CURRENT KEY]{RESET}")
                print(f"  {CYAN}{session_key.decode()}{RESET}")
            else:
                print(f"\n{YELLOW}[INFO]{RESET} No key in session.")
                print(f"  → Use option {CYAN}[1]{RESET} to generate one.")

        # --- [6] Save key to file ---
        elif choice == "6":
            if not session_key:
                print(f"\n{RED}[ERROR]{RESET} No key in session to save.")
                print(f"  → Use option {CYAN}[1]{RESET} to generate one first.")
                continue
            path_input = prompt(f"Save path (press Enter for default '{DEFAULT_KEY_FILE}'): ")
            filepath   = Path(path_input) if path_input else DEFAULT_KEY_FILE
            try:
                save_key(session_key, filepath)
            except OSError as exc:
                print(f"{RED}[ERROR]{RESET} Could not save key: {exc}")

        # --- [0] Exit ---
        elif choice == "0":
            print(f"\n{CYAN}Goodbye!{RESET}\n")
            break

        # --- Invalid ---
        else:
            if choice:
                print(f"{YELLOW}[WARN]{RESET} '{choice}' is not a valid option. Choose a number from 0 to 6.")
            # Silently ignore empty input (just redraws the menu)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Main entry point. Auto-loads the default key file if present,
    then starts the interactive CLI session.
    """
    initial_key = None

    if DEFAULT_KEY_FILE.exists():
        try:
            initial_key = load_key(DEFAULT_KEY_FILE)
        except ValueError:
            print(
                f"{YELLOW}[WARN]{RESET} '{DEFAULT_KEY_FILE}' exists but contains an invalid key.\n"
                "  Please generate a new one with option [1]."
            )

    run_interactive(initial_key=initial_key)


if __name__ == "__main__":
    main()
