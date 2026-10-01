"""Pre-commit hook utility scripts for Occulens development."""

import re
import shutil
import subprocess
import sys
from pathlib import Path


def check_branch_name() -> int:
    """Verify that current branch name complies with git-workflow-and-versioning."""
    git_bin = shutil.which("git") or "git"
    try:
        branch = subprocess.check_output(  # noqa: S603
            [git_bin, "branch", "--show-current"], text=True
        ).strip()
    except (subprocess.SubprocessError, OSError):
        return 0

    if not branch:
        return 0

    prefix = r"(feature|fix|chore|refactor|test|docs|perf|style|build|ci)"
    pattern = rf"^(main|master|develop|{prefix}/[a-z0-9._-]+)$"
    if not re.match(pattern, branch):
        sys.stderr.write(
            f"ERROR: Branch name '{branch}' violates convention. "
            "Expected 'main', 'develop', or '(feature|fix|chore|refactor)/<short-description>'.\n"
        )
        return 1
    return 0


def trim_trailing_whitespace(files: list[str]) -> int:
    """Strip trailing whitespace from files in place; exit 1 if any file was modified."""
    modified_any = False
    for filepath in files:
        path = Path(filepath)
        if not path.is_file():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as err:
            sys.stderr.write(f"Warning: could not read {filepath}: {err}\n")
            continue

        lines = [line.rstrip() for line in content.splitlines()]
        new_content = "\n".join(lines)
        if content.endswith("\n") and lines:
            new_content += "\n"

        if new_content != content:
            path.write_text(new_content, encoding="utf-8")
            sys.stderr.write(f"Fixed trailing whitespace in: {filepath}\n")
            modified_any = True

    return 1 if modified_any else 0


def ensure_eof_newline(files: list[str]) -> int:
    """Ensure text files end with a newline; exit 1 if any file was modified."""
    modified_any = False
    for filepath in files:
        path = Path(filepath)
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError as err:
            sys.stderr.write(f"Warning: could not read bytes from {filepath}: {err}\n")
            continue

        if data and not data.endswith(b"\n"):
            path.write_bytes(data + b"\n")
            sys.stderr.write(f"Added end-of-file newline to: {filepath}\n")
            modified_any = True

    return 1 if modified_any else 0


def check_yaml(files: list[str]) -> int:
    """Validate YAML syntax for specified files."""
    import yaml  # type: ignore[import-untyped]

    failed = False
    for filepath in files:
        path = Path(filepath)
        if not path.is_file():
            continue
        try:
            with path.open(encoding="utf-8") as f:
                yaml.safe_load(f)
        except Exception as exc:
            sys.stderr.write(f"YAML syntax error in {filepath}: {exc}\n")
            failed = True

    return 1 if failed else 0


def check_toml(files: list[str]) -> int:
    """Validate TOML syntax for specified files."""
    import tomllib

    failed = False
    for filepath in files:
        path = Path(filepath)
        if not path.is_file():
            continue
        try:
            with path.open("rb") as f:
                tomllib.load(f)
        except Exception as exc:
            sys.stderr.write(f"TOML syntax error in {filepath}: {exc}\n")
            failed = True

    return 1 if failed else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(0)

    command = sys.argv[1]
    args = sys.argv[2:]

    dispatch = {
        "check-branch": lambda: check_branch_name(),
        "trailing-whitespace": lambda: trim_trailing_whitespace(args),
        "end-of-file-fixer": lambda: ensure_eof_newline(args),
        "check-yaml": lambda: check_yaml(args),
        "check-toml": lambda: check_toml(args),
    }

    if command in dispatch:
        sys.exit(dispatch[command]())
    else:
        sys.stderr.write(f"Unknown command: {command}\n")
        sys.exit(1)
