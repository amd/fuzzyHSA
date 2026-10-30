#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Generate Python ctypes bindings for KFD ioctl headers.

Uses ctypesgen to parse kernel headers and generate Python bindings.

Usage:
    pip install ctypesgen
    python generate_bindings.py

This will generate src/fuzzyHSA/kfd/autogen/kfd.py from /usr/include/linux/kfd_ioctl.h
"""

import shutil
import subprocess
import sys
from pathlib import Path

# Paths
SCRIPT_DIR = Path(__file__).parent
AUTOGEN_DIR = SCRIPT_DIR / "src" / "fuzzyHSA" / "kfd" / "autogen"
KFD_HEADER = Path("/usr/include/linux/kfd_ioctl.h")

# Alternative header locations to try
KFD_HEADER_ALTERNATIVES = [
    Path("/usr/include/linux/kfd_ioctl.h"),
    Path("/usr/src/linux-headers-{}/include/uapi/linux/kfd_ioctl.h"),
]


def find_kfd_header() -> Path | None:
    """Find the KFD ioctl header on the system."""
    if KFD_HEADER.exists():
        return KFD_HEADER

    # Try to find via kernel headers
    import platform
    kernel_version = platform.release()
    for alt in KFD_HEADER_ALTERNATIVES:
        path = Path(str(alt).format(kernel_version))
        if path.exists():
            return path

    return None


def _ctypesgen_cmd() -> list[str] | None:
    """Locate the ctypesgen console script. `python -m ctypesgen` does NOT work
    (the package ships no __main__), so the console entry point is the only path."""
    exe = shutil.which("ctypesgen")
    return [exe] if exe else None


def check_ctypesgen() -> bool:
    """Check if ctypesgen is installed."""
    cmd = _ctypesgen_cmd()
    if cmd is None:
        return False
    try:
        return subprocess.run(cmd + ["--version"], capture_output=True, text=True).returncode == 0
    except FileNotFoundError:
        return False


def generate_kfd_bindings(header: Path, output: Path) -> bool:
    """Generate KFD bindings using ctypesgen."""
    print(f"Generating bindings from {header}")
    print(f"Output: {output}")

    # Ensure output directory exists
    output.parent.mkdir(parents=True, exist_ok=True)

    # Run ctypesgen via its console script (see _ctypesgen_cmd)
    cmd = _ctypesgen_cmd() + [
        str(header),
        "-o", str(output),
        "--no-macro-warnings",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error: ctypesgen failed:\n{result.stderr}", file=sys.stderr)
        return False

    # Post-process: add mypy ignore and clean up
    content = output.read_text()

    # Add mypy ignore at the top
    if not content.startswith("# mypy:"):
        content = "# mypy: ignore-errors\n# ruff: noqa\n" + content

    # Remove trailing whitespace
    lines = [line.rstrip() for line in content.splitlines()]
    content = "\n".join(lines) + "\n"

    output.write_text(content)

    print(f"Successfully generated {output}")
    return True


def create_init_file(autogen_dir: Path) -> None:
    """Create __init__.py for autogen package."""
    init_file = autogen_dir / "__init__.py"
    if not init_file.exists():
        init_file.write_text(
            "# SPDX-License-Identifier: Apache-2.0\n"
            '"""Auto-generated bindings. Do not edit manually."""\n'
        )
        print(f"Created {init_file}")


def main() -> int:
    # Check ctypesgen is installed
    if not check_ctypesgen():
        print("Error: ctypesgen not installed. Run: pip install ctypesgen", file=sys.stderr)
        return 1

    # Find header
    header = find_kfd_header()
    if header is None:
        print("Error: Could not find kfd_ioctl.h", file=sys.stderr)
        print("Make sure linux kernel headers are installed:", file=sys.stderr)
        print("  Ubuntu/Debian: sudo apt install linux-headers-$(uname -r)", file=sys.stderr)
        print("  Fedora: sudo dnf install kernel-headers", file=sys.stderr)
        return 1

    # Generate bindings
    output = AUTOGEN_DIR / "kfd.py"
    if not generate_kfd_bindings(header, output):
        return 1

    # Create __init__.py
    create_init_file(AUTOGEN_DIR)

    print("\nDone! Bindings generated successfully.")
    print(f"Header: {header}")
    print(f"Output: {output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
