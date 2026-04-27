#!/usr/bin/env python3
"""
SCrack — SHA-1 Hash Recovery Tool

Usage:
    python main.py --sha <hash> --pw <prefix>

Examples:
    python main.py --sha 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 --pw pass
    python main.py --sha 7c4a8d09ca3762af61e59520943dc26494f8941b --pw 12
"""

import sys
import argparse
import multiprocessing as mp

from module.engine import CrackEngine
from module.workers import stop_signal


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="SCrack",
        description="SHA-1 Hash Recovery Tool with GPU Acceleration",
        epilog="Example: python main.py --sha 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 --pw pass",
    )
    parser.add_argument(
        "--sha",
        required=True,
        metavar="HASH",
        help="The SHA-1 hash to crack (40 hex characters)",
    )
    parser.add_argument(
        "--pw",
        required=True,
        metavar="PREFIX",
        help="Known prefix of the password (the visible part before the *'s)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    try:
        # Windows requires the 'spawn' start method for multiprocessing
        if sys.platform == 'win32' and hasattr(mp, 'set_start_method'):
            mp.set_start_method('spawn', force=True)

        engine = CrackEngine(target_hash=args.sha, target_prefix=args.pw)

        if not engine.validate_config():
            sys.exit(1)

        result = engine.run()

        if result:
            print(f"\nAnalysis Status: SUCCESS")
        else:
            print(f"\nAnalysis Status: UNSUCCESSFUL")

    except KeyboardInterrupt:
        print(f"\n\nAnalysis interrupted by operator.")
        stop_signal.value = True
        sys.exit(130)
    except Exception as e:
        print(f"\nCRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        stop_signal.value = True
        sys.exit(1)
    finally:
        stop_signal.value = True


if __name__ == "__main__":
    main()
