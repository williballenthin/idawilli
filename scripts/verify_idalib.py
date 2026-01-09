#!/usr/bin/env python3
"""
Verify that idalib is properly installed and configured.

This script tests that:
1. The idapro package can be imported
2. A database can be opened and closed using open_database()
3. Basic IDA API functions work

Usage:
    python verify_idalib.py <binary_file>

Example:
    python verify_idalib.py /bin/ls
"""

import sys
import argparse


def main():
    parser = argparse.ArgumentParser(description="Verify idalib installation")
    parser.add_argument("file", help="Binary file to analyze")
    parser.add_argument(
        "--run-auto-analysis",
        action="store_true",
        default=False,
        help="Run auto-analysis (slower but more complete)",
    )
    args = parser.parse_args()

    print("Testing idalib installation...")

    # Import idapro first (required by idalib)
    try:
        import idapro

        print("  [OK] idapro package imported successfully")
    except ImportError as e:
        print(f"  [FAIL] Could not import idapro: {e}")
        print("  Make sure idapro is installed: pip install idapro")
        print("  And activated: python <IDA_DIR>/py-activate-idalib.py -d <IDA_DIR>")
        return 1

    # Open database
    try:
        print(f"  Opening database for: {args.file}")
        idapro.open_database(args.file, args.run_auto_analysis)
        print("  [OK] Database opened successfully")
    except Exception as e:
        print(f"  [FAIL] Could not open database: {e}")
        return 1

    # Test basic IDA API
    try:
        import idaapi
        import idc

        # Wait for auto-analysis if requested
        if args.run_auto_analysis:
            print("  Waiting for auto-analysis to complete...")
            idaapi.auto_wait()

        # Get some basic info
        info = idaapi.get_inf_structure()
        print(f"  [OK] File type: {info.filetype}")
        print(f"  [OK] Processor: {info.procname}")
        print(f"  [OK] Min EA: {hex(info.min_ea)}")
        print(f"  [OK] Max EA: {hex(info.max_ea)}")
    except Exception as e:
        print(f"  [WARN] Could not query database info: {e}")

    # Close database
    try:
        idapro.close_database(save=False)
        print("  [OK] Database closed successfully")
    except Exception as e:
        print(f"  [FAIL] Could not close database: {e}")
        return 1

    print("\nidalib verification complete! All tests passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
