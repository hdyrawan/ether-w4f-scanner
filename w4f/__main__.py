"""Allow `python3 -m w4f` to run the same CLI as the installed `w4f` command."""

import sys

from w4f.cli import main

if __name__ == "__main__":
    sys.exit(main())
