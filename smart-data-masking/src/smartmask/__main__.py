"""Allow running the CLI as: python -m smartmask.cli"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
