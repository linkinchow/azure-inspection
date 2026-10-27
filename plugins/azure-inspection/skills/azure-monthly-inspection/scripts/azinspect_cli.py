"""Run without installing: python <skill>/scripts/azinspect_cli.py <command> ..."""
import os
import sys

sys.dont_write_bytecode = True  # the plugin directory may be read-only
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from azinspect.cli import main  # noqa: E402

sys.exit(main())
