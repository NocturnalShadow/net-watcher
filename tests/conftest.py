import sys
import os

_tests_dir = os.path.dirname(os.path.abspath(__file__))
# Make src/ and tests/ importable from any working directory.
sys.path.insert(0, _tests_dir)
sys.path.insert(0, os.path.join(_tests_dir, "..", "src"))
