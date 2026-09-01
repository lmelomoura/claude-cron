"""Loads bin/security as a package. bin/ has no __init__ chain of its own."""
import sys
from pathlib import Path

# Modify sys.path at module load time, BEFORE conftest is fully initialized
REPO = Path(__file__).resolve().parent.parent.parent
bin_path = str(REPO / "bin")
if bin_path not in sys.path:
    sys.path.insert(0, bin_path)
