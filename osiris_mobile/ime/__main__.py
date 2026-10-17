"""``python -m osiris_mobile.ime`` runs the loopback daemon (same as ``osiris-ime-bridge``)."""

import sys

from .server import main

sys.exit(main())
