"""Canonical loopback backend entrypoint for the VibeGate dashboard."""

from .dashboard import main


if __name__ == "__main__":
    raise SystemExit(main())
