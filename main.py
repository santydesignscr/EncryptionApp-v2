"""
main.py — EncryptionApp v2 entry point.

Run with:
    python main.py
"""

from app.gui.app_window import AppWindow


def main() -> None:
    app = AppWindow()
    app.mainloop()


if __name__ == "__main__":
    main()
