"""Entry point for running: python -m scanner"""

from scanner.app import SafeStayApp


def main() -> None:
    app = SafeStayApp()
    app.run()


if __name__ == "__main__":
    main()
