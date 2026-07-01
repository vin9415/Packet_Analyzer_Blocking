"""ASCII report formatting (Windows-console safe)."""

WIDTH = 62
AUTHOR = "Vinit Kumar Pandey"


def banner(title: str) -> None:
    line = "=" * WIDTH
    print()
    print(line)
    print(f" {title}")
    print(f" by {AUTHOR}")
    print(line)
    print()


def section(title: str) -> None:
    line = "-" * WIDTH
    print(line)
    print(f" {title}")
    print(line)


def row(label: str, value: int | str, width: int = 12) -> None:
    print(f"  {label:<22} {value:>{width}}")
