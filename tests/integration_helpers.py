"""Independent path/display and CLI helpers, without scanner implementation imports."""

from pathlib import Path
from urllib.parse import quote


def displayed_path(path):
    path = Path(path)
    if path.is_relative_to(Path.cwd()):
        return str(path.relative_to(Path.cwd()))
    return str(path)


def displayed_uri(path):
    """SARIF 2.1.0 uses URI references, not platform filesystem strings."""
    displayed = Path(displayed_path(path))
    return displayed.as_uri() if displayed.is_absolute() else quote(displayed.as_posix(), safe="/")


def cli(args):
    from fstec_lint.cli import main

    try:
        return main(args)
    except SystemExit as error:
        return error.code


def write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path
