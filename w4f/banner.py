"""w4f startup banner — "Rebel" figlet font (patorjk taag style, x=none).

The three glyphs for "w4f" are embedded as pre-rendered rows (DOS Rebel /
patorjk "Rebel", 11-row font, full-width x=none layout). Per-letter ANSI
colors: w = red, 4 = default, f = blue. No external font file or figlet
dependency — pure stdlib, works anywhere.
"""

from __future__ import annotations

# Each glyph: 11 rows, trailing '@' endmarks already stripped, hardblank '$'
# replaced with space. Kept verbatim from DOS Rebel.flf so the output matches
# patorjk.com/software/taag with f=Rebel&x=none.
_W = [
    "                ",
    "                ",
    " █████ ███ █████",
    "░░███ ░███░░███ ",
    " ░███ ░███ ░███ ",
    " ░░███████████  ",
    "  ░░████░████   ",
    "   ░░░░ ░░░░    ",
    "                ",
    "                ",
    "                ",
]
_4 = [
    " █████ █████ ",
    "░░███ ░░███  ",
    " ░███  ░███ █",
    " ░███████████",
    " ░░░░░░░███░█",
    "       ░███░ ",
    "       █████ ",
    "      ░░░░░  ",
    "             ",
    "             ",
    "             ",
]
_F = [
    "    ██████ ",
    "   ███░░███",
    "  ░███ ░░░ ",
    " ███████   ",
    "░░░███░    ",
    "  ░███     ",
    "  █████    ",
    " ░░░░░     ",
    "           ",
    "           ",
    "           ",
]

# ANSI colors
_RED = "\033[31m"
_BLUE = "\033[34m"
_RESET = "\033[0m"

_GLYPHS = {"w": _W, "4": _4, "f": _F}
_COLORS = {"w": _RED, "4": "", "f": _BLUE}

_ROWS = 11


def render_banner(text: str = "w4f", colors: dict | None = None) -> str:
    """Render the Rebel banner. Unknown chars render as blank columns.

    colors: optional {char: ansi_code} override; default w=red, f=blue.
    """
    col = dict(_COLORS)
    if colors:
        col.update(colors)
    lines = [""] * _ROWS
    for ch in text:
        glyph = _GLYPHS.get(ch)
        if glyph is None:
            for i in range(_ROWS):
                lines[i] += " " * 8
            continue
        code = col.get(ch, "")
        for i in range(_ROWS):
            row = glyph[i]
            lines[i] += (code + row + _RESET) if code else row
    # Trim fully-blank leading/trailing rows for a tight banner.
    start = next((i for i, l in enumerate(lines) if l.strip()), 0)
    end = next((i for i in range(_ROWS - 1, -1, -1) if lines[i].strip()), _ROWS - 1)
    return "\n".join(lines[start : end + 1])


BANNER = render_banner()


def print_banner(stream=None) -> None:
    """Print the banner; stream defaults to stdout."""
    import sys

    (stream or sys.stdout).write(BANNER + "\n")
