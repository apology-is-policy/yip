import re
import unicodedata


def terminal_rows(data, width, height):
    """Apply tcell's cursor-addressed cell updates to a fixed-size screen."""
    cells = [[' '] * width for _ in range(height)]
    x = y = 0
    tokens = r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[ -?]*[@-~]|\x1b\([AB0]|.'
    for token in re.findall(tokens, data.decode(errors='replace'), re.S):
        if token.startswith('\x1b'):
            if token.startswith('\x1b[') and token.endswith('H'):
                coords = token[2:-1].split(';')
                y = int(coords[0] or 1) - 1
                x = int(coords[1] or 1) - 1 if len(coords) > 1 else 0
        elif token == '\r':
            x = 0
        elif token == '\n':
            y += 1
        elif token.isprintable():
            if 0 <= y < height and 0 <= x < width:
                cells[y][x] = token
            x += 2 if unicodedata.east_asian_width(token) in ('W', 'F') else 1
    return [''.join(row) for row in cells]
