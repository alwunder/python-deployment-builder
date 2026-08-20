import importlib.util


def map_available() -> bool:
    return importlib.util.find_spec("webview") is not None


def show_map() -> None:
    import webview

    webview.start(gui="edgechromium")


def main() -> None:
    pass
