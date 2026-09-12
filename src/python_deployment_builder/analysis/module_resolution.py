"""Shared bounded physical locations for local import/package identities.

No code is imported. Package-dir mappings use exact/longest-parent precedence;
otherwise candidates follow the supplied source-root order. Callers decide
whether they need a package directory, a module, or initializer promotion.
"""

from pathlib import Path


def safe_local_path(path: Path, root: Path) -> bool:
    """Reject symlink leaves and any resolved escape from the repository."""

    if path.is_symlink():
        return False
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def module_locations(
    root: Path,
    module: str,
    source_roots: list[str],
    package_directories: dict[str, str] | None = None,
) -> list[Path]:
    """Return safe unsuffixed module/package locations, without executing imports."""

    if not module or not all(part.isidentifier() for part in module.split(".")):
        return []
    mappings = package_directories or {}
    parents = [key for key in mappings if key and (module == key or module.startswith(key + "."))]
    if parents:
        parent = max(parents, key=lambda key: len(key.split(".")))
        remainder = module.split(".")[len(parent.split(".")) :]
        candidates = [root / mappings[parent] / Path(*remainder)]
    elif "" in mappings:
        candidates = [root / mappings[""] / Path(*module.split("."))]
    else:
        candidates = [
            root / source_root / Path(*module.split("."))
            for source_root in source_roots
            if (root / source_root).is_dir() and safe_local_path(root / source_root, root)
        ]
    return list(dict.fromkeys(path for path in candidates if safe_local_path(path, root)))


def module_resource_roots(
    root: Path,
    module: str,
    source_roots: list[str],
    package_directories: dict[str, str] | None = None,
) -> list[Path]:
    """Resolve Python 3.12 explicit files() anchors to one importable container.

    At a physical location a regular package wins over a same-named .py module.
    Namespace directories are considered only in the absence of a concrete
    package/module, matching the import system's namespace fallback rule.
    """

    namespaces: list[Path] = []
    for location in module_locations(root, module, source_roots, package_directories):
        initializer = location / "__init__.py"
        module_file = location.with_suffix(".py")
        if initializer.is_file():
            return [location] if safe_local_path(initializer, root) else []
        if module_file.is_file():
            return [module_file.parent] if safe_local_path(module_file, root) else []
        if location.is_dir():
            namespaces.append(location)
    return namespaces
