"""Sphinx configuration for fantasm."""

from datetime import datetime
from importlib.metadata import version as get_version

# -- Project information -----------------------------------------------------

project = "fantasm"
author = "Robert Smallshire"
copyright = f"{datetime.now().year}, {author}"

# `release` is the full version string, `version` the short (major.minor).
release = get_version("fantasm")
version = ".".join(release.split(".")[:2])


# -- General configuration ---------------------------------------------------

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",       # Google / NumPy-style docstrings
    "sphinx.ext.viewcode",       # "[source]" links next to each documented object
    "sphinx.ext.intersphinx",
    "sphinx_copybutton",         # copy-to-clipboard on code blocks
    "sphinx_click",              # auto-document Click command groups
    "myst_parser",               # render the Markdown internals/ archive
]

# Docstrings throughout the code use Google style.
napoleon_google_docstring = True
napoleon_numpy_docstring = False

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "click": ("https://click.palletsprojects.com/en/stable/", None),
    "networkx": ("https://networkx.org/documentation/stable/", None),
}

# `internals/` is reachable through the "Project history" toctree but
# we still want a clean default exclude list otherwise.
templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# Source suffixes — RST primarily, MyST for the historical Markdown.
source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}


# -- Options for HTML output -------------------------------------------------

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]

html_logo = "_static/logo.svg"
html_favicon = "_static/logo.png"

html_theme_options = {
    "navigation_depth": 3,
    "collapse_navigation": False,
    "sticky_navigation": True,
    "titles_only": False,
}


# -- sphinx-click ------------------------------------------------------------

# `:nested: full` documents every subcommand recursively beneath the
# top-level group. Without it, only the parent group surfaces and the
# 17 subcommands stay invisible.


# -- autodoc -----------------------------------------------------------------

autodoc_default_options = {
    "members": True,
    "show-inheritance": True,
    "undoc-members": False,
}
autodoc_typehints = "description"
autodoc_member_order = "bysource"
