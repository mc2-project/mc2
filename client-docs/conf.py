# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys

curr_path = os.path.dirname(os.path.abspath(os.path.expanduser(__file__)))
libpath = os.path.join(curr_path, "../python-package/")
sys.path.insert(0, libpath)
sys.path.insert(0, curr_path)


# -- Project information -----------------------------------------------------

project = "MC<sup>2</sup> Client"
copyright = "2021, MC2 Team"
author = "MC2 Team"

# The full version, including alpha/beta/rc tags
#  release = "0.0.1"


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named "sphinx.ext.*") or your custom
# ones.
extensions = [
    "numpydoc",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosectionlabel",
    "sphinxarg.ext",
    "sphinx_copybutton",
    "sphinxcontrib.spelling",
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "furo"

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
#
html_theme_options = {
    "light_css_variables": {
        "color-brand-primary": "#00B0FF",
        "color-brand-content": "#00B0FF",
        "color-admonition-background": "#3681da",
    },
}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]

# Correctly spelled words to be ignored during spellcheck
spelling_word_list_filename = "spelling_wordlist.txt"

# Emit misspelling as Sphinx warning
spelling_warning = True
