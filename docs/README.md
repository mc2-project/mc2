# Documentation Development

To build the documentation locally, install the `sphinx` and `sphinx-argparse` Python packages, then build the documentation from this directory.

```sh
# In opaque-client/docs/ directory
sudo apt-get install -y enchant
pip3 install numpydoc sphinx sphinx-argparse sphinx-copybutton sphinxcontrib-spelling
make html
```

To view the documentation in a browser, open the generated `index.html` file.

```sh
open _build/html/index.html
```

To run spellcheck:

```sh
sphinx-build -b spelling . _build
```
To add correctly spelled words to the dictionary (and prevent spellcheck errors on these words), modify `docs/spelling_wordlist.txt`.
