vulnerabilities - framework to manipulate vulnerabilities
=========================================================

|pypi| |build| |coverage|


.. |pypi| image:: https://img.shields.io/pypi/v/vulnerabilities
    :target: https://pypi.org/project/vulnerabilities/
    :alt: PyPI Version

.. |build| image:: https://github.com/damiencarol/vulnerabilities/actions/workflows/build.yml/badge.svg
    :target: https://github.com/damiencarol/vulnerabilities/actions/workflows/build.yml
    :alt: Build Status

.. |coverage| image:: https://codecov.io/gh/damiencarol/vulnerabilities/branch/main/graph/badge.svg?token=03PXOUG6HI
    :target: https://codecov.io/gh/damiencarol/vulnerabilities
    :alt: Code coverage

The `vulnerabilities` module provides functions to manipulate security reports
from various different tools.

Installation
============
Module `vulnerabilities` can be installed from PyPI using `pip` ::

    pip install vulnerabilities

Download
========
vulnerabilities is available on PyPI
https://pypi.org/project/vulnerabilities/

The documentation is hosted at:
https://vulnerabilities.readthedocs.io/en/stable/

Code
====
The code and issue tracker are hosted on GitHub:
https://github.com/damiencarol/vulnerabilities/

Features
========

* Load reports from different tools
  - Anchore Grype
  - Bandit (https://github.com/PyCQA/bandit)
  - CycloneDX (https://cyclonedx.org/)
  - SARIF (https://www.oasis-open.org/committees/sarif/)

Quick example
=============
Here's a snapshot, just to give an idea about the power of the
package. For more examples, look at the documentation.

Suppose you want to read data from Bandit in pandas.
here is the code:

    >>> from vulnerabilities.tools.bandit.parser import BanditParser
    >>> findings = BanditParser().get_findings(open("tests/scans/bandit/report1.json"), None)
    >>> import pandas as pd
    >>> df = pd.DataFrame.from_dict(findings)
    >>> df.loc[:,['title','severity','file_path','line']]
                                                   title severity                  file_path  line
    0  Using xml.sax to parse untrusted XML data is k...      Low  scripts/bandit/payload.py     1
    1  Use of insecure MD2, MD4, MD5, or SHA1 hash fu...   Medium  scripts/bandit/payload.py     5
    2  Use of insecure MD2, MD4, MD5, or SHA1 hash fu...   Medium  scripts/bandit/payload.py     9
    3  Use of assert detected. The enclosed code will...      Low  scripts/bandit/payload.py    13

All parsers will produce the same data structure with the same attributes.

Contributing
============

We welcome many types of contributions - bug reports, pull requests (code, infrastructure or documentation fixes). For more information about how to contribute to the project, see the ``CONTRIBUTING.md`` file in the repository.


Author
======
The vulnerabilities module was written by Damien Carol <damien.carol@gmail.com>
in 2021.

It is maintained by:

* Damien Carol <damien.carol@gmail.com> 2021-

License
=======

All contributions released under the `BSD 3-Clause License <https://opensource.org/licenses/BSD-3-Clause>`_. 
