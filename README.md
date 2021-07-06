![](https://img.shields.io/pypi/v/skjold?color=black&label=PyPI&style=flat-square)
![](https://img.shields.io/github/workflow/status/twu/skjold/Python%20Package/master?color=black&label=Tests&style=flat-square)
![](https://img.shields.io/pypi/status/skjold?color=black&style=flat-square)
![](https://img.shields.io/pypi/pyversions/skjold?color=black&logo=python&logoColor=white&style=flat-square)
![](https://img.shields.io/pypi/l/skjold?color=black&label=License&style=flat-square)
![](https://img.shields.io/pypi/dm/skjold?color=black&label=Downloads&style=flat-square)
[![](https://api.codeclimate.com/v1/badges/9f756df1ff145e6004a7/maintainability)](https://codeclimate.com/github/twu/skjold/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/9f756df1ff145e6004a7/test_coverage)](https://codeclimate.com/github/twu/skjold/test_coverage)

```
        .         .    .      Skjold /skjɔl/
    ,-. | , . ,-. |  ,-|
    `-. |<  | | | |  | |      Security audit python project dependencies
    `-' ' ` | `-' `' `-´      against several security advisory databases.
           `'
```

## Introduction
It currently supports fetching advisories from the following sources:

| Source | Name | Notes |
| ------:|:----:|:------|
| [GitHub Advisory Database](https://github.com/advisories) | `github` | |
| [PyUP.io safety-db](https://github.com/pyupio/safety-db) | `pyup` | |
| [GitLab gemnasium-db](https://gitlab.com/gitlab-org/security-products/gemnasium-db) | `gemnasium` | |
| [PYPA Advisory Database](https://github.com/pypa/advisory-db) | `pypa` | **Experimental!** Only supports `ECOSYSTEM` and `SEMVER`! |
| [OSV.dev Database](https://osv.dev) | `osv` | **Experimental!** Only supports `ECOSYSTEM` and `SEMVER`!<br/> Sends package information to [OSV.dev](https://osv.dev) API. |


No source is enabled by default! Individual sources can be enabled by setting `sources` list (see [Configuration](#configuration)). There is (currently) no de-duplication meaning that using all of them could result in _a lot_ of duplicates.

## Motivation
Skjold was initially created for myself to replace `safety`. ~Which appears to no longer receive monthly updates (see [pyupio/safety-db #2282](https://github.com/pyupio/safety-db/issues/2282))~. I wanted something I can run locally and use for my local or private projects/scripts.

I currently also use it during CI builds and before deploying/publishing containers or packages.

## Installation
`skjold` can be installed from either [PyPI](https://pypi.org/project/skjold/) or directly from [Github](https://github.com/twu/skjold) using `pip`:

```sh
pip install skjold                                        # Install from PyPI
pip install git+https://github.com/twu/skjold.git@vX.X.X  # Install from Github
```

This should provide a script named `skjold` that can then be invoked. See [Usage](#usage).

## Usage
```sh
$ pip list --format=freeze | skjold -v audit --sources gemnasium -
```

When running `audit` one can either provide a path to a _frozen_ `requirements.txt`, a `poetry.lock` or a `Pipfile.lock` file. Alternatively, dependencies can also be passed in via `stdin`  (formatted as `package==version`).

`skjold` will maintain a local cache (under `cache_dir`) that will expire automatically after `cache_expires` has passed. The `cache_dir` and `cache_expires` can be adjusted by setting them in  `tools.skjold` section of the projects `pyproject.toml` (see [Configuration](#configuration) for more details). The `cache_dir`will be created automatically, and by default unless otherwise specified will be located under `$HOME/.skjold/cache`.

For further options please read `skjold --help` and/or `skjold audit --help`.

### Examples

All examples involving `github` assume that `SKJOLD_GITHUB_API_TOKEN` is already set (see [Github](#github)).

```sh
# Using pip list. Checking against GitHub only.
$ pip list --format=freeze | skjold audit -s github -

# Be verbose. Read directly from supported formats.
$ skjold -v audit requirements.txt
$ skjold -v audit poetry.lock
$ skjold -v audit Pipenv.lock

# Using poetry.
$ poetry export -f requirements.txt | skjold audit -s github -s gemnasium -s pyup -

# Using poetry, format output as json and pass it on to jq for additional filtering.
$ poetry export -f requirements.txt | skjold audit -o json -s github - | jq '.[0]'

# Using Pipenv, checking against Github
$ pipenv run pip list --format=freeze | skjold audit -s github -

# Checking a single package via stdin against Github and format findings as json.
$ echo "urllib3==1.23" | skjold audit -o json -r -s github -
[
  {
    "severity": "HIGH",
    "name": "urllib3",
    "version": "1.23",
    "versions": "<1.24.2",
    "source": "github",
    "summary": "High severity vulnerability that affects urllib3",
    "references": [
      "https://nvd.nist.gov/vuln/detail/CVE-2019-11324"
    ],
    "url": "https://github.com/advisories/GHSA-mh33-7rrq-662w"
  }
]

# Checking a single package via stdin against Gemnasium and report findings (`-o cli`).
$ echo "urllib3==1.23" | skjold audit -o cli -r -s gemnasium -

urllib3==1.23 (<=1.24.2) via gemnasium

CRLF injection. In the urllib3 library for Python, CRLF injection is possible
if the attacker controls the request parameter.
https://nvd.nist.gov/vuln/detail/CVE-2019-11236
--

urllib3==1.23 (<1.24.2) via gemnasium

Weak Authentication Caused By Improper Certificate Validation. The urllib3
library for Python mishandles certain cases where the desired set of CA
certificates is different from the OS store of CA certificates, which results
in SSL connections succeeding in situations where a verification failure is the
correct outcome. This is related to use of the `ssl_context`, `ca_certs`, or
`ca_certs_dir` argument.
https://nvd.nist.gov/vuln/detail/CVE-2019-11324
--

urllib3==1.23 (<1.25.9) via gemnasium

Injection Vulnerability. urllib3 allows CRLF injection if the attacker controls
the HTTP request method, as demonstrated by inserting `CR` and `LF` control
characters in the first argument of `putrequest()`. NOTE: this is similar to
CVE-2020-26116.
https://nvd.nist.gov/vuln/detail/CVE-2020-26137
--
```

#### Ignore Findings

Findings can be ignored either by manually adding an entry using the sources identifier to a file named `.skjoldignore` (See [Example](https://github.com/twu/skjold/blob/master/.skjoldignore)) or by using in the CLI. Below are a few possible usage examples.

```
# Ignore PYSEC-2020-148 finding from PyPA source until a certain date with a specific reason.
$ skjold ignore urllib3 PYSEC-2020-148 --reason "Very good reason." --expires "2021-01-01T00:00:00+00:00"
Ignore urllib3 in PYSEC-2020-148 until 2021-01-01 00:00:00+00:00?
Very good reason.
--
Add to '.skjoldignore'? [y/N]: y

# Ignore PYSEC-2020-148 finding from PyPA source for 7 days with "No immediate remediation." reason.
$ skjold ignore urllib3 PYSEC-2020-148
Ignore urllib3 in PYSEC-2020-148 until ...?
No immediate remediation.
--
Add to '.skjoldignore'? [y/N]: y

# Audit `poetry.lock` using a custom `.skjoldignore` file location via `ENV`...
$ SKJOLD_IGNORE_FILE=<path-to-file> skjold audit -s pyup poetry.lock

# ... or using -i/--ignore-file
$ skjold audit -s pyup -i <path-to-file> poetry.lock
```

### Configuration

`skjold` can read its configuration from the `tools.skjold` section of a projects  `pyproject.toml`. Arguments specified via the command-line should take precedence over any configured or default value.

```toml
[tool.skjold]
sources = ["github", "pyup", "gemnasium"]  # Sources to check against.
report_only = true                         # Report only, always exit with zero.
report_format = 'json'                     # Output findings as `json`. Default is 'cli'.
cache_dir = '.skjold_cache'                # Cache location (default: `~/.skjold/cache`).
cache_expires = 86400                      # Cache max. age.
ignore_file = '.skjoldignore'              # Ignorefile location (default `.skjoldignore`).
verbose = true                             # Be verbose.
```

To take a look at the current configuration / defaults run:
```shell
$ skjold config
sources: ['pyup', 'github', 'gemnasium']
report_only: True
report_format: json
verbose: False
cache_dir: .skjold_cache
cache_expires: 86400
ignore_file = '.skjoldignore'
```

#### Github

For the `github` source to work you'll need to provide a Github API Token via an `ENV` variable named `SKJOLD_GITHUB_API_TOKEN`. You can [create a new Github Access Token here](https://github.com/settings/tokens). You *do not* have to give it *any* permissions as it is only required to query the [GitHub GraphQL API v4](https://developer.github.com/v4/) API.

### Version Control Integration
To use `skjold` with the excellent [pre-commit](https://pre-commit.com/) framework add the following to the projects `.pre-commit-config.yaml` after [installation](https://pre-commit.com/#install).

```yaml
repos:
  - repo: https://github.com/twu/skjold
    rev: vX.X.X
    hooks:
    - id: skjold
      verbose: true  # Important if used with `report_only`, see below.
```

After running `pre-commit install` the hook should be good to go. To configure `skjold` in this scenario I recommend adding the entire configuration to the projects `pyproject.toml` instead of manipulating the hook `args`. See this projects [pyproject.toml](./pyproject.toml) for an example.

> **Important!**: When using `skjold` as a `pre-commit`-hook it only gets triggered if you want to commit changed dependency files (e.g. `Pipenv.lock`, `poetry.lock`, `requirements.txt`,...).
> It will not continuously check your dependencies on _every_ commit!

You could run `pre-commit run skjold --all-files` manually in your workflow/scripts or run `skjold` manually.
If you have a better solution please let me know!

> **Important!**: If you use `report_only` in any way make sure that you add `verbose: true` to your hook configuration
otherwise `pre-commit` won't show you any output since the hook is always returning with a zero exit code due
to `report_only` being set!

## Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

