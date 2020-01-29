![](https://img.shields.io/pypi/v/skjold?color=black&label=PyPI&style=flat-square)
![](https://img.shields.io/pypi/status/skjold?color=black&style=flat-square)
![](https://img.shields.io/pypi/pyversions/skjold?color=black&logo=python&logoColor=white&style=flat-square)
![](https://img.shields.io/pypi/l/skjold?color=black&label=License&style=flat-square)

```
        .         .    .      Skjold /skjɔl/
    ,-. | , . ,-. |  ,-|
    `-. |<  | | | |  | |      Security audit python project dependencies
    `-' ' ` | `-' `' `-´      against several security advisory databases.
           `'
```

## Introduction
It currently supports fetching advisories from the following sources:

- [GitHub Advisory Database](https://github.com/advisories)
- [PyUP.io safety-db](https://github.com/pyupio/safety-db)
- [GitLab gemnasium-db](https://gitlab.com/gitlab-org/security-products/gemnasium-db)

Unless configured explicitly `skjold` will run the given packages against all of them. There is (currently) no de-duplication meaning that using all of them could result in _a lot_ of duplicates. Source can be added disabled by setting `sources` list (see [Configuration](#configuration)).

## Motivation
Skjold was initially created for myself to replace `safety`. Which appears to no longer receive monthly updates (see [pyupio/safety-db #2282](https://github.com/pyupio/safety-db/issues/2282)). I wanted something I can run locally and use for my local or private projects/scripts.

I currently also use it during CI builds and before deploying/publishing containers or packages.

## Installation
`skjold` can be installed from either [PyPI](https://pypi.org/project/beautifulsoup4/) or directly from [Github](https://github.com/twu/skylt) using `pip`:

```sh
pip install git+https://github.com/twu/skjold.git@vX.X.X  # Install from Github
pip install skjold                                        # Install from PyPI
```

This should provide a script named `skjold` that can then be invoked. See [Usage](#usage).

## Usage
```sh
$ pip freeze | skjold -v audit --source gemnasium -
```

When running `audit` one can either provide a path to a _frozen_ `requirements.txt`, a `poetry.lock` or a `Pipfile.lock` file. Alternatively, dependencies can also be passed in via `stdin`  (formatted as `package==version`).

`skjold` will maintain a local cache (under `cache_dir`) that will expire automatically after `cache_expires` has passed. The `cache_dir` and `cache_expires` can be adjusted by setting them in  `tools.skjold` section of the projects `pyproject.toml` (see [Configuration](#configuration) for more details). The `cache_dir`will be created automatically, and by default unless otherwise specified will be located under `$HOME/.skjold/cache`.

For further options please read `skjold --help` and/or `skjold audit --help`.

### Examples

All examples involving `github` assume that `SKJOLD_GITHUB_API_TOKEN` is already set (see [Github](#github)).

```sh
# Using pip freeze. Checking against GitHub only.
$ pip freeze | skjold audit -s github -

# Be verbose. Read directly from supported formats.
$ skjold -v audit requirements.txt
$ skjold -v audit poetry.lock
$ skjold -v audit Pipenv.lock

# Using poetry.
$ poetry export -f requirements.txt | skjold audit -s github -s gemnasium -s pyup -

# Using poetry, format output as json and pass it on to jq for additional filtering.
$ poetry export -f requirements.txt | skjold audit -o json -s github - | jq '.[0]'

# Using Pipenv, checking against Github
$ pipenv run pip freeze | skjold audit -s github -

# Checking a single package via stdin against Github and format findings as json.
echo "urllib3==1.23" | skjold audit -o json -r -s github -
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
```

### Configuration

`skjold` can read its configuration from the `tools.skjold` section of a projects  `pyproject.toml`. Arguments specified via the command-line should take precedence over any configured or default value.

```toml
[tool.skjold]
sources = ["github", "pyup", "gemnasium"]  # Sources to check against.
report-only = true                         # Report only, always exit with zero.
report-format = 'json'                     # Output findings as `json`. Default is 'cli'.
cache_dir = '.skylt_cache'                 # Cache location (default: `~/.skjold/cache`).
cache_expires = 86400                      # Cache max. age.
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
      name: "skjold: Auditing dependencies for known vulnerabilities."
      entry: skjold audit
      language: python
      language_version: python3
      files: ^(poetry\.lock|Pipfile\.lock|requirements.*\.txt)$
```

After running `pre-commit install` the hook should be good to go. To configure `skjold` in this scenario I recommend to add the entire configuration to the projects `pyproject.toml` instead of manipulating the hook `args`. See this projects [pyproject.toml](./pyproject.toml) for an example.

## Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

