# nmapscanner

Wrap NMAP and scan port dumping data to arbitrary data stores.

# Install

From GitHub:
- `pip install git+https://github.com/cooperlees/nmapscanner`

# Usage

TBA

# Development

```console
python3 -m venv [--upgrade-deps] /tmp/tn
/tmp/tn/bin/pip install -e .
````

## Run Tests

For testing we use [ptr](https://github.com/facebookincubator/ptr/).

```console
/tmp/tn/bin/ptr [-k] [--print-cov] [--debug] [--venv]
```

- `-k`: keep testing venv ptr creates
- `--print-cov`: handy to see what coverage is on all files
- `--debug`: Handy to see all commands run so you can run a step manually
- `--venv`: Reuse an already created venv (much faster to launch + run all CI)
