#!/usr/bin/env python3
# Copyright (c) 2014-present, Facebook, Inc.

from setuptools import setup


ptr_params = {
    "entry_point_module": "nmapscanner",
    "test_suite": "nmapscanner_tests",
    "test_suite_timeout": 300,
    "required_coverage": {"nmapscanner.py": 60},
    "run_black": True,
    "run_flake8": True,
    "run_mypy": True,
    "run_usort": True,
}


setup(
    name="nmapscanner",
    version="22.1.20",
    description=("Run NMAP Scans - Parse Output - Send results to scuba"),
    py_modules=["nmapscanner", "nmapscanner_tests", "nmapscanner_tests_fixtures"],
    python_requires=">=3.9",
    install_requires=["click", "python-libnmap"],
    entry_points={"console_scripts": ["nmapscanner = nmapscanner:main"]},
    test_suite="nmapscanner_tests",
)
