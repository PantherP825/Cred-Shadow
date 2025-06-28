#!/usr/bin/env python3
"""
Setup script for CRED-SHADOW SMB Share Secret Scanner
Standalone installation for any Python environment
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="cred-shadow",
    version="1.0.0",
    author="Ankit Pandey",
    description="SMB Share Secret Scanner for Ethical Security Testing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ankitpandey/cred-shadow",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.11",
    install_requires=[
        "impacket>=0.12.0",
        "smbprotocol>=1.15.0", 
        "rich>=14.0.0",
        "colorama>=0.4.6",
        "yara-python>=4.3.0",
        "termcolor>=2.3.0",
        "prettytable>=3.8.0",
        "python-dotenv>=1.0.0",
        "cryptography>=42.0.0",
        "pyasn1>=0.4.8"
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0"
        ]
    },
    entry_points={
        "console_scripts": [
            "cred-shadow=main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)