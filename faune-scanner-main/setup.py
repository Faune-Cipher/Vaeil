from setuptools import setup, find_packages

setup(
    name="vaeil",
    version="1.0.0",
    author="Faune",
    description="TCP port scanner with CVE detection and HTML reporting",
    packages=find_packages(),
    install_requires=[
        "requests",
        "rich",
    ],
    entry_points={
        "console_scripts": [
            "vaeil=vaeil.scanner:main",
        ],
    },
    python_requires=">=3.8",
)
