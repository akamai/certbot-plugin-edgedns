#from pip import __version__ as pip_version
from setuptools import find_packages
from setuptools import setup
from setuptools import find_packages

version = "0.1.1"

#print("pip version: {0}".format(pip_version))

install_requires = [
    "acme==4.1.1",
    "certbot==4.1.1",
    "setuptools",
    "requests",
    "mock",
    "urllib3",
    "edgegrid-python==2.0.2",
    "zope.interface",
]

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
]

dependency_links = []

# read the contents of your README file
from os import path

with open("README.rst") as f:
    long_description = f.read()

setup(
    name="certbot-plugin-edgedns",
    version=version,
    description="Akamai Edge DNS Authenticator plugin for Certbot",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    url="https://github.com/akamai/certbot-plugin-edgedns",
    author="Ed Lynes [Akamai Technologies, Inc]",
    author_email="elynes@akamai.com",
    license="Apache License 2.0",
    python_requires=">=3.9, <=3.14",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Plugins",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: System :: Installation/Setup",
        "Topic :: System :: Networking",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    dependency_links=dependency_links,
    packages=find_packages(),
    include_package_data=True,
    keywords=['certbot', 'edgedns',],
    install_requires=install_requires,
    extras_require={
        'docs': docs_extras,
    },
    entry_points={
        "certbot.plugins": [
            "edgedns = certbot_plugin_edgedns.edgedns:Authenticator"
        ]
    },
    test_suite="certbot_edgedns",
)
