#!/usr/bin/env python
from setuptools import setup, find_packages

with open('README.md') as readme:
    readme = readme.read()

setup(
    name="django-clamav",
    version='0.4.0',
    keywords="python, django, clamav, antivirus, scanner, virus, libclamav, clamd",
    description="django-clamav is a django integration with Clamd (Clamav daemon).",
    url="https://github.com/QueraTeam/django-clamav",
    package_dir={'': 'src'},
    packages=find_packages('src', exclude="tests"),
    package_data={'django_clamav': [
        'locale/*/LC_MESSAGES/*.po',
        'locale/*/LC_MESSAGES/*.mo',
    ]},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Framework :: Django",
        "Framework :: Django :: 1.8",
        "Framework :: Django :: 1.10",
        "Framework :: Django :: 1.11",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
    ],
    install_requires=(
        "clamd",
        "Django>=1.4",
    ),
    tests_require=(
        "nose==1.3.7",
    ),
    test_suite='nose.collector',
    zip_safe=False,
    include_package_data=True,
)
