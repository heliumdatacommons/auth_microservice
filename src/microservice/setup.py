#!/usr/bin/env python3.6
from setuptools import setup, find_packages

setup(
    name='auth_microservice',
    version='0.1',
    description='service to help management of auth tokens',
    author='Kyle Ferriter',
    author_email='kferriter@renci.org',
    url='https://github.com/heliumdatacommons/auth_microservice',
    packages=find_packages(),
    install_requires=[
        'wheel',
        'Django',
        'pycrypto',
        'requests',
        'psycopg2',
    ],
    include_package_data=True,
)
