import os
from setuptools import setup, find_packages

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='auth_microservice',
    version='0.1',
    description='service to help management of auth tokens',
    author='Kyle Ferriter',
    author_email='kferriter@renci.org',
    url='https://github.com/heliumdatacommons/auth_microservice',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Django',
        'django-extensions',
        'pycrypto',
        'requests',
        'pyjwt',
    ],
    tests_require=[
        'pyjwkest>=1.3.0',
        'mock>=2.0.0',
    ],
)
