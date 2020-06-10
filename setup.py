"""Managing DMARC aggregate and feedback reports"""
from codecs import open
from os import path

from setuptools import setup

here = path.abspath(path.dirname(__file__))
# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    name='django-dmarc2',
    version='0.5.2',
    packages=['dmarc'],
    include_package_data=True,
    license='BSD',
    description='Managing DMARC aggregate and feedback reports',
    long_description=long_description,
    url='https://github.com/webtweakers/django-dmarc',
    download_url='https://pypi.python.org/pypi/django-dmarc2',
    author='Alan Hicks',
    author_email='ahicks@p-o.co.uk',
    install_requires=['django>=2.2.0,<2.3.0', 'django-netfields'],
    python_requires='>=3.7.0',
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 2.0',
        'Framework :: Django :: 2.1',
        'Framework :: Django :: 2.2',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Office/Business',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords='dmarc email spf dkim',
)
