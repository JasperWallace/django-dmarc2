"""Managing DMARC aggregate and feedback reports"""
import codecs

from setuptools import setup


def get_long_description():
    """Reads the main README.rst to get the program's long description"""
    with codecs.open('README.rst', encoding='utf-8') as f_readme:
        return f_readme.read()


setup(
    name='django-dmarc',
    version='0.5.1',
    packages=['dmarc'],
    include_package_data=True,
    license='BSD',
    description='Managing DMARC aggregate and feedback reports',
    long_description=get_long_description(),
    url='http://p-o.co.uk/tech-articles/django-dmarc/',
    download_url='https://pypi.python.org/pypi/django-dmarc',
    author='Alan Hicks',
    author_email='ahicks@p-o.co.uk',
    install_requires=[
        'django>=1.8,<2.0',
        'pytz',
        'six>=1.10,<2.0',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Office/Business',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords='dmarc email spf dkim',
)
