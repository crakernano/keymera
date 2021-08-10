from setuptools import setup

__version__ = "0.0.0"

setup(
    name='keymera',
    packages=['keymera'],
    version='__version__',
    licence='MIT',
    description='ethical hacking suite',
    authon='CrakerNano',
    author_email='',
    url='',
    downloard_url='',
    keywords='hacking, scanner',
    python_requires='>=2.7',
    classifiers=['Programming Language :: Python',
                 'Programming Language :: Python :: 2.7',
                 'Programming Language :: Python :: 3.6.9'
                 ],
)

try:
    from semantic_release import setup_hook
    setup_hook(sys.argv)
except ImportError:
    pass
