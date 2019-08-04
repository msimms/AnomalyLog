from setuptools import setup, find_packages

requirements = ['flask', 'mako', 'slacker']

setup(
    name='anomalylog',
    version='0.1.0',
    description='',
    url='https://github.com/msimms/AnomalyLog',
    author='Mike Simms',
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    install_requires=requirements,
)
