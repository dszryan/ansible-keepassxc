from setuptools import setup, find_packages

setup(
    name="ansible_collections.dszryan.keepass",
    version="0.0.0.dev0",
    packages=find_packages(),
    namespace_packages=['ansible_collections.dszryan.keepass'],
    package_dir={"ansible_collections.dszryan.keepass": "ansible_collections.dszryan.keepass"}
)
