from setuptools import setup, find_packages

with open("requirements.txt") as f:
    required = f.read().splitlines()

setup(
    name='openrecon',
    version='1.0.2',
    author='Stanislav Istyagin (@clevergod)',
    description='🛰️ Asynchronous Reconnaissance Tool for Domain Enumeration and Subdomain Discovery',
    packages=find_packages(),
    install_requires=required,
    entry_points={
        'console_scripts': [
            'openrecon=openrecon.openrecon:main',
        ],
    },
    include_package_data=True,
    python_requires='>=3.8',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
    ],
)