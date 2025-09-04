from setuptools import setup, find_packages

setup(
    name='openrecon',
    version='1.0.0',
    author='Stanislav Istyagin (@clevergod)',
    description='🛰️ Asynchronous Reconnaissance Tool for Domain Enumeration and Subdomain Discovery',
    packages=find_packages(),
    install_requires=[i.strip() for i in open("requirements.txt").readlines()],
    entry_points={
        'console_scripts': [
            'openrecon=openrecon:main',
        ],
    },
    include_package_data=True,
    python_requires='>=3.8',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
    ],
)