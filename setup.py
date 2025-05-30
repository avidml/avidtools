from setuptools import find_packages, setup
  
setup(
    name='avidtools',
    version='0.1.3',
    description='Developer tools for AVID',
    author='Subho Majumdar',
    author_email='info@avidml.org',
    packages=find_packages(exclude=['.']),
    install_requires=[
        'pydantic',
        'typing;python_version<"3.5"',
        'typing_extensions',
        'datetime',
        'nvdlib'
    ],
)
