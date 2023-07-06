from setuptools import find_packages, setup
  
setup(
    name='avidtools',
    version='0.1.1.1',
    description='Developer tools for AVID',
    author='Subho Majumdar',
    author_email='info@avidml.org',
    packages=find_packages(exclude=['.']),
    install_requires=[
        'pydantic==1.10.4',
#         'enum',
        'typing',
        'typing_extensions',
        'datetime',
        'nvdlib'
    ],
)