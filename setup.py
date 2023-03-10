from setuptools import setup
  
setup(
    name='avidtools',
    version='0.1',
    description='Developer tools for AVID',
    author='Subho Majumdar',
    author_email='avid.mldb@gmail.com',
    packages=['avidtools'],
    install_requires=[
        'pydantic',
#         'enum',
        'typing',
        'typing_extensions',
        'datetime'
    ],
)