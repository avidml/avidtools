from setuptools import find_packages, setup
  
setup(
    name='avidtools',
    version='0.2.0',
    description='Developer tools for AVID',
    author='Subho Majumdar',
    author_email='info@avidml.org',
    packages=find_packages(exclude=['.']),
    python_requires='>=3.12',
    install_requires=[
        'pydantic>=2.11.5',
        'typing-extensions>=4.13.2',
        'datetime>=5.5',
        'nvdlib>=0.8.1'
    ],
)
