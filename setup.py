## setup.py file for secret_key_database
from pathlib import Path

from distutils.core import setup

## Get the parent directory of this file
dir_parent = Path(__file__).parent

## Get requirements from requirements.txt
def read_requirements():
    with open(str(dir_parent / "requirements.txt"), "r") as req:
        content = req.read()  ## read the file
        requirements = content.split("\n") ## make a list of requirements split by (\n) which is the new line character

    ## Filter out any empty strings from the list
    requirements = [req for req in requirements if req]
    ## Filter out any lines starting with #
    requirements = [req for req in requirements if not req.startswith("#")]
    ## Remove any commas, quotation marks, and spaces from each requirement
    requirements = [req.replace(",", "").replace("\"", "").replace("\'", "").strip() for req in requirements]

    return requirements
deps_all = read_requirements()


## Get README.md
with open(str(dir_parent / "README.md"), "r") as f:
    readme = f.read()

## Get version number
with open(str(dir_parent / "secret_key_database" / "__init__.py"), "r") as f:
    for line in f:
        if line.startswith("__version__"):
            version = line.split("=")[1].strip().replace("\"", "").replace("\'", "")
            break

setup(
    name='secret_key_database',
    version=version,
    author='Richard Hakim',
    keywords=['cryptography', 'encryption', 'security', 'secret_key_database',],
    license='LICENSE',
    description='A simple Python package for encrypting and decrypting secret keys.',
    long_description=readme,
    long_description_content_type="text/markdown",
    url='https://github.com/RichieHakim/secret_key_database',

    packages=[
        'secret_key_database',
    ],
    
    install_requires=deps_all,
    # extras_require={},
)