import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="instantpy",
    version="0.0.2",
    author="Michael Wood",
    author_email="mww012@gmail.com",
    description="A Python wrapper for Aruba Instant REST API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mww012/instantpy.git",
    packages=setuptools.find_packages(exclude=['.vscode/']),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6'
)