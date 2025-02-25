from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="securityhub-soc2-analyzer",
    version="0.1.0",
    author="AWS Security",
    author_email="your-email@example.com",
    description="A tool to analyze AWS SecurityHub findings and map them to SOC2 controls",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/securityhub_soc2analysis",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "securityhub-soc2-analyzer=app:cli_handler",
        ],
    },
)
