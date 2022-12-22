import setuptools

long_description = """# Dettectinator
Dettectinator - The Python library to your [DeTT&amp;CT](https://github.com/rabobank-cdc/DeTTECT) YAML files.

Dettectinator is built to be included in your SOC automation tooling. It can be included as a Python library or it can be used via the command line.

Dettectinator provides plugins to read detections from your SIEM or EDR and create/update the DeTT&CT YAML file, so that you can use it to visualize your ATT&CK detection coverage in the ATT&CK Navigator.

Currently de CLI is limited to processing detections through these plugins, the library can also be used for processing data sources.

See the [documentation](https://github.com/siriussecurity/dettectinator) for more information on how to use it."""

setuptools.setup(
    name="dettectinator",
    version="1.1.0",
    author="Sirius Security",
    description="Dettectinator - The Python library to your DeTT&CT YAML files.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/siriussecurity/dettectinator",
    project_urls={
        "Documentation": "https://github.com/siriussecurity/dettectinator/wiki",
        "Code": "https://github.com/siriussecurity/dettectinator",
        "Issue tracker": "https://github.com/siriussecurity/dettectinator/issues",
    },
    keywords="mitre attack dettect soc threat hunting",
    packages=setuptools.find_packages(exclude=["examples", "tests"]),
    install_requires=["requests", "ruamel.yaml", "attackcti", "python-dateutil", "msal", "stix2", "openpyxl", "suricataparser", "addonfactory-splunk-conf-parser-lib", "pandas", "anyascii"],
    license='GPL3',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Operating System :: OS Independent',
        'Topic :: Security',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3.9'
    ],
)