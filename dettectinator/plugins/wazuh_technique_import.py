"""
Dettectinator - The Python library to your DeTT&CT YAML files.
Wazuh Rules CSV Plugin
"""

import csv
from collections.abc import Iterable
from argparse import ArgumentParser
import json
import re
from anyascii import anyascii

from .technique_import import TechniqueBase

class TechniqueWazuhCsv(TechniqueBase):
    """
    Import data from a Wazuh rules CSV file, which contains MITRE ATT&CK techniques in the 'mitre' column
    """

    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)
        if 'file' not in self._parameters:
            raise Exception('TechniqueWazuhCsv: "file" parameter is required.')

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        TechniqueBase.set_plugin_params(parser)
        parser.add_argument('--file', help='Path of the Wazuh rules csv file to import', required=True)

    def get_data_from_source(self) -> Iterable:
        """
        Gets the use-case/technique data from the Wazuh rules CSV source.
        :return: Iterable, yields technique, detection, applicable_to
        """
        file = self._parameters['file']
        print(f'Reading Wazuh rules from "{file}"')

        with open(file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Skip rows where mitre field is empty or contains only []
                mitre_field = row.get('mitre', '[]')
                if not mitre_field or mitre_field == '[]':
                    continue

                try:
                    # Parse the mitre field which is stored as a string representation of a list
                    techniques = json.loads(mitre_field.replace("'", '"'))
                    
                    # Get the rule description
                    description = f"[Rule {row.get('ID', 'Unknown')}] {row.get('Description', '').strip()}"
                    if not description:
                        continue

                    # For each technique in the mitre field, yield a separate detection
                    for technique in techniques:
                        if technique:  # Skip empty technique IDs
                            # Take ASCII representation of unicode characters
                            description = anyascii(description)
                            yield technique, description, None

                except json.JSONDecodeError:
                    print(f"Warning: Could not parse MITRE techniques for rule: {row.get('ID', 'Unknown')}")
                    continue 