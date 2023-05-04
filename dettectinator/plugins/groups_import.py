"""
Dettectinator - The Python library to your DeTT&CT YAML files.
Authors:
    Martijn Veken, Sirius Security
    Ruben Bouman, Sirius Security
License: GPL-3.0 License
"""

from argparse import ArgumentParser
from collections.abc import Iterable
import urllib3

# Disable SSL certificate warnings for dev purposes:
urllib3.disable_warnings()


class GroupBase:
    """
    Base class for importing group/technique/software data
    """

    def __init__(self, parameters: dict) -> None:
        self._parameters = parameters

        self._campaign = self._parameters.get('campaign', '')
        self._group = self._parameters.get('group', '')

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        parser.add_argument('-gr', '--group',
                            help='Name of the group.', default='')
        parser.add_argument('-ca', '--campaign',
                            help='Name of the campaign of the group.', default='')

    def get_attack_groups(self) -> dict:
        """
        Retrieves group/technique/software data from a data source
        :return: Dictionary, example:  {'APT1': {'campaign': 'P0wn them all', 'techniques': ['T1566.002', 'T1059.001',
                                        'T1053.005'], 'software': ['S0002']}}
        """
        groups = {}

        for group, campaign, techniques, software in self.get_data_from_source():
            campaign = campaign or self._campaign
            group = group or self._group

            groups[group] = {'campaign': campaign,
                             'techniques': techniques,
                             'software': software}

        return groups

    def get_data_from_source(self) -> Iterable:
        """
        Gets the use-case/technique data from the source.
        :return: Iterable, yields technique, detection, applicable_to
        """
        raise NotImplementedError()


class GroupFoo(GroupBase):

    def get_data_from_source(self) -> Iterable:
        data = {'APT1': {'campaign': 'P0wn them all', 'techniques': ['T1566.002', 'T1059.001', 'T1053.005'],
                         'software': ['S0002']}}

        for group, group_data in data.items():
            yield group, group_data['campaign'], group_data['techniques'], group_data['software']
