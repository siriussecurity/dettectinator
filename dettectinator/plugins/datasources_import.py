"""
Dettectinator - The Python library to your DeTT&CT YAML files.
Authors:
    Martijn Veken, Sirius Security
    Ruben Bouman, Sirius Security
License: GPL-3.0 License
"""

from argparse import ArgumentParser
from collections.abc import Iterable
from xml.etree.ElementTree import Element

import json
import xml.etree.ElementTree as ElementTree


class DatasourceBase:
    """
    Base class for importing datasource/product data
    """

    def __init__(self, parameters: dict) -> None:
        self._parameters = parameters

        self._re_include = self._parameters.get('re_include', None)
        self._re_exclude = self._parameters.get('re_exclude', None)

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        raise NotImplementedError()

    def get_attack_datasources(self, applicable_to: list) -> dict:
        """
        Retrieves datasource/product data from a data source
        :param applicable_to: Systems that the datasources are applicable to.
        :return: Dictionary, example: {"User Account Creation":[{"applicable_to":["test"],"available_for_data_analytics":true,"products":["DeviceEvents: UserAccountCreated"]}]}
        """

        data_sources = {}

        for datasource, product in self.get_data_from_source():
            # Exclude all products that match the exclude-pattern
            if self._re_exclude and not re.match(self._re_exclude, product) is None:
                continue

            # Include all products that match the include-pattern
            if self._re_include and re.match(self._re_include, product) is None:
                continue

            if datasource not in data_sources.keys():
                record = {'applicable_to': applicable_to, 'available_for_data_analytics': True, 'products': []}
                data_sources[datasource] = [record]
            else:
                record = data_sources[datasource][0]

            if product not in record['products']:
                record['products'].append(product)

        return data_sources

    def get_data_from_source(self) -> Iterable:
        """
        Gets the datasource/product data from the source.
        :return: Iterable, yields technique, detection
        """
        raise NotImplementedError()


class DatasourceOssemBase(DatasourceBase):
    """
    Base class for importing datasource/product data that is based on OSSEM data
    For information about OSSEM see: https://github.com/OTRF/OSSEM-DM
    """

    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)
        self._log_source = None

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        raise NotImplementedError()

    def get_data_from_source(self) -> Iterable:
        """
        Gets the datasource/product data from the source.
        :return: Iterable, yields technique, detection
        """
        raise NotImplementedError()

    def _get_ossem_data(self):
        """
        Retrieves data from the OSSEM ATT&CK mapping
        """
        import pandas

        url = 'https://raw.githubusercontent.com/OTRF/OSSEM-DM/main/use-cases/mitre_attack/attack_events_mapping.csv'
        data = pandas.read_csv(url)
        data.where(data['Log Source'] == self._log_source, inplace=True)
        data.dropna(how='all', inplace=True)
        select = data[['Data Source', 'Component', 'EventID', 'Event Name', 'Filter in Log', 'Audit Category']]
        dict_result = select.to_dict(orient="records")
        return dict_result


class DatasourceDefenderEndpoints(DatasourceOssemBase):
    """
    Base class for importing use-case/technique data
    """

    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)
        self._log_source = 'Microsoft Defender for Endpoint'

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        pass

    def get_data_from_source(self) -> Iterable:
        """
        Gets the datasource/product data from the source.
        :return: Iterable, yields technique, detection
        """
        ossem_data = self._get_ossem_data()

        for record in ossem_data:
            action_types = json.loads(record['Filter in Log'].replace('\'', '\"'))
            if len(action_types) > 0:
                for action_type in action_types:
                    yield str(record['Component']).title(), f'{record ["Event Name"]}: {action_type["ActionType"]}'
            else:
                yield str(record['Component']).title(), record['Event Name']


class DatasourceWindowsSysmon(DatasourceOssemBase):
    """
    Base class for importing use-case/technique data
    """

    def __init__(self, parameters: dict) -> None:
        super().__init__(parameters)

        if 'sysmon_config' not in self._parameters:
            raise Exception('DatasourceWindowsSysmon: "sysmon_config" parameter is required.')

        self._sysmon_config = parameters['sysmon_config']
        self._log_source = 'Microsoft-Windows-Sysmon'

    @staticmethod
    def set_plugin_params(parser: ArgumentParser) -> None:
        """
        Set command line arguments specific for the plugin
        :param parser: Argument parser
        """
        parser.add_argument('--sysmon_config', help='Path of the Sysmon config file.', required=True)

    def get_data_from_source(self) -> Iterable:
        """
        Gets the datasource/product data from the source.
        :return: Iterable, yields technique, detection
        """
        ossem_data = self._get_ossem_data()
        sysmon_config = self._get_sysmon_config()

        for record in ossem_data:
            config_items = sysmon_config.findall(f'.//{record["Audit Category"]}')

            # Event type is not found in the config, which means that there is no filtering
            if len(config_items) == 0:
                yield str(record['Component']).title(), f'{record["EventID"]}: {record["Event Name"]}'
                continue

            for config_item in config_items:
                if config_item.attrib['onmatch'] == "include" and len(config_item.getchildren()) > 0:
                    # There is an include attribute in the config with sub elements, which means there is logging
                    yield str(record['Component']).title(), f'{record["EventID"]}: {record["Event Name"]}'

    def _get_sysmon_config(self) -> Element:
        """
        Gets the Sysmon config from the filesystem
        """
        tree = ElementTree.parse(self._sysmon_config)
        root = tree.getroot()
        return root
