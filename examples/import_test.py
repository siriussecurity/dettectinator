"""
Dettectinator - The Python library to your DeTT&CT YAML files.
Authors:
    Martijn Veken, Sirius Security
    Ruben Bouman, Sirius Security
License: GPL-3.0 License

This file is intended for demonstration purposes only.
"""

import os
import sys
import json
import argparse

try:
    # When dettectinator is installed as python library
    from dettectinator import DettectTechniquesAdministration, DettectDataSourcesAdministration
    from dettectinator.plugins.detection_import import DetectionCsv, DetectionTaniumSignals, DetectionDefenderAlerts, DetectionSentinelAlertRules
    from plugins.datasources_import import DatasourceDefenderEndpoints
except ModuleNotFoundError:
    # When dettectinator is not installed as python library
    sys.path.append(os.path.dirname(os.path.abspath(__file__).replace('examples', 'dettectinator')))
    from dettectinator import DettectTechniquesAdministration, DettectDataSourcesAdministration
    from plugins.detection_import import DetectionCsv, DetectionTaniumSignals, DetectionDefenderAlerts, DetectionSentinelAlertRules
    from plugins.datasources_import import DatasourceDefenderEndpoints


def test_file(local_stix_path: str):
    """
    Tests an import via ImportCsv plugin.
    """
    parameters = {'file': 'import.csv'}
    import_csv = DetectionCsv(parameters)
    use_cases = import_csv.get_attack_techniques(['test'], 'Test')
    print(json.dumps(use_cases, indent=4))

    dettect = DettectTechniquesAdministration(local_stix_path=local_stix_path)
    dettect.update_detections(use_cases, False, False, '', False, False)
    dettect.save_yaml_file('techniques_import_file.yaml')


def test_defender(local_stix_path: str):
    """
    Tests an import via ImportDefenderAlerts plugin.
    """
    parameters = {'app_id': '', 'tenant_id': ''}
    import_defender = DetectionDefenderAlerts(parameters)
    use_cases = import_defender.get_attack_techniques(['test'], 'MD')
    print(json.dumps(use_cases, indent=4))

    dettect = DettectTechniquesAdministration(local_stix_path=local_stix_path)
    dettect.update_detections(use_cases, False, False, '', False, False)
    dettect.save_yaml_file('techniques_import_defender.yaml')


def test_tanium(local_stix_path: str):
    """
    Tests an import via ImportTaniumSignals plugin.
    """
    parameters = {'host': '', 'user': '', 'password': '', 'search_prefix': ''}
    import_tanium = DetectionTaniumSignals(parameters)
    use_cases = import_tanium.get_attack_techniques(['all'], 'Tanium')
    print(json.dumps(use_cases, indent=4))

    dettect = DettectTechniquesAdministration(local_stix_path=local_stix_path)
    dettect.update_detections(use_cases, False, False, '', False, False)
    dettect.save_yaml_file('techniques_import_tanium.yaml')


def test_sentinel(local_stix_path: str):
    """
    Tests an import via ImportSentinelAlertRules plugin.
    """
    parameters = {'app_id': '', 'tenant_id': '', 'subscription_id': '', 'resource_group': '', 'workspace': ''}
    import_sentinel = DetectionSentinelAlertRules(parameters)
    use_cases = import_sentinel.get_attack_techniques(['test'], 'test')
    print(json.dumps(use_cases, indent=4))

    dettect = DettectTechniquesAdministration(local_stix_path=local_stix_path)
    dettect.update_detections(use_cases, False, False, '', False, False)
    dettect.save_yaml_file('techniques_import_sentinel.yaml')


def test_datasources_mde(local_stix_path: str):

    parameters = {}
    import_datasources_mde = DatasourceDefenderEndpoints(parameters)
    datasources = import_datasources_mde.get_attack_data_sources(['test'])
    print(json.dumps(datasources, indent=4))

    dettect = DettectDataSourcesAdministration(local_stix_path=local_stix_path)
    dettect.update_data_sources(datasources, False, False)
    dettect.save_yaml_file('datasources_import_mde.yaml')


if __name__ == '__main__':
    menu_parser = argparse.ArgumentParser()
    menu_parser.add_argument('--local-stix-path', help="Path to a local STIX ATT&CK repository")
    args = menu_parser.parse_args()
    arg_local_stix_path = args.local_stix_path

    # test_file(arg_local_stix_path)
    # test_defender(arg_local_stix_path)
    # test_tanium(arg_local_stix_path)
    # test_sentinel(arg_local_stix_path)
    test_datasources_mde(arg_local_stix_path)
