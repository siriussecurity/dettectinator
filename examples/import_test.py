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
    from dettectinator.plugins.technique_import import TechniqueCsv, TechniqueTaniumSignals, TechniqueDefenderAlerts, TechniqueSentinelAlertRules
    from plugins.datasources_import import DatasourceDefenderEndpoints
except ModuleNotFoundError:
    # When dettectinator is not installed as python library
    sys.path.append(os.path.dirname(os.path.abspath(__file__).replace('examples', 'dettectinator')))
    from dettectinator import DettectTechniquesAdministration, DettectDataSourcesAdministration
    from plugins.technique_import import TechniqueCsv, TechniqueTaniumSignals, TechniqueDefenderAlerts, TechniqueSentinelAlertRules
    from plugins.datasources_import import DatasourceDefenderEndpoints


def test_techniques_file(local_stix_path: str):
    """
    Tests an import via ImportCsv plugin.
    """
    parameters = {'file': 'import.csv'}
    import_csv = TechniqueCsv(parameters)
    techniques = import_csv.get_attack_techniques(['test'], 'Test')
    print(json.dumps(techniques, indent=4))

    dettect = DettectTechniquesAdministration(local_stix_path=local_stix_path)
    dettect.update_detections(techniques, False, False, '', False, False)
    dettect.save_yaml_file('techniques_import_file.yaml')


def test_techniques_defender(local_stix_path: str):
    """
    Tests an import via ImportDefenderAlerts plugin.
    """
    parameters = {'app_id': '', 'tenant_id': ''}
    import_defender = TechniqueDefenderAlerts(parameters)
    techniques = import_defender.get_attack_techniques(['test'], 'MD')
    print(json.dumps(techniques, indent=4))

    dettect = DettectTechniquesAdministration(local_stix_path=local_stix_path)
    dettect.update_detections(techniques, False, False, '', False, False)
    dettect.save_yaml_file('techniques_import_defender.yaml')


def test_techniques_tanium(local_stix_path: str):
    """
    Tests an import via ImportTaniumSignals plugin.
    """
    parameters = {'host': '', 'user': '', 'password': '', 'search_prefix': ''}
    import_tanium = TechniqueTaniumSignals(parameters)
    techniques = import_tanium.get_attack_techniques(['all'], 'Tanium')
    print(json.dumps(techniques, indent=4))

    dettect = DettectTechniquesAdministration(local_stix_path=local_stix_path)
    dettect.update_detections(techniques, False, False, '', False, False)
    dettect.save_yaml_file('techniques_import_tanium.yaml')


def test_techniques_sentinel(local_stix_path: str):
    """
    Tests an import via ImportSentinelAlertRules plugin.
    """
    parameters = {'app_id': '', 'tenant_id': '', 'subscription_id': '', 'resource_group': '', 'workspace': ''}
    import_sentinel = TechniqueSentinelAlertRules(parameters)
    techniques = import_sentinel.get_attack_techniques(['test'], 'test')
    print(json.dumps(techniques, indent=4))

    dettect = DettectTechniquesAdministration(local_stix_path=local_stix_path)
    dettect.update_detections(techniques, False, False, '', False, False)
    dettect.save_yaml_file('techniques_import_sentinel.yaml')


def test_datasources_mde(local_stix_path: str):

    parameters = {}
    import_datasources_mde = DatasourceDefenderEndpoints(parameters)
    datasources = import_datasources_mde.get_attack_datasources(['test'])
    print(json.dumps(datasources, indent=4))

    dettect = DettectDataSourcesAdministration(local_stix_path=local_stix_path)
    dettect.update_data_sources(datasources, False, False)
    dettect.save_yaml_file('datasources_import_mde.yaml')


if __name__ == '__main__':
    menu_parser = argparse.ArgumentParser()
    menu_parser.add_argument('--local-stix-path', help="Path to a local STIX ATT&CK repository")
    args = menu_parser.parse_args()
    arg_local_stix_path = args.local_stix_path

    # test_technique_importfile(arg_local_stix_path)
    # test_technique_importdefender(arg_local_stix_path)
    # test_technique_importtanium(arg_local_stix_path)
    # test_technique_importsentinel(arg_local_stix_path)
    test_datasources_mde(arg_local_stix_path)
