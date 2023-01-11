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
import argparse

try:
    # When dettectinator is installed as python library
    from dettectinator import DettectTechniquesAdministration
    from dettectinator import DettectDataSourcesAdministration
except ModuleNotFoundError:
    # When dettectinator is not installed as python library
    sys.path.append(os.path.dirname(os.path.abspath(__file__).replace('examples', 'dettectinator')))
    from dettectinator import DettectTechniquesAdministration
    from dettectinator import DettectDataSourcesAdministration


def techniques_yaml(local_stix_path):
    """
    Tests the modification of a DeTT&CT techniques administration YAML file.
    """
    # Testing techniques YAML:
    dettect = DettectTechniquesAdministration('techniques.yaml', local_stix_path=local_stix_path)

    rules = {}
    rules['Detection A'] = {'applicable_to': ['all'], 'location_prefix': 'Splunk', 'techniques': ['T1055']}
    rules['Detection B'] = {'applicable_to': ['all'], 'location_prefix': 'Splunk', 'techniques': ['T1529']}
    rules['Detection C'] = {'applicable_to': ['Windows 3.1'], 'location_prefix': 'Splunk', 'techniques': ['T1055']}
    rules['Detection D'] = {'applicable_to': ['Windows 3.1', 'Windows 97'], 'location_prefix': 'EDR', 'techniques': ['T1055']}
    rules['Detection E'] = {'applicable_to': ['Windows 3.1', 'Windows 97'], 'location_prefix': 'EDR', 'techniques': ['T1561']}
    rules['Detection F'] = {'applicable_to': ['Windows 3.1', 'Windows 97'], 'location_prefix': 'EDR', 'techniques': ['T1561']}
    rules['Detection G'] = {'applicable_to': ['all'], 'location_prefix': 'EDR', 'techniques': ['T1561']}

    warnings, results = dettect.update_detections(rules, check_unused_detections=True, clean_unused_detections=True,
                                                  check_unused_applicable_to=True, clean_unused_applicable_to=True)
    output = warnings + results
    if len(output) > 0:
        print('\nPlease review the following items:')
        print(' - ' + '\n - '.join(output))
    dettect.save_yaml_file('techniques_updated.yaml')


def data_sources_yaml(local_stix_path):
    """
    Tests the modification of a DeTT&CT data source administration YAML file.
    """
    # Testing data source YAML:
    dettect_ds = DettectDataSourcesAdministration('data_sources.yaml', local_stix_path=local_stix_path)

    data_sources = {}
    data_sources['Process Creation'] = [{'applicable_to': ['all'], 'products': ['Windows Event Log'], 'available_for_data_analytics': True, 'data_quality': {
                                            'device_completeness': 5,
                                            'data_field_completeness': 5,
                                            'timeliness': 5,
                                            'consistency': 5,
                                            'retention': 5}
                                         },
                                        {'applicable_to': ['laptops'], 'products': ['Sysmon'], 'available_for_data_analytics': True}]
    data_sources['Command Execution'] = [{'applicable_to': ['servers'], 'products': ['Sysmon'], 'available_for_data_analytics': True}]
    data_sources['Process Termination'] = [{'applicable_to': ['all'], 'products': ['Sysmon'], 'available_for_data_analytics': True}]
    data_sources['Drive Creation'] = [{'applicable_to': ['workstations'], 'products': ['Windows Event Log'], 'available_for_data_analytics': True}]

    warnings, results = dettect_ds.update_data_sources(data_sources, check_unused_data_sources=True, clean_unused_data_sources=True)
    output = warnings + results
    if len(output) > 0:
        print('\nPlease review the following items:')
        print(' - ' + '\n - '.join(output))
    dettect_ds.save_yaml_file('data_sources_updated.yaml')


def techniques_yaml_list(local_stix_path):
    """
    Tests the modification of a DeTT&CT techniques administration YAML file.
    """
    # Testing techniques YAML:
    dettect = DettectTechniquesAdministration('techniques.yaml', local_stix_path=local_stix_path)

    rules = {}
    rules['Detection A'] = [{'applicable_to': ['all'], 'location_prefix': 'Splunk', 'techniques': ['T1055']}]
    rules['Detection B'] = [{'applicable_to': ['all'], 'location_prefix': 'Splunk', 'techniques': ['T1529']}]
    rules['Detection C'] = [{'applicable_to': ['Windows 3.1'], 'location_prefix': 'Splunk', 'techniques': [
        'T1055']}, {'applicable_to': ['all'], 'location_prefix': 'Splunk', 'techniques': ['T1055']}]
    rules['Detection D'] = [{'applicable_to': ['Windows 3.1', 'Windows 97'], 'location_prefix': 'EDR', 'techniques': ['T1055']}]
    rules['Detection F'] = [{'applicable_to': ['Windows 3.1', 'Windows 97'], 'location_prefix': 'EDR', 'techniques': ['T1561']}]
    rules['Detection E'] = [{'applicable_to': ['Windows 3.1', 'Windows 97'], 'location_prefix': 'EDR', 'techniques': ['T1561']}]
    rules['Detection G'] = [{'applicable_to': ['all'], 'location_prefix': 'EDR', 'techniques': ['T1561']}]

    warnings, results = dettect.update_detections(rules, check_unused_detections=True, clean_unused_detections=True,
                                                  check_unused_applicable_to=True, clean_unused_applicable_to=True)
    output = warnings + results
    if len(output) > 0:
        print('\nPlease review the following items:')
        print(' - ' + '\n - '.join(output))
    dettect.save_yaml_file('techniques_updated_list.yaml')


if __name__ == '__main__':
    menu_parser = argparse.ArgumentParser()
    menu_parser.add_argument('--local-stix-path', help="Path to a local STIX ATT&CK repository")
    args = menu_parser.parse_args()
    arg_local_stix_path = args.local_stix_path

    # techniques_yaml(arg_local_stix_path)
    techniques_yaml_list(arg_local_stix_path)
    # data_sources_yaml(arg_local_stix_path)
