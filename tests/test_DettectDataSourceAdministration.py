import unittest
import os
import sys
import shutil

sys.path.append(os.path.dirname(os.path.abspath(__file__).replace('tests', 'dettectinator')))
from dettectinator import DettectDataSourcesAdministration

class TestDettectDataSourcesAdministration(unittest.TestCase):

    local_stix_path = '../../cti'
    if not os.path.exists(local_stix_path):
        local_stix_path = None

    dettect = DettectDataSourcesAdministration(local_stix_path=local_stix_path)
    dettect_ics = DettectDataSourcesAdministration(domain='ics', local_stix_path=local_stix_path)
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'unittest_output_ds')

    def setUp(self) -> None:
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
        os.mkdir(self.output_dir)
        return super().setUp()

    def tearDown(self) -> None:
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
        return super().tearDown()

    def test_update_data_sources_new_file_basic(self):
        self.dettect.start_clean_file()
        data_sources = {}
        data_sources['Process Creation'] = [{'applicable_to': ['all'],
                                             'products': ['Windows Event Log'],
                                             'available_for_data_analytics': True,
                                             'data_quality': {'device_completeness': 1,
                                                              'data_field_completeness': 2,
                                                              'timeliness': 3,
                                                              'consistency': 4,
                                                              'retention': 5}}]
        warnings, results = self.dettect.update_data_sources(data_sources)

        self.assertIs(0, len(warnings), msg='No results expected')
        self.assertIs(2, len(results), msg='Two results expected')
        self.assertEqual('Check data quality scores for data source Process Creation. Data source is new.', results[0], msg='Expecting specific result value')
        self.assertEqual("Check data quality scores for data source Process Creation. applicable_to is new: ['all']", results[1], msg='Expecting specific results value')
        self.assertEqual('Process Creation', self.dettect._yaml_content['data_sources'][0]['data_source_name'], msg='Expecting specific data source name value')
        self.assertEqual('all', self.dettect._yaml_content['data_sources'][0]['data_source'][0]['applicable_to'][0], msg='Expecting specific applicable_to value')
        self.assertEqual('Windows Event Log', self.dettect._yaml_content['data_sources'][0]['data_source'][0]['products'][0], msg='Expecting specific products value')
        self.assertEqual(1, self.dettect._yaml_content['data_sources'][0]['data_source'][0]['data_quality']['device_completeness'], msg='Expecting specific data quality value')
        self.assertEqual(2, self.dettect._yaml_content['data_sources'][0]['data_source'][0]['data_quality']['data_field_completeness'], msg='Expecting specific data quality value')
        self.assertEqual(3, self.dettect._yaml_content['data_sources'][0]['data_source'][0]['data_quality']['timeliness'], msg='Expecting specific data quality value')
        self.assertEqual(4, self.dettect._yaml_content['data_sources'][0]['data_source'][0]['data_quality']['consistency'], msg='Expecting specific data quality value')
        self.assertEqual(5, self.dettect._yaml_content['data_sources'][0]['data_source'][0]['data_quality']['retention'], msg='Expecting specific data quality value')
        self.assertEqual('enterprise-attack', self.dettect._yaml_content['domain'], msg='Expecting specific domain value')

    def test_update_data_sources_new_file_basic_ics(self):
        self.dettect_ics.start_clean_file()
        data_sources = {}
        data_sources['Device Alarm'] = [{'applicable_to': ['all'],
                                             'products': ['Device Logs'],
                                             'available_for_data_analytics': True}]
        warnings, results = self.dettect_ics.update_data_sources(data_sources)

        self.assertIs(0, len(warnings), msg='No results expected')
        self.assertEqual('Device Alarm', self.dettect_ics._yaml_content['data_sources'][0]['data_source_name'], msg='Expecting specific data source name value')
        self.assertEqual('all', self.dettect_ics._yaml_content['data_sources'][0]['data_source'][0]['applicable_to'][0], msg='Expecting specific applicable_to value')
        self.assertEqual('Device Logs', self.dettect_ics._yaml_content['data_sources'][0]['data_source'][0]['products'][0], msg='Expecting specific products value')
        self.assertEqual('ics-attack', self.dettect_ics._yaml_content['domain'], msg='Expecting specific domain value')

    def test_update_data_sources_invalid_data_source(self):
        self.dettect.start_clean_file()
        data_sources = {}
        data_sources['Process Creations'] = [{'applicable_to': ['all'],
                                             'products': ['Windows Event Log'],
                                             'available_for_data_analytics': True}]
        warnings, results = self.dettect.update_data_sources(data_sources)

        self.assertIs(1, len(results), msg='One result expected')
        self.assertEqual('Data source "Process Creations" does not exist in ATT&CK (enterprise-attack). Skipping.', results[0], msg='Expecting data source not exist result')

    def test_update_detections_new_systems(self):
        self.dettect.start_clean_file()
        data_sources = {}
        data_sources['Process Creation'] = [{'applicable_to': ['all'],
                                             'products': ['Windows Event Log'],
                                             'available_for_data_analytics': True}]
        warnings1, results1 = self.dettect.update_data_sources(data_sources)

        data_sources = {}
        data_sources['Process Creation'] = [{'applicable_to': ['workstations'],
                                             'products': ['Windows Event Log'],
                                             'available_for_data_analytics': True}]
        warnings2, results2 = self.dettect.update_data_sources(data_sources)

        self.assertIs(2, len(results2), msg='One result expected')
        self.assertEqual('Applicable_to value "[\'workstations\']" of data source "Process Creation" not in systems object of data source YAML file. Added to systems object with platform=all. Please review this new entry.', results2[0], msg='Expecting specific results value')
        self.assertEqual('Check data quality scores for data source Process Creation. applicable_to is new: [\'workstations\']', results2[1], msg='Expecting specific results value')

    def test_update_data_sources_update(self):
        self.dettect.start_clean_file()
        data_sources = {}
        data_sources['Process Creation'] = [{'applicable_to': ['all'],
                                             'products': ['Windows Event Log'],
                                             'available_for_data_analytics': True,
                                             'data_quality': {'device_completeness': 1,
                                                              'data_field_completeness': 2,
                                                              'timeliness': 3,
                                                              'consistency': 4,
                                                              'retention': 5}}]
        warnings1, results1 = self.dettect.update_data_sources(data_sources)
        data_sources['Process Creation'] = [{'applicable_to': ['all'],
                                             'products': ['Windows Event Log', 'SIEM'],
                                             'available_for_data_analytics': True,
                                             'data_quality': {'device_completeness': 2,
                                                              'data_field_completeness': 3,
                                                              'timeliness': 4,
                                                              'consistency': 5,
                                                              'retention': 4}}]
        warnings2, results2 = self.dettect.update_data_sources(data_sources)

        self.assertIs(0, len(warnings2), msg='No results expected')
        self.assertIs(1, len(results2), msg='One result expected')
        self.assertEqual("Check data quality scores for data source Process Creation. Data source with applicable_to ['all'] is updated.", results2[0], msg='Expecting specific results value')

    def test_update_data_sources_check_unused(self):
        self.dettect.start_clean_file()
        data_sources, data_sources2 = {}, {}
        data_sources['Process Metadata'] = [{'applicable_to': ['all'],
                                             'products': ['Windows Event Log'],
                                             'available_for_data_analytics': True,
                                             'data_quality': {'device_completeness': 1,
                                                              'data_field_completeness': 2,
                                                              'timeliness': 3,
                                                              'consistency': 4,
                                                              'retention': 5}}]
        self.dettect.update_data_sources(data_sources)
        data_sources2['Process Creation'] = [{'applicable_to': ['all'],
                                             'products': ['Windows Event Log', 'SIEM'],
                                             'available_for_data_analytics': True,
                                             'data_quality': {'device_completeness': 2,
                                                              'data_field_completeness': 3,
                                                              'timeliness': 4,
                                                              'consistency': 5,
                                                              'retention': 4}}]
        warnings2, results2 = self.dettect.update_data_sources(data_sources2, check_unused_data_sources=True)

        self.assertIs(1, len(warnings2), msg='One result expected')
        self.assertIs(2, len(results2), msg='One result expected')
        self.assertEqual('YAML data source "Process Metadata" not in given data sources list.', warnings2[0], msg='Expecting specific warning value')
        self.assertEqual('Check data quality scores for data source Process Creation. Data source is new.', results2[0], msg='Expecting specific results value')
        self.assertEqual("Check data quality scores for data source Process Creation. applicable_to is new: ['all']", results2[1], msg='Expecting specific results value')

    def test_update_data_sources_clean_unused(self):
        self.dettect.start_clean_file()
        data_sources, data_sources2 = {}, {}
        data_sources['Process Metadata'] = [{'applicable_to': ['all'],
                                             'products': ['Windows Event Log'],
                                             'available_for_data_analytics': True,
                                             'data_quality': {'device_completeness': 1,
                                                              'data_field_completeness': 2,
                                                              'timeliness': 3,
                                                              'consistency': 4,
                                                              'retention': 5}}]
        self.dettect.update_data_sources(data_sources)
        data_sources2['Process Creation'] = [{'applicable_to': ['all'],
                                             'products': ['Windows Event Log', 'SIEM'],
                                             'available_for_data_analytics': True,
                                             'data_quality': {'device_completeness': 2,
                                                              'data_field_completeness': 3,
                                                              'timeliness': 4,
                                                              'consistency': 5,
                                                              'retention': 4}}]
        warnings2, results2 = self.dettect.update_data_sources(data_sources2, check_unused_data_sources=True, clean_unused_data_sources=True)

        self.assertIs(1, len(warnings2), msg='One result expected')
        self.assertIs(2, len(results2), msg='One result expected')
        self.assertEqual('YAML data source "Process Metadata" not in given data sources list, so removed.', warnings2[0], msg='Expecting specific warning value')
        self.assertEqual('Check data quality scores for data source Process Creation. Data source is new.', results2[0], msg='Expecting specific results value')
        self.assertEqual("Check data quality scores for data source Process Creation. applicable_to is new: ['all']", results2[1], msg='Expecting specific results value')

    def test_save_yaml_file(self):
        self.dettect.start_clean_file()
        data_sources = {}
        data_sources['Process Metadata'] = [{'applicable_to': ['all'],
                                             'products': ['Windows Event Log'],
                                             'available_for_data_analytics': True,
                                             'data_quality': {'device_completeness': 1,
                                                              'data_field_completeness': 2,
                                                              'timeliness': 3,
                                                              'consistency': 4,
                                                              'retention': 5}}]
        self.dettect.update_data_sources(data_sources)
        filename = os.path.join(self.output_dir, 'test_save_ds_yaml_file.yaml')
        self.dettect.save_yaml_file(filename)

        self.assertTrue(os.path.exists(filename), msg='Failed save_yaml_file')

    def test_set_name(self):
        self.dettect.start_clean_file()
        data_sources = {}
        data_sources['Process Metadata'] = [{'applicable_to': ['all'],
                                             'products': ['Windows Event Log'],
                                             'available_for_data_analytics': True,
                                             'data_quality': {'device_completeness': 1,
                                                              'data_field_completeness': 2,
                                                              'timeliness': 3,
                                                              'consistency': 4,
                                                              'retention': 5}}]
        self.dettect.update_data_sources(data_sources)
        self.dettect.set_name('TestName')

        self.assertEqual('TestName', self.dettect._yaml_content['name'], msg='Wrong name value')

    def test_get_filename(self):
        self.dettect.start_clean_file()
        data_sources = {}
        data_sources['Process Metadata'] = [{'applicable_to': ['all'],
                                             'products': ['Windows Event Log'],
                                             'available_for_data_analytics': True,
                                             'data_quality': {'device_completeness': 1,
                                                              'data_field_completeness': 2,
                                                              'timeliness': 3,
                                                              'consistency': 4,
                                                              'retention': 5}}]
        self.dettect.update_data_sources(data_sources)

        self.assertEqual('data_sources_new.yaml', self.dettect.get_filename(), msg='Wrong name value')



if __name__ == '__main__':
    unittest.main()
