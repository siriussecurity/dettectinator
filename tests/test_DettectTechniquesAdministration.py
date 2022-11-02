import unittest
import os
import sys
import shutil

sys.path.append(os.path.dirname(os.path.abspath(__file__).replace('tests', 'dettectinator')))
from dettectinator import DettectTechniquesAdministration

class TestDettectTechniquesAdministration(unittest.TestCase):

    local_stix_path = '../../cti'
    if not os.path.exists(local_stix_path):
        local_stix_path = None

    dettect = DettectTechniquesAdministration(local_stix_path=local_stix_path)
    dettect_mobile = DettectTechniquesAdministration(domain='mobile', local_stix_path=local_stix_path)
    dettect_ics = DettectTechniquesAdministration(domain='ics', local_stix_path=local_stix_path)
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'unittest_output_tech')

    def setUp(self) -> None:
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
        os.mkdir(self.output_dir)
        return super().setUp()

    def tearDown(self) -> None:
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
        return super().tearDown()

    def test_update_detections_new_file_basic(self):
        self.dettect.start_clean_file()
        rules = {}
        rules['Detection A'] = {'applicable_to': ['all'], 'location_prefix': 'Test', 'techniques': ['T1055']}
        warnings, results = self.dettect.update_detections(rules)

        self.assertIs(0, len(warnings), msg='No warnings expected')
        self.assertEqual('T1055', self.dettect._yaml_content['techniques'][0]['technique_id'], msg='Expecting specific technique_id value')
        self.assertEqual('all', self.dettect._yaml_content['techniques'][0]['detection'][0]['applicable_to'][0], msg='Expecting specific applicable_to value')
        self.assertEqual('Test: Detection A', self.dettect._yaml_content['techniques'][0]['detection'][0]['location'][0], msg='Expecting specific location value')
        self.assertEqual('enterprise-attack', self.dettect._yaml_content['domain'], msg='Expecting specific domain value')

    def test_update_detections_new_file_basic_mobile(self):
        self.dettect_mobile.start_clean_file()
        rules = {}
        rules['Detection A'] = {'applicable_to': ['all'], 'location_prefix': 'Test', 'techniques': ['T1456']}
        warnings, results = self.dettect_mobile.update_detections(rules)

        print(warnings)
        self.assertIs(0, len(warnings), msg='No warnings expected')
        self.assertEqual('T1456', self.dettect_mobile._yaml_content['techniques'][0]['technique_id'], msg='Expecting specific technique_id value')
        self.assertEqual('all', self.dettect_mobile._yaml_content['techniques'][0]['detection'][0]['applicable_to'][0], msg='Expecting specific applicable_to value')
        self.assertEqual('Test: Detection A', self.dettect_mobile._yaml_content['techniques'][0]['detection'][0]['location'][0], msg='Expecting specific location value')
        self.assertEqual('mobile-attack', self.dettect_mobile._yaml_content['domain'], msg='Expecting specific domain value')

    def test_update_detections_new_file_basic_ics(self):
        self.dettect_ics.start_clean_file()
        rules = {}
        rules['Detection A'] = {'applicable_to': ['all'], 'location_prefix': 'Test', 'techniques': ['T0817']}
        warnings, results = self.dettect_ics.update_detections(rules)

        self.assertIs(0, len(warnings), msg='No warnings expected')
        self.assertEqual('T0817', self.dettect_ics._yaml_content['techniques'][0]['technique_id'], msg='Expecting specific technique_id value')
        self.assertEqual('all', self.dettect_ics._yaml_content['techniques'][0]['detection'][0]['applicable_to'][0], msg='Expecting specific applicable_to value')
        self.assertEqual('Test: Detection A', self.dettect_ics._yaml_content['techniques'][0]['detection'][0]['location'][0], msg='Expecting specific location value')
        self.assertEqual('ics-attack', self.dettect_ics._yaml_content['domain'], msg='Expecting specific domain value')

    def test_update_detections_invalid_technique(self):
        self.dettect.start_clean_file()
        rules = {}
        rules['Detection A'] = {'applicable_to': ['all'], 'location_prefix': 'Test', 'techniques': ['T9999']}
        warnings, results = self.dettect.update_detections(rules)

        self.assertIs(1, len(warnings), msg='One warning expected')
        self.assertEqual('Technique "T9999" listed in detection rule "Detection A" does not exist in ATT&CK (enterprise-attack). Skipping.', warnings[0], msg='Expecting technique not exist result')

    def test_update_detections_new_file_new_location(self):
        self.dettect.start_clean_file()
        rules = {}
        rules['Detection A'] = {'applicable_to': ['all'], 'location_prefix': 'Test', 'techniques': ['T1055']}
        warnings, results = self.dettect.update_detections(rules)

        rules['Detection B'] = {'applicable_to': ['all'], 'location_prefix': 'Test', 'techniques': ['T1055']}
        warnings, results = self.dettect.update_detections(rules)

        self.assertIs(0, len(warnings), msg='No warnings expected')
        self.assertIs(2, len(self.dettect._yaml_content['techniques'][0]['detection'][0]['location']), msg='Expecting 2 items in location field')

    def test_update_detections_new_file_new_applicable_to(self):
        self.dettect.start_clean_file()
        rules = {}
        rules['Detection A'] = {'applicable_to': ['all'], 'location_prefix': 'Test', 'techniques': ['T1055']}
        warnings, results = self.dettect.update_detections(rules)

        rules['Detection B'] = {'applicable_to': ['servers'], 'location_prefix': 'Test', 'techniques': ['T1055']}
        warnings, results = self.dettect.update_detections(rules)

        self.assertIs(0, len(warnings), msg='No warnings expected')
        self.assertEqual('servers', self.dettect._yaml_content['techniques'][0]['detection'][1]['applicable_to'][0], msg='Expecting specific applicable_to value')

    def test_update_detections_check_unused_detections(self):
        self.dettect.start_clean_file()
        rules1 = {}
        rules1['Detection A'] = {'applicable_to': ['all'], 'location_prefix': 'Test', 'techniques': ['T1055']}
        warnings1, results1 = self.dettect.update_detections(rules1)
        rules2 = {}
        rules2['Detection B'] = {'applicable_to': ['all'], 'location_prefix': 'Test', 'techniques': ['T1202']}
        warnings2, results2 = self.dettect.update_detections(rules2, check_unused_detections=True, clean_unused_detections=False)

        self.assertIs(1, len(warnings2), msg='1 warnings expected')
        self.assertIs(1, len(self.dettect._yaml_content['techniques'][0]['detection'][0]['location']), msg='Expecting location field having 1 entry')

    def test_update_detections_clean_unused_detections(self):
        self.dettect.start_clean_file()
        rules1 = {}
        rules1['Detection A'] = {'applicable_to': ['all'], 'location_prefix': 'Test', 'techniques': ['T1055']}
        warnings1, results1 = self.dettect.update_detections(rules1)
        rules2 = {}
        rules2['Detection B'] = {'applicable_to': ['all'], 'location_prefix': 'Test', 'techniques': ['T1202']}
        warnings2, results2 = self.dettect.update_detections(rules2, check_unused_detections=True, clean_unused_detections=True)

        self.assertIs(0, len(warnings2), msg='No warnings expected')
        self.assertIs(0, len(self.dettect._yaml_content['techniques'][0]['detection'][0]['location']), msg='Location field expected empty')

    def test_update_detections_check_unused_applicable_to(self):
        self.dettect.start_clean_file()
        rules1 = {}
        rules1['Detection A'] = {'applicable_to': ['to_be_removed'], 'location_prefix': 'Test', 'techniques': ['T1055']}
        warnings1, results1 = self.dettect.update_detections(rules1)
        rules2 = {}
        rules2['Detection B'] = {'applicable_to': ['all'], 'location_prefix': 'Test', 'techniques': ['T1202']}
        warnings2, results2 = self.dettect.update_detections(rules2, check_unused_applicable_to=True, clean_unused_applicable_to=False)

        self.assertIs(1, len(warnings2), msg='1 warning expected')
        self.assertIs(1, len(self.dettect._yaml_content['techniques'][0]['detection']), msg='Expecting detection object havin 1 entry')

    def test_update_detections_clean_unused_applicable_to(self):
        self.dettect.start_clean_file()
        rules1 = {}
        rules1['Detection A'] = {'applicable_to': ['to_be_removed'], 'location_prefix': 'Test', 'techniques': ['T1055']}
        warnings1, results1 = self.dettect.update_detections(rules1)
        rules2 = {}
        rules2['Detection B'] = {'applicable_to': ['all'], 'location_prefix': 'Test', 'techniques': ['T1202']}
        warnings2, results2 = self.dettect.update_detections(rules2, check_unused_applicable_to=True, clean_unused_applicable_to=True)

        self.assertIs(1, len(warnings2), msg='1 warning expected')
        self.assertIs(0, len(self.dettect._yaml_content['techniques'][0]['detection']), msg='Detection object expected to be empty')

    def test_save_yaml_file(self):
        self.dettect.start_clean_file()
        rules = {}
        rules['Detection A'] = {'applicable_to': ['all'], 'location_prefix': 'Test', 'techniques': ['T1055']}
        self.dettect.update_detections(rules)
        filename = os.path.join(self.output_dir, 'test_save_tech_yaml_file.yaml')
        self.dettect.save_yaml_file(filename)

        self.assertTrue(os.path.exists(filename), msg='Failed save_yaml_file')

    def test_set_name(self):
        self.dettect.start_clean_file()
        rules = {}
        rules['Detection A'] = {'applicable_to': ['all'], 'location_prefix': 'Test', 'techniques': ['T1055']}
        self.dettect.update_detections(rules)
        self.dettect.set_name('TestName')

        self.assertEqual('TestName', self.dettect._yaml_content['name'], msg='Wrong name value')

    def test_get_filename(self):
        self.dettect.start_clean_file()
        rules = {}
        rules['Detection A'] = {'applicable_to': ['all'], 'location_prefix': 'Test', 'techniques': ['T1055']}
        self.dettect.update_detections(rules)

        self.assertEqual('techniques_new.yaml', self.dettect.get_filename(), msg='Wrong name value')


if __name__ == '__main__':
    unittest.main()
