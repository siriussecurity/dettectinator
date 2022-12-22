"""
Dettectinator - The Python library to your DeTT&CT YAML files.
Authors:
    Martijn Veken, Sirius Security
    Ruben Bouman, Sirius Security
License: GPL-3.0 License

Some functions and code are taken with permission from the DeTT&CT project (http://github.com/rabobank-cdc/DeTTECT).
"""

import importlib
import inspect
import sys
import os
import json
import errno
from io import StringIO
from datetime import datetime
from copy import deepcopy
from logging import getLogger, ERROR as LOGERROR
from ruamel.yaml import YAML
from attackcti import attack_client
from requests import exceptions
from stix2 import datastore, Filter
from anyascii import anyascii
import dateutil.parser


getLogger('taxii2client').setLevel(LOGERROR)

try:
    # When dettectinator is installed as python library
    from dettectinator.constants import *
except ModuleNotFoundError:
    # When dettectinator is not installed as python library
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from constants import *


class DettectBase(object):
    """
    Base class for DeTT&CT YAML file classes.
    """

    def __init__(self, filename: str, domain: str = None, local_stix_path: str = None) -> None:
        self.filename = filename
        self._local_stix_path = local_stix_path
        self._yaml = None
        self._yaml_content = None

        self._init_yaml()

        if filename is not None:
            self._load_yaml_content()
            self.domain = 'enterprise-attack' if 'domain' not in self._yaml_content.keys() else self._yaml_content['domain']
        else:
            self.domain = 'mobile-attack' if domain == 'mobile' else 'ics-attack' if domain == 'ics' else 'enterprise-attack'
            self.start_clean_file()

        self._load_platform_in_correct_capitalisation()
        self.name = self._yaml_content['name']
        self._initialize_attack_client()
        self._load_attack_techniques()

        # TODO YAML merge functionaliteit

    def _init_yaml(self) -> None:
        """
        Initialize ruamel.yaml with the correct settings
        """
        self._yaml = YAML()
        self._yaml.Representer.ignore_aliases = lambda *args: True  # disable anchors/aliases

    def _load_yaml_content(self) -> None:
        """
        Loads the YAML file into _yaml_content. It will contain the raw YAML content. This variable is used for alteration of the YAML file.
        """
        if not os.path.exists(self.filename):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), self.filename)

        with open(self.filename, 'r') as yaml_file:
            self._yaml_content = self._yaml.load(yaml_file)

    def set_name(self, name):
        """
        Sets the name attribute in the YAML file.
        """
        self._yaml_content['name'] = name

    def get_filename(self):
        """
        Returns the filename of the YAML file.
        """
        return self.filename

    def start_clean_file(self):
        """
        Starts a clean YAML file.
        """
        if isinstance(self, DettectDataSourcesAdministration):
            self._yaml_content = deepcopy(YAML_OBJ_NEW_DATA_SOURCES_FILE)
            self.filename = f"data_sources_{self._yaml_content['name']}.yaml"
            self._yaml_content['domain'] = self.domain

            if self.domain == 'mobile-attack':
                raise Exception(f'{self.__class__.__name__}: Data sources for ATT&CK Mobile not yet implemented by MITRE.')
        elif isinstance(self, DettectTechniquesAdministration):
            self._yaml_content = deepcopy(YAML_OBJ_NEW_TECHNIQUES_FILE)
            self.filename = f"techniques_{self._yaml_content['name']}.yaml"
            self._yaml_content['domain'] = self.domain

    def save_yaml_file(self, filename=None) -> None:
        """
        Saves the YAML file back to disk using the given filename or the same filename when the file was read.
        """
        with open(filename if filename else self.filename, 'w') as yaml_file:
            string_io = StringIO()
            self._yaml.indent(mapping=4, sequence=4, offset=2)
            self._yaml.width = 2048
            self._yaml.dump(self._yaml_content, string_io)
            string_io.seek(0)
            new_lines = string_io.readlines()
            for line in new_lines:
                # Date fix for compatability with YAML Editor (which uses JavaScript to generate YAML):
                if 'date' in line:
                    line = line.replace('T00:00:00Z', 'T00:00:00.000Z').replace(' 00:00:00', 'T00:00:00.000Z')
                yaml_file.write(anyascii(line))
            self.filename = filename if filename else self.filename

    @staticmethod
    def _set_yaml_dv_comments(yaml_object: object) -> object:
        """
        Set all comments in the detection, visibility or data source details YAML object when the 'comment' key-value pair is missing or is None.
        This gives the user the flexibility to have YAML files with missing 'comment' key-value pairs.
        :param yaml_object: detection or visibility object.
        :return: detection or visibility object for which empty comments are filled with an empty string.
        """
        yaml_object['comment'] = yaml_object.get('comment', '')
        if yaml_object['comment'] is None:
            yaml_object['comment'] = ''
        if 'score_logbook' in yaml_object:
            for score_obj in yaml_object['score_logbook']:
                score_obj['comment'] = score_obj.get('comment', '')
                if score_obj['comment'] is None:
                    score_obj['comment'] = ''

        return yaml_object

    @staticmethod
    def _add_entry_to_list_in_dictionary(dictionary: dict, key_dict: str, key_list: str, entry: object) -> None:
        """
        Ensures a list will be created if it doesn't exist in the given dict[key_dict][key_list] and adds the entry to the
        list. If the dict[key_dict] doesn't exist yet, it will be created.
        :param dictionary: the dictionary
        :param key_dict: the key name in de main dict
        :param key_list: the key name where the list in the dictionary resides
        :param entry: the entry to add to the list
        :return:
        """
        if key_dict not in dictionary.keys():
            dictionary[key_dict] = {}
        if key_list not in dictionary[key_dict].keys():
            dictionary[key_dict][key_list] = []
        dictionary[key_dict][key_list].append(entry)

    def _load_platform_in_correct_capitalisation(self) -> None:
        """
        Sets the platforms with the correct capitalisation. E.g.: "linux" will become "Linux"
        """
        platform = self._yaml_content.get('platform', None)

        if platform is None:
            platform = []

        if isinstance(platform, str):
            platform = [platform]

        platform = [p.lower() for p in platform if p is not None]
        selected_platforms = PLATFORMS_ENTERPRISE if self.domain == 'enterprise-attack' else PLATFORMS_ICS if self.domain == 'ics-attack' else PLATFORMS_MOBILE

        if 'all' in platform:
            platform = list(selected_platforms.values())
        else:
            platform = [selected_platforms[p] for p in platform if p is not None if p in selected_platforms.keys()]

        self.platform = platform

    def _initialize_attack_client(self) -> None:
        """
        Initializes the attack_client to get information from local STIX repository or from online TAXII server.
        """
        try:
            if self._local_stix_path is not None:
                if self._local_stix_path is not None and os.path.isdir(os.path.join(self._local_stix_path, 'enterprise-attack')) \
                        and os.path.isdir(os.path.join(self._local_stix_path, 'ics-attack')) \
                        and os.path.isdir(os.path.join(self._local_stix_path, 'mobile-attack')):
                    self.mitre = attack_client(local_path=self._local_stix_path)
                else:
                    raise Exception(f'{self.__class__.__name__}: Not a valid local STIX path: {self._local_stix_path}')
            else:
                self.mitre = attack_client()
        except (exceptions.ConnectionError, datastore.DataSourceError) as e:
            if hasattr(e, 'request'):
                raise Exception(f'{self.__class__.__name__}: Cannot connect to MITRE\'s CTI TAXII server: {str(e.request.url)}') from e
            else:
                raise Exception(f'{self.__class__.__name__}: Cannot connect to MITRE\'s CTI TAXII server.') from e

    def _load_attack_techniques(self) -> None:
        """
        Load the ATT&CK STIX data from the MITRE TAXII server.
        :return: MITRE ATT&CK data object (STIX)
        """
        if self.domain == 'enterprise-attack':
            self.attack_techniques = self._convert_stix_techniques_to_dict(self.mitre.get_enterprise_techniques())
        elif self.domain == 'ics-attack':
            self.attack_techniques = self._convert_stix_techniques_to_dict(self.mitre.get_ics_techniques())
        else:
            self.attack_techniques = self._convert_stix_techniques_to_dict(self.mitre.get_mobile_techniques())

    def _get_technique_from_attack(self, technique_id: str) -> dict:
        """
        Return the technique object for the given technique_id.
        """
        for tech in self.attack_techniques:
            if tech['technique_id'] == technique_id:
                return tech
        return None

    @staticmethod
    def _convert_stix_techniques_to_dict(stix_attack_data: list) -> list:
        """
        Convert the STIX list with AttackPatterns to a dictionary for easier use in python and also include the technique_id and DeTT&CT data sources.
        :param stix_attack_data: the MITRE ATT&CK STIX dataset with techniques
        :return: list with dictionaries containing all techniques from the input stix_attack_data
        """
        attack_data = []
        for stix_tech in stix_attack_data:
            tech = json.loads(stix_tech.serialize(), object_hook=DettectBase._date_hook)

            # Add technique_id as key, because it's hard to get from STIX:
            tech['technique_id'] = DettectBase._get_attack_id(stix_tech)

            # Create empty x_mitre_data_sources key for techniques without data sources:
            if 'x_mitre_data_sources' not in tech.keys():
                tech['x_mitre_data_sources'] = []

            attack_data.append(tech)

        return attack_data

    @staticmethod
    def _date_hook(json_dict: dict) -> dict:
        """
        Parses STIX dates so that they can be used as date object in dictionaries. Function is used as object_hook function in the JSON serialize.
        :param json_dict: the dictionary with STIX data
        :return: dictionary with corrected STIX data
        """
        for (key, value) in json_dict.items():
            if key == 'created':
                json_dict['created'] = dateutil.parser.parse(value)
            elif key == 'modified':
                json_dict['modified'] = dateutil.parser.parse(value)
        return json_dict

    @staticmethod
    def _get_attack_id(stix_obj: object) -> str:
        """
        Get the Technique, Group or Software ID from the STIX object
        :param stix_obj: STIX object (Technique, Software or Group)
        :return: ATT&CK ID
        """
        for ext_ref in stix_obj['external_references']:
            if ext_ref['source_name'] in ['mitre-attack', 'mitre-mobile-attack', 'mitre-ics-attack']:
                return ext_ref['external_id']


class DettectTechniquesAdministration(DettectBase):
    """
    Create or modify a DeTT&CT techniques administration YAML file.
    """

    def __init__(self, filename: str = None, domain: str = None, local_stix_path: str = None) -> None:
        super(DettectTechniquesAdministration, self).__init__(filename, domain, local_stix_path)

        # Get the normalized content from the YAML file:
        self._load_techniques()

    def update_detections(self, detection_rules: dict, check_unused_detections: bool = False, clean_unused_detections: bool = False, location_prefix_unused_detections: str = '', check_unused_applicable_to: bool = False, clean_unused_applicable_to: bool = False) -> list:
        """
        Updates the techniques YAML file with the given detections.
        :param  detection_rules: a dictionary of dictionaries containing detection name as key with the following data: applicable_to, location prefix and list with ATT&CK (sub) techniques
                {
                    {'Detection A': {'applicable_to': ['all'], 'location_prefix': 'SIEM', 'techniques': ['T1055']}}
                }
        :param  check_unused_detections: boolean. When True, all detections in YAML file will be checked against given detection_rules list. It's using
                                         the location field as list for detection rules including location_prefix as prefix: "Splunk: Detection A"
        :param  clean_unused_detections: boolean. When True, all detections in YAML file that don't exist in the given detection_rules list will be removed.
        :param clean_unused_applicable_to: boolean. When True, all detection objects with a applicable_to value that doesn't exist in the given detection_rules list will be removed.
        :return a list with results containing warnings or errors during the update process.
        """
        date_today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

        warnings, results = self._add_rules(detection_rules, date_today)
        w, r = self._delete_rules(detection_rules, check_unused_detections, clean_unused_detections, location_prefix_unused_detections, check_unused_applicable_to, clean_unused_applicable_to, date_today)
        warnings += w
        results += r

        return warnings, results

    def _add_rules(self, detection_rules: dict, date_today: datetime) -> list:
        """
        Adds new detection rules to the techniques YAML file. A score_logbook entry is added for every change.
        """
        warnings, results = [], []

        # Loop through all detection rules:
        for rule_name, rule_data in detection_rules.items():
            # Loop through every technique per rule:
            for technique_id in rule_data['techniques']:
                attack_technique = self._get_technique_from_attack(technique_id)
                if attack_technique is None:
                    warnings.append(f'Technique "{technique_id}" listed in detection rule "{rule_name}" does not exist in ATT&CK ({self.domain}). Skipping.')
                    continue

                location = rule_name if rule_data['location_prefix'] == '' else rule_data['location_prefix'] + ': ' + rule_name
                yaml_technique = self._get_technique_from_yaml(technique_id)
                if yaml_technique is not None:
                    # Check is applicable_to is already there:
                    applicable_to_list = [d['applicable_to'] for d in yaml_technique['detection']]
                    if rule_data['applicable_to'] in applicable_to_list:
                        # applicable_to already present, go to the right applicable_to:
                        for d in yaml_technique['detection']:
                            if d['applicable_to'] == rule_data['applicable_to']:
                                # Check if detection rule is in location field:
                                rule_exist = False
                                for loc in d['location']:
                                    if rule_name in loc:
                                        rule_exist = True
                                        break

                                # If detection rule is not yet in location field, add detection rule to location field:
                                if not rule_exist:
                                    d['location'].append(location)

                                    # Check if score_logbook already has entry for today:
                                    today_found = False
                                    for logbook_entry in d['score_logbook']:
                                        if logbook_entry['date'] == date_today:
                                            logbook_entry['comment'] += f'. Detection rule added: {rule_name}'
                                            today_found = True
                                            break

                                    if not today_found:
                                        d['score_logbook'].append({
                                            'date': date_today,
                                            'score': self._get_latest_score(d),
                                            'comment': f'Auto added by Dettectinator. TODO: Check score. Detection rule added: {rule_name}'
                                        })
                                        results.append(f'Check score for technique {technique_id}. Detection rule(s) added for applicable_to {d["applicable_to"]}.')

                                break
                    else:
                        # applicable_to not present, add new detection object:
                        new_detection = deepcopy(YAML_OBJ_DETECTION)
                        new_detection['applicable_to'] = rule_data['applicable_to']
                        new_detection['location'] = [location]
                        new_detection['score_logbook'][0]['date'] = date_today
                        new_detection['score_logbook'][0]['score'] = 1
                        new_detection['score_logbook'][0]['comment'] = f'Auto added by Dettectinator. TODO: Check score. applicable_to with detection rule added: {rule_name}'
                        yaml_technique['detection'].append(new_detection)
                        results.append(f'Check score for technique {technique_id}. applicable_to is new: {str(rule_data["applicable_to"])}.')
                else:
                    # Technique not present in YAML, add:
                    new_technique = deepcopy(YAML_OBJ_TECHNIQUE)
                    new_technique['technique_id'] = technique_id
                    new_technique['technique_name'] = attack_technique['name']
                    new_technique['detection'] = []
                    new_technique['visibility'] = []
                    new_detection = deepcopy(YAML_OBJ_DETECTION)
                    new_detection['applicable_to'] = rule_data['applicable_to']
                    new_detection['location'] = [location]
                    new_detection['score_logbook'][0]['date'] = date_today
                    new_detection['score_logbook'][0]['score'] = 1
                    new_detection['score_logbook'][0]['comment'] = f'Auto added by Dettectinator. TODO: Check score. Technique with detection rule added: {rule_name}'
                    new_technique['detection'].append(new_detection)
                    new_visibility = deepcopy(YAML_OBJ_VISIBILITY)
                    new_technique['visibility'].append(new_visibility)
                    self._yaml_content['techniques'].append(new_technique)
                    results.append(f'Check score for technique {technique_id}. Technique is new.')

        return warnings, results

    def _delete_rules(self, detection_rules: dict, check_unused_detections: bool, clean_unused_detections: bool, location_prefix_unused_detections: str, check_unused_applicable_to: bool, clean_unused_applicable_to: bool, date_today: datetime) -> list:
        """
        Removes detection rules from the techniques YAML file which are not in the given list of detection_rules. A score_logbook entry is added for every change.
        """
        # First categorize all detection rules per applicable_to:
        warnings, results = [], []
        applicable_to_rules = {}
        for rule_name, rule_data in detection_rules.items():
            if str(rule_data['applicable_to']) not in applicable_to_rules.keys():
                applicable_to_rules[str(rule_data['applicable_to'])] = {}  # cast key to string because a list cannot be a dictionary index name
            applicable_to_rules[str(rule_data['applicable_to'])][rule_name] = rule_data

        # Loop through all techniques in techniques YAML file:
        for yaml_technique in self._yaml_content['techniques']:
            # Look through all detection objects:
            to_remove = []
            for detection in yaml_technique['detection']:
                # Proceed if applicable to from YAML file exists in detection rules list:
                if str(detection['applicable_to']) in applicable_to_rules.keys():
                    # Get the rules for this applicable_to with the same ATT&CK technique:
                    rules_for_app_to = []
                    for rule_name, rule_data in applicable_to_rules[str(detection['applicable_to'])].items():
                        if yaml_technique['technique_id'] in rule_data['techniques']:
                            location = rule_name if rule_data['location_prefix'] == '' else rule_data['location_prefix'] + ': ' + rule_name
                            rules_for_app_to.append(location)

                    # Make a copy to loop through while editting the original location field:
                    locations = deepcopy(detection['location'])
                    for loc in locations:
                        if loc.startswith(location_prefix_unused_detections) and loc not in rules_for_app_to:
                            if check_unused_detections and not clean_unused_detections:
                                warnings.append('Rule from YAML not found in rules list: ' + loc)
                            elif check_unused_detections and clean_unused_detections:
                                detection['location'].remove(loc)
                                score = 0 if len(detection['location']) == 0 else self._get_latest_score(detection)

                                # Check if score_logbook already has entry for today:
                                today_found = False
                                for logbook_entry in detection['score_logbook']:
                                    if logbook_entry['date'] == date_today:
                                        logbook_entry['score'] = score
                                        logbook_entry['comment'] += f'. Detection rule removed: {loc}'
                                        today_found = True
                                        break

                                if not today_found:
                                    detection['score_logbook'].append({
                                        'date': date_today,
                                        'score': score,
                                        'comment': f'Auto added by Dettectinator. TODO: Check score. Detection rule removed: {loc}'
                                    })
                                    results.append(f'Check score for technique {yaml_technique["technique_id"]}. Detection rule(s) removed.')
                else:
                    if check_unused_applicable_to and not clean_unused_applicable_to:
                        warnings.append(f'YAML applicable_to for technique "{yaml_technique["technique_id"]}" not in rules list: {str(detection["applicable_to"])}.')
                    elif check_unused_applicable_to and clean_unused_applicable_to:
                        to_remove.append(detection)

            for item in to_remove:
                warnings.append(f'YAML applicable_to for technique "{yaml_technique["technique_id"]}" not in rules list, so removed: {str(detection["applicable_to"])}.')
                yaml_technique['detection'].remove(item)

        return warnings, results

    def _load_techniques(self) -> None:
        """
        Loads the normalized techniques (including detection and visibility properties) from the techniques YAML file.
        """
        my_techniques = {}

        for d in self._yaml_content['techniques']:
            if 'detection' in d:
                # Add detection items:
                if isinstance(d['detection'], dict):  # There is just one detection entry
                    d['detection'] = self._set_yaml_dv_comments(d['detection'])
                    self._add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'detection', d['detection'])
                elif isinstance(d['detection'], list):  # There are multiple detection entries
                    for de in d['detection']:
                        de = self._set_yaml_dv_comments(de)
                        self._add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'detection', de)

            if 'visibility' in d:
                # Add visibility items
                if isinstance(d['visibility'], dict):  # There is just one visibility entry
                    d['visibility'] = self._set_yaml_dv_comments(d['visibility'])
                    self._add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'visibility', d['visibility'])
                elif isinstance(d['visibility'], list):  # There are multiple visibility entries
                    for de in d['visibility']:
                        de = self._set_yaml_dv_comments(de)
                        self._add_entry_to_list_in_dictionary(my_techniques, d['technique_id'], 'visibility', de)

        self.techniques = my_techniques

    def _get_technique(self, technique_id: str) -> object:
        """
        Gets the technique from the normalized YAML techniques.
        """
        for tech_id, tech in self.techniques.items():
            if tech_id == technique_id:
                return tech

    def _get_technique_from_yaml(self, technique_id: str) -> object:
        """
        Gets the technique from the techniques YAML file.
        """
        for tech in self._yaml_content['techniques']:
            if tech['technique_id'] == technique_id:
                return tech

    @staticmethod
    def _get_latest_score(yaml_object: object) -> int or None:
        """
        Return the latest score present in the score_logbook
        :param yaml_object: a detection or visibility YAML object
        :return: score as an integer or None
        """
        score_obj = DettectTechniquesAdministration._get_latest_score_obj(yaml_object)
        if score_obj:
            return score_obj['score']
        else:
            return None

    @staticmethod
    def _get_latest_score_obj(yaml_object: object) -> object:
        """
        Get the score object in the score_logbook by date
        :param yaml_object: a detection or visibility YAML object
        :return: the latest score object
        """
        if not isinstance(yaml_object['score_logbook'], list):
            yaml_object['score_logbook'] = [yaml_object['score_logbook']]

        if len(yaml_object['score_logbook']) > 0 and 'date' in yaml_object['score_logbook'][0]:
            # for some weird reason 'sorted()' provides inconsistent results
            newest_score_obj = None
            newest_date = None
            for score_obj in yaml_object['score_logbook']:
                score_obj_date = score_obj['date']

                if not newest_score_obj or (score_obj_date and score_obj_date > newest_date):
                    newest_date = score_obj_date
                    newest_score_obj = score_obj

            return newest_score_obj
        else:
            return None


class DettectDataSourcesAdministration(DettectBase):
    """
    Create or modify a DeTT&CT data source administration YAML file.
    """

    def __init__(self, filename: str = None, domain: str = None, local_stix_path: str = None) -> None:
        super(DettectDataSourcesAdministration, self).__init__(filename, domain, local_stix_path)

        self._system_applicable_to_values = ['all']
        for s in self._yaml_content['systems']:
            self._system_applicable_to_values.append(s['applicable_to'])

        self._get_data_components_from_cti()

    def update_data_sources(self, data_sources: dict, check_unused_data_sources: bool = False, clean_unused_data_sources: bool = False) -> list:
        """
        Updates the data source YAML file with the given data sources. All data quality scores are set to "1" for new data sources.

        :param  data_sources: a dictionary of dictionaries containing data source name as key with the following data in a list: applicable_to,
                              products, available_for_data_analytics and data_quality. data_quality may be omitted of remain empty. In that case
                              default data quality scores of "1" will be used.
                {
                    { 'Process Creation': [{'applicable_to': ['all'],
                                           'products': ['Windows Event Log'],
                                           'available_for_data_analytics': True,
                                           'data_quality': {'device_completeness': 1,
                                                            'data_field_completeness': 1,
                                                            'timeliness': 1,
                                                            'consistency': 1,
                                                            'retention': 1}
                                           }]
                    }
                }
        :param  check_unused_data_sources: boolean. When True, all data sources in YAML file will be checked against given data_sources list.
        :param  clean_unused_data_sources: boolean. When True, all data sources in YAML file that don't exist in the given data_sources list will be removed.
        :return a list with results containing warnings or errors during the update process.
        """
        date_today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

        warnings, results = self._add_data_sources(data_sources, date_today)

        if check_unused_data_sources:
            w, r = self._delete_data_sources(data_sources, clean_unused_data_sources)
            warnings += w
            results += r

        return warnings, results

    def _add_data_sources(self, data_sources: dict, date_today: datetime) -> list:
        """
        Adds new data sources to the data source YAML file. A comment is added for every change.
        """
        warnings, results = [], []

        # Loop through all given data sources:
        for data_source_name, data_source_applicable_to in data_sources.items():
            if data_source_name.lower() not in self.data_components.keys():
                results.append(f'Data source "{data_source_name}" does not exist in ATT&CK ({self.domain}). Skipping.')
                continue
            else:
                data_source_name = self.data_components[data_source_name.lower()]

            # Check if data source is already present in YAML file:
            yaml_data_source = self._get_data_source_from_yaml(data_source_name)
            if yaml_data_source is None:
                # Data source not present in YAML, add:
                new_data_source_object = deepcopy(YAML_OBJ_DATA_SOURCES)
                new_data_source_object['data_source_name'] = data_source_name
                new_data_source_object['data_source'] = []
                self._yaml_content['data_sources'].append(new_data_source_object)
                yaml_data_source = new_data_source_object
                results.append(f'Check data quality scores for data source {data_source_name}. Data source is new.')

            # Loop through all given applicable_to values:
            for data_source_data in data_source_applicable_to:
                # Health check: is given applicable_to present in systems object. If not: it will be added with platform=all
                for a in data_source_data['applicable_to']:
                    if a not in self._system_applicable_to_values:
                        self._yaml_content['systems'].append({'applicable_to': a, 'platform': ['all']})
                        self._system_applicable_to_values.append(a)
                        results.append(f'Applicable_to value "{str(data_source_data["applicable_to"])}" of data source "{data_source_name}" not in systems object of data source YAML file. Added to systems object with platform=all. Please review this new entry.')

                # Check if applicable_to is already there:
                applicable_to_list = [d['applicable_to'] for d in yaml_data_source['data_source']]
                if data_source_data['applicable_to'] not in applicable_to_list:
                    # applicable_to not present, add new data source object:
                    new_data_source = deepcopy(YAML_OBJ_DATA_SOURCE)
                    new_data_source['applicable_to'] = data_source_data['applicable_to']
                    new_data_source['date_registered'] = date_today
                    new_data_source['date_connected'] = date_today
                    new_data_source['products'] = data_source_data['products']
                    new_data_source['available_for_data_analytics'] = data_source_data['available_for_data_analytics']
                    default_scores, scores_changed = self._set_data_quality(new_data_source, data_source_data)
                    new_data_source['comment'] = 'Auto added by Dettectinator.' + (' TODO: Check data quality scores, default values used.' if default_scores else '')
                    yaml_data_source['data_source'].append(new_data_source)
                    results.append(f'Check data quality scores for data source {data_source_name}. applicable_to is new: {str(data_source_data["applicable_to"])}')
                else:
                    # applicable_to present, get the object and update:
                    for data_source in yaml_data_source['data_source']:
                        if data_source['applicable_to'] == data_source_data['applicable_to']:
                            changed = False
                            if data_source['products'] != data_source_data['products']:
                                data_source['products'] = data_source_data['products']
                                changed = True
                            if data_source['available_for_data_analytics'] != data_source_data['available_for_data_analytics']:
                                data_source['available_for_data_analytics'] = data_source_data['available_for_data_analytics']
                                changed = True
                            default_scores, scores_changed = self._set_data_quality(data_source, data_source_data)
                            if scores_changed:
                                changed = True
                            if changed:
                                data_source['comment'] = 'Auto updated by Dettectinator. TODO: Check data quality scores.'
                                results.append(f'Check data quality scores for data source {data_source_name}. Data source with applicable_to {str(data_source_data["applicable_to"])} is updated.')
                            break

        return warnings, results

    def _delete_data_sources(self, data_sources: list, clean_unused_data_sources: bool) -> list:
        """
        Removes data sources from the data source YAML file which are not in the given data_sources list. A comment is added for every change.
        """
        warnings, results = [], []

        data_sources_lowercase = [ds.lower() for ds in data_sources.keys()]

        # Loop through all data sources in YAML file:
        to_remove = []
        for yaml_data_source in self._yaml_content['data_sources']:
            # Check if data source is present in data_sources list:
            if yaml_data_source['data_source_name'].lower() in data_sources_lowercase:
                # Data source is present, now check if applicable_to's from YAML are present in data_sources list.

                # Assemble all applicable_to's from data_source list:
                applicable_to_ds = []
                for data_source_applicable_to in data_sources.values():
                    for data_source_data in data_source_applicable_to:
                        applicable_to_ds.append(str(data_source_data['applicable_to']))

                # Make a copy to loop through applicable_to's in YAML (so that original can be mutated):
                applicable_to_yaml = deepcopy(yaml_data_source['data_source'])
                for app_to in applicable_to_yaml:
                    if str(app_to['applicable_to']) not in applicable_to_ds:
                        yaml_data_source['data_source'].remove(app_to)
                        warnings.append(f'YAML applicable_to value "{str(app_to["applicable_to"])}" of data source "{yaml_data_source["data_source_name"]}" not in given data sources list, so removed.')
            else:
                # Data source in YAML but not in data_sources list. So remove.
                if not clean_unused_data_sources:
                    warnings.append(f'YAML data source "{yaml_data_source["data_source_name"]}" not in given data sources list.')
                else:
                    to_remove.append(yaml_data_source)

        for item in to_remove:
            self._yaml_content['data_sources'].remove(item)
            warnings.append(f'YAML data source "{item["data_source_name"]}" not in given data sources list, so removed.')

        return warnings, results

    @staticmethod
    def _set_data_quality(new_data_source_object, data_source_data):
        if 'data_quality' in data_source_data.keys() and data_source_data['data_quality'] != {}:
            changed = False
            if new_data_source_object['data_quality']['device_completeness'] != data_source_data['data_quality']['device_completeness']:
                new_data_source_object['data_quality']['device_completeness'] = data_source_data['data_quality']['device_completeness']
                changed = True
            if new_data_source_object['data_quality']['data_field_completeness'] != data_source_data['data_quality']['data_field_completeness']:
                new_data_source_object['data_quality']['data_field_completeness'] = data_source_data['data_quality']['data_field_completeness']
                changed = True
            if new_data_source_object['data_quality']['timeliness'] != data_source_data['data_quality']['timeliness']:
                new_data_source_object['data_quality']['timeliness'] = data_source_data['data_quality']['timeliness']
                changed = True
            if new_data_source_object['data_quality']['consistency'] != data_source_data['data_quality']['consistency']:
                new_data_source_object['data_quality']['consistency'] = data_source_data['data_quality']['consistency']
                changed = True
            if new_data_source_object['data_quality']['retention'] != data_source_data['data_quality']['retention']:
                new_data_source_object['data_quality']['retention'] = data_source_data['data_quality']['retention']
                changed = True
            return False, changed
        else:
            new_data_source_object['data_quality']['device_completeness'] = 1
            new_data_source_object['data_quality']['data_field_completeness'] = 1
            new_data_source_object['data_quality']['timeliness'] = 1
            new_data_source_object['data_quality']['consistency'] = 1
            new_data_source_object['data_quality']['retention'] = 1
            return True, False

    def _get_data_source_from_yaml(self, data_source_name: str) -> object:
        """
        Gets the data source from the data source YAML file.
        """
        for ds in self._yaml_content['data_sources']:
            if ds['data_source_name'] == data_source_name:
                return ds

    def _get_data_components_from_cti(self) -> object:
        """
        Get all data component STIX objects from CTI for the provided ATT&CK Matrix
        :param matrix: ATT&CK Matrix
        :return: list of data component STIX objects
        """
        if self.domain == 'enterprise-attack':
            data_components = self.mitre.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "x-mitre-data-component"))
        elif self.domain == 'ics-attack':
            # ICS data components are not yet in CTI, so this will not work
            data_components = self.mitre.TC_ICS_SOURCE.query(Filter("type", "=", "x-mitre-data-component"))
        elif self.domain == 'mobile-attack':
            # Mobile data components are not yet in CTI, so this will not work
            data_components = self.mitre.TC_MOBILE_SOURCE.query(Filter("type", "=", "x-mitre-data-component"))

        self.data_components = {}
        for data_component in data_components:
            self.data_components[data_component['name'].lower()] = data_component['name']


if __name__ == '__main__':
    # Where being run from the command line here, start CLI logic
    cli_mod = importlib.import_module('cli')
    cli= getattr(cli_mod, 'CommandLine')()
    cli.start()
