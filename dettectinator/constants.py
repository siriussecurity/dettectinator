"""
The contents of this file are taken with permission from the DeTT&CT project (http://github.com/rabobank-cdc/DeTTECT).
"""

PLATFORMS_ENTERPRISE = {'pre': 'PRE', 'windows': 'Windows', 'macos': 'macOS', 'linux': 'Linux', 'office 365': 'Office 365',
                        'azure ad': 'Azure AD', 'google workspace': 'Google Workspace', 'iaas': 'IaaS', 'saas': 'SaaS',
                        'network': 'Network', 'containers': 'Containers'}

PLATFORMS_ICS = {'control server': 'Control Server', 'data historian': 'Data Historian', 'device configuration/parameters': 'Device Configuration/Parameters',
                 'engineering workstation': 'Engineering Workstation', 'field controller/rtu/plc/ied': 'Field Controller/RTU/PLC/IED',
                 'human-machine interface': 'Human-Machine Interface', 'input/output server': 'Input/Output Server',
                 'safety instrumented system/protection relay': 'Safety Instrumented System/Protection Relay', 'windows': 'Windows',
                 'none': 'None'}

PLATFORMS_MOBILE = {'android': 'Android', 'ios': 'iOS'}

YAML_OBJ_DETECTION = {'applicable_to': ['all'],
                      'location': [''],
                      'comment': '',
                      'score_logbook':
                          [
                              {'date': None,
                               'score': -1,
                               'comment': ''}
                      ]}

YAML_OBJ_VISIBILITY = {'applicable_to': ['all'],
                       'comment': '',
                       'score_logbook':
                           [
                               {'date': None,
                                'score': 0,
                                'comment': '',
                                'auto_generated': True}
                           ]
                       }

YAML_OBJ_TECHNIQUE = {'technique_id': '',
                      'technique_name': '',
                      'detection': [YAML_OBJ_DETECTION],
                      'visibility': [YAML_OBJ_VISIBILITY]}

YAML_OBJ_NEW_TECHNIQUES_FILE = {'version': 1.2,
                                'file_type': 'technique-administration',
                                'name': 'new',
                                'domain': 'enterprise-attack',
                                'platform': ['all'],
                                'techniques': []
                               }

YAML_OBJ_DATA_SOURCE = {'applicable_to': ['all'],
                        'date_registered': None,
                        'date_connected': None,
                        'products': [],
                        'available_for_data_analytics': False,
                        'comment': '',
                        'data_quality': {
                            'device_completeness': 0,
                            'data_field_completeness': 0,
                            'timeliness': 0,
                            'consistency': 0,
                            'retention': 0}
                        }

YAML_OBJ_DATA_SOURCES = {'data_source_name': '',
                         'data_source': [YAML_OBJ_DATA_SOURCE]}

YAML_OBJ_NEW_DATA_SOURCES_FILE = {'version': 1.1,
                                  'file_type': 'data-source-administration',
                                  'name': 'new',
                                  'domain': 'enterprise-attack',
                                  'systems': [{ 'applicable_to': 'default', 'platform': ['all'] }],
                                  'data_sources': []
                                 }

YAML_OBJ_NEW_GROUPS_FILE = {'version': 1.0,
                            'file_type': 'group-administration',
                            'domain': 'enterprise-attack',
                            'platform': ['all'],
                            'groups': []
                           }