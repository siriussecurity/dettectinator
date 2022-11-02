"""
Dettectinator - The Python library to your DeTT&CT YAML files.
Authors:
    Martijn Veken, Sirius Security
    Ruben Bouman, Sirius Security
License: GPL-3.0 License
"""

from plugins.support.msal_patch import PublicClientApplicationPatch
import msal
import datetime
import json
import requests


class Azure:
    """
    Class for authenticating agaings Azure AD
    """

    def __init__(self):
        pass

    @staticmethod
    def connect_device_flow(app_id: str, tenant_id: str, endpoint: str) -> str:
        """
        Login to Azure AD using  Device Flow authentication
        :return: Access token to use with the API
        """
        authority = 'https://login.microsoftonline.com/' + tenant_id
        scope = [endpoint + '/.default']

        app = PublicClientApplicationPatch(app_id, authority=authority)

        # Insert a User-Agent header to mimic a Windows device
        # This can be changed to adapt to certain Conditional Access Policies
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36 Edg/106.0.1370.34'  # This is another valid field
        }

        flow = app.initiate_device_flow(scopes=scope, headers=headers)
        if 'user_code' not in flow:
            raise Exception('Azure: Failed to create device flow. Err: %s' % json.dumps(flow, indent=4))

        print(flow['message'])
        print('Waiting for authentication...\n')
        logon_result = app.acquire_token_by_device_flow(flow, headers=headers)

        if 'access_token' in logon_result:
            print('You have been succesfully logged in: ')
            print(f'Name: {logon_result["id_token_claims"]["name"]}')
            print(f'UPN: {logon_result["id_token_claims"]["preferred_username"]}')
            print(f'Token expiration: {datetime.datetime.fromtimestamp(logon_result["id_token_claims"]["exp"]).isoformat()}')
            return logon_result['access_token']
        else:
            raise Exception('Azure: Failed to logon to Azure AD.')

    @staticmethod
    def connect_client_secret(app_id: str, tenant_id: str, endpoint: str, secret: str) -> str:
        """
        Login to Azure AD using Client secret authentication
        :return: Access token to use with the API
        """
        authority = 'https://login.microsoftonline.com/' + tenant_id
        scope = [endpoint + '/.default']

        app = msal.ConfidentialClientApplication(app_id, authority=authority, client_credential=secret)

        logon_result = app.acquire_token_for_client(scopes=scope)

        if "access_token" in logon_result:
            print('You have been succesfully logged in.')
            print(f'Token expires in {logon_result["expires_in"]} seconds.')
            return logon_result['access_token']
        else:
            raise Exception('Azure: Failed to logon to Azure AD.')


class Tanium:
    """
    Class to authenticate against Tanium
    """

    def __init__(self):
        pass

    @staticmethod
    def connect_http(user: str, password: str, login_url: str) -> str:
        """
        Logs in to the Tanium host and saves the session ticket.
        """
        data = {'username': user, 'password': password}
        r = requests.post(login_url, data=json.dumps(data), verify=False)
        if r.status_code == 200:
            return r.json()['data']['session']
        else:
            raise Exception('Tanium: login failed.')
