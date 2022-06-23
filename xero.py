from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import WebApplicationClient
from oauthlib.oauth2.rfc6749.errors import InvalidGrantError
from xml.etree.ElementTree import fromstring
import secrets
import hashlib
import base64
import argparse
import pathlib
import json
import requests


# Zap the very unhelpful behaviour from oauthlib when Xero returns
# more scopes than requested
import os
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = "true"


XERO_ENDPOINT_URL = "https://api.xero.com/api.xro/2.0/"
XERO_AUTHORIZE_URL = "https://login.xero.com/identity/connect/authorize"
XERO_CONNECT_URL = "https://identity.xero.com/connect/token"
XERO_REVOKE_URL = "https://identity.xero.com/connect/revocation"
XERO_CONNECTIONS_URL = "https://api.xero.com/connections"


class PKCE(WebApplicationClient):
    """Proof Key for Code Exchange by OAuth Public Clients - RFC7636
    """
    @staticmethod
    def _b64encode_without_padding(b):
        return base64.urlsafe_b64encode(b).split(b'=')[0]

    def prepare_request_uri(self, *args, **kwargs):
        self.code_verifier = self._b64encode_without_padding(
            secrets.token_bytes(32))
        code_challenge = self._b64encode_without_padding(
            hashlib.sha256(self.code_verifier).digest())
        return super().prepare_request_uri(
            *args, code_challenge=code_challenge,
            code_challenge_method="S256", **kwargs)

    def prepare_request_body(self, *args, **kwargs):
        return super().prepare_request_body(
            *args, code_verifier=self.code_verifier, **kwargs)


def connection_ok(state):
    if "client_id" not in state:
        return False
    if "redirect_uri" not in state:
        return False
    if "token" not in state:
        return False
    if "tenant_id" not in state:
        return False

    session = xero_session(state, omit_tenant=True)
    try:
        r = session.get(XERO_CONNECTIONS_URL)
    except InvalidGrantError:
        return False
    if r.status_code != 200:
        return False
    connections = r.json()
    for tenant in connections:
        if tenant['tenantId'] == state["tenant_id"]:
            return True
    return False


def xero_session(state, omit_tenant=False):
    kwargs = {}

    def token_updater(token):
        state["token"] = token

    kwargs['token'] = state.get("token")
    kwargs['token_updater'] = token_updater
    kwargs['auto_refresh_kwargs'] = {
        'client_id': state["client_id"],
    }
    kwargs['auto_refresh_url'] = XERO_CONNECT_URL

    session = OAuth2Session(
        state["client_id"],
        client=PKCE(state["client_id"]),
        redirect_uri=state["redirect_uri"],
        scope=["offline_access", "accounting.transactions",
               "accounting.contacts", "accounting.settings"],
        **kwargs)

    if not omit_tenant:
        session.headers = {
            'xero-tenant-id': state["tenant_id"],
            'accept': 'application/xml',
        }

    return session


def connect(state):
    if "client_id" not in state:
        state["client_id"] = input("Client ID: ")
    if "redirect_uri" not in state:
        state["redirect_uri"] = input("Redirect URI: ")

    session = xero_session(state, omit_tenant=True)
    auth_url, auth_state = session.authorization_url(XERO_AUTHORIZE_URL)

    print(f"Visit this page in your browser:\n{auth_url}\n")

    auth_response = input("After authorising, paste the URL provided here: ")

    print()

    state["token"] = session.fetch_token(
        XERO_CONNECT_URL,
        client_id=state["client_id"],
        authorization_response=auth_response)

    # Fetch the list of tenants
    r = session.get(XERO_CONNECTIONS_URL)
    if r.status_code != 200:
        print("Failed to get the list of Xero tenants")
        r.raise_for_status()
    connections = r.json()
    for idx, tenant in enumerate(connections):
        print(f"{idx}: {tenant['tenantId']} {tenant['tenantName']}")
    print()
    num = input("Number of tenant to use: ")
    state["tenant_id"] = connections[int(num)]['tenantId']


def disconnect(state):
    xero = xero_session(state, omit_tenant=True)
    r = requests.post(XERO_REVOKE_URL, auth=(state["client_id"], ""),
                      data={'token': xero.token['refresh_token']})
    if r.status_code == 200:
        del state["token"]
        print("Disconnected from Xero.")
    else:
        print(f"Failed to disconnect from Xero: {r.status_code=}")


def fieldtext(c, field):
    f = c.find(field)
    if f is None:
        return
    return f.text


def print_organisation_details(session):
    r = session.get(XERO_ENDPOINT_URL + "Organisation/")
    if r.status_code != 200:
        print("Failed to retrieve organisation details from Xero: "
              f"http status code {r.status_code}")
        return

    root = fromstring(r.text)
    if root.tag != "Response":
        print("Failed to retrieve organisation details from Xero: "
              f"root element of response was '{root.tag}' instead of "
              "'Response'")
        return
    org = None
    orgs = root.find("Organisations")
    if orgs is not None:
        org = orgs.find("Organisation")
    if org is None:
        print("There were no organisation details in the response "
              "from Xero.")
        return

    print(f"Organisation name: {fieldtext(org, 'Name')}")
    print(f"Short code: {fieldtext(org, 'ShortCode')}")


def demo():
    parser = argparse.ArgumentParser(
        description="Connect to the Xero API")
    parser.add_argument('--statefile', type=pathlib.Path,
                        default=pathlib.Path("xerostate.json"))
    parser.add_argument('--disconnect', action="store_true")

    args = parser.parse_args()

    try:
        with open(args.statefile) as f:
            state = json.load(f)
    except Exception:
        state = {}

    try:
        if not connection_ok(state):
            connect(state)

        session = xero_session(state)

        print_organisation_details(session)

        if args.disconnect:
            disconnect(state)

    finally:
        with open(args.statefile, 'w') as f:
            json.dump(state, f)
