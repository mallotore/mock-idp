import base64

import pytest
from flask import Flask

from mock_idp.errors import OAuthError
from mock_idp.parsing import client_credentials, parse_authorize_request, request_data, require_authorization_code_grant
from mock_idp.pkce import Pkce
from mock_idp.settings import Settings

from helpers import CLIENT_ID, REDIRECT

SETTINGS = Settings()

app = Flask(__name__)


def basic(value):
  return {"Authorization": "Basic " + base64.b64encode(value.encode()).decode()}


def test_client_credentials_from_basic_auth():
  with app.test_request_context("/token", method="POST", headers=basic("id:secret")):
    assert client_credentials() == ("id", "secret")


def test_basic_auth_credentials_are_form_urldecoded():
  with app.test_request_context("/token", method="POST", headers=basic("my%40id:s3cr%2Bt%2F%25")):
    assert client_credentials() == ("my@id", "s3cr+t/%")


@pytest.mark.parametrize("header", ["Basic !!!not-base64", "Basic " + base64.b64encode(b"\xff\xfe").decode()])
def test_bad_basic_header_gives_no_credentials(header):
  with app.test_request_context("/token", method="POST", headers={"Authorization": header}):
    assert client_credentials() == (None, None)


def test_client_credentials_fall_back_to_the_form_body():
  with app.test_request_context("/token", method="POST", data={"client_id": "id", "client_secret": "s"}):
    assert client_credentials() == ("id", "s")


def test_client_credentials_fall_back_to_the_json_body():
  with app.test_request_context("/token", method="POST", json={"client_id": "id"}):
    assert client_credentials() == ("id", None)


def test_request_data_prefers_the_form():
  with app.test_request_context("/token", method="POST", data={"code": "c"}):
    assert request_data()["code"] == "c"


def test_request_data_reads_a_json_object():
  with app.test_request_context("/token", method="POST", json={"code": "c"}):
    assert request_data() == {"code": "c"}


@pytest.mark.parametrize("body", [[1], "x", 5])
def test_request_data_ignores_non_object_json(body):
  with app.test_request_context("/token", method="POST", json=body):
    assert request_data() == {}


def test_parse_authorize_request():
  req = parse_authorize_request(
    {
      "redirect_uri": REDIRECT,
      "state": "s",
      "nonce": "n",
      "client_id": CLIENT_ID,
      "code_challenge": "c",
      "code_challenge_method": "S256",
    },
    SETTINGS,
  )
  assert (req.redirect_uri, req.state, req.nonce) == (REDIRECT, "s", "n")
  assert req.pkce == Pkce("c", "S256")


@pytest.mark.parametrize(
  "args, error",
  [
    ({"redirect_uri": REDIRECT, "response_type": "token"}, "unsupported_response_type"),
    ({"redirect_uri": REDIRECT, "scope": "email"}, "invalid_scope"),
    ({}, "invalid_request"),
    ({"redirect_uri": REDIRECT, "client_id": "other"}, "unauthorized_client"),
    ({"redirect_uri": REDIRECT, "code_challenge": "c", "code_challenge_method": ""}, "invalid_request"),
  ],
)
def test_invalid_authorize_requests(args, error):
  with pytest.raises(OAuthError) as raised:
    parse_authorize_request(args, SETTINGS)
  assert raised.value.error == error


def test_only_the_authorization_code_grant_is_supported():
  require_authorization_code_grant({"grant_type": "authorization_code"})
  require_authorization_code_grant({})
  with pytest.raises(OAuthError, match="unsupported_grant_type"):
    require_authorization_code_grant({"grant_type": "password"})


def test_non_string_token_parameters_are_rejected():
  with pytest.raises(OAuthError) as raised:
    require_authorization_code_grant({"code": [1]})
  assert raised.value.error == "invalid_request"
