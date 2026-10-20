import pytest

from mock_idp.errors import OAuthError
from mock_idp.pkce import Pkce, parse_pkce, pkce_matches, s256


def test_s256_matches_the_rfc_7636_example():
  assert s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_s256_verifier_matches():
  verifier = "v" * 50
  assert pkce_matches(Pkce(s256(verifier), "S256"), verifier)


def test_plain_verifier_matches():
  assert pkce_matches(Pkce("secret", "plain"), "secret")


@pytest.mark.parametrize("pkce", [Pkce(s256("right"), "S256"), Pkce("right", "plain")])
def test_wrong_verifier_does_not_match(pkce):
  assert not pkce_matches(pkce, "wrong")


@pytest.mark.parametrize("verifier", ["", None])
def test_empty_or_missing_verifier_does_not_match(verifier):
  assert not pkce_matches(Pkce("x", "plain"), verifier)


@pytest.mark.parametrize("method", ["plain", "S256"])
def test_non_ascii_verifier_is_a_mismatch(method):
  assert not pkce_matches(Pkce("abc", method), "é")


def test_parse_supported_methods():
  assert parse_pkce({"code_challenge": "c", "code_challenge_method": "S256"}) == Pkce("c", "S256")
  assert parse_pkce({"code_challenge": "c", "code_challenge_method": "plain"}) == Pkce("c", "plain")


def test_absent_method_means_plain():
  assert parse_pkce({"code_challenge": "c"}) == Pkce("c", "plain")


@pytest.mark.parametrize("method", ["S512", ""])
def test_unsupported_or_empty_method_is_an_error(method):
  with pytest.raises(OAuthError) as error:
    parse_pkce({"code_challenge": "c", "code_challenge_method": method})
  assert error.value.error == "invalid_request" and error.value.status == 400


def test_no_challenge_means_no_pkce():
  assert parse_pkce({}) is None
  assert parse_pkce({"code_challenge": ""}) is None


@pytest.mark.parametrize("method", ["S512", ""])
def test_method_is_ignored_without_a_challenge(method):
  assert parse_pkce({"code_challenge_method": method}) is None
  assert parse_pkce({"code_challenge": "", "code_challenge_method": method}) is None
