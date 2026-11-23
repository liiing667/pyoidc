from base64 import b64encode

import pytest

from oic.exception import FailedAuthentication
from oic.oauth2.message import AccessTokenRequest
from oic.oic import JWT_BEARER
from oic.oic.message import AuthnToken
from oic.oic.message import AuthorizationRequest
from oic.utils.authn.client import AuthnFailure
from oic.utils.authn.client import ClientSecretJWT
from oic.utils.authn.client import get_client_id
from oic.utils.keyio import KeyJar
from oic.utils.time_util import utc_time_sans_frac

CDB = {
    "number5": {"client_secret": "drickyoughurt"},
    "token_client": {},
    "expired": {"client_secret": "drickyoughurt", "client_secret_expires_at": 1},
    "secret_token": "token_client",
    "expired_token": "expired",
}


class TestGetClientID:
    def setup_class(self):
        self.cdb = CDB.copy()

    def test_empty_authn_client_ok(self):
        bib = {"client_id": "number5"}
        arq = AuthorizationRequest(**bib)
        assert get_client_id(self.cdb, arq, None) == "number5"

    def test_empty_authn_client_missing(self):
        bib = {"client_id": "missing"}
        arq = AuthorizationRequest(**bib)
        with pytest.raises(FailedAuthentication):
            get_client_id(self.cdb, arq, None)

    def test_empty_authn_empty_request(self):
        with pytest.raises(FailedAuthentication):
            get_client_id(self.cdb, AuthorizationRequest(), None)

    def test_empty_authn_client_invalid(self):
        bib = {"client_id": "expired"}
        arq = AuthorizationRequest(**bib)
        with pytest.raises(FailedAuthentication):
            get_client_id(self.cdb, arq, None)

    def test_wrong_authn(self):
        with pytest.raises(FailedAuthentication):
            get_client_id(self.cdb, AuthorizationRequest(), "mumbo jumbo")

    def test_basic_authn_client_ok(self):
        authn = "Basic " + b64encode(b"number5:drickyoughurt").decode()
        assert get_client_id(self.cdb, AuthorizationRequest(), authn)

    def test_basic_authn_client_missing(self):
        authn = "Basic " + b64encode(b"missing:drickyoughurt").decode()
        with pytest.raises(FailedAuthentication):
            get_client_id(self.cdb, AuthorizationRequest(), authn)

    def test_basic_authn_client_wrongpass(self):
        authn = "Basic " + b64encode(b"number5:wrongpassword").decode()
        with pytest.raises(FailedAuthentication):
            get_client_id(self.cdb, AuthorizationRequest(), authn)

    def test_basic_authn_client_invalid(self):
        authn = "Basic " + b64encode(b"expired:drickyoughurt").decode()
        with pytest.raises(FailedAuthentication):
            get_client_id(self.cdb, AuthorizationRequest(), authn)

    def test_bearer_authn_client_ok(self):
        authn = "Bearer secret_token"
        assert get_client_id(self.cdb, AuthorizationRequest(), authn) == "token_client"

    def test_bearer_authn_client_missing(self):
        authn = "Bearer wrong_token"
        with pytest.raises(FailedAuthentication):
            get_client_id(self.cdb, AuthorizationRequest(), authn)

    def test_bearer_authn_client_invalid(self):
        authn = "Bearer expired_token"
        with pytest.raises(FailedAuthentication):
            get_client_id(self.cdb, AuthorizationRequest(), authn)


class _ClientAssertionProvider:
    """Minimal provider interface used by :class:`ClientSecretJWT` verification."""

    def __init__(self):
        self.baseurl = "https://op.example.com"
        self.client_id = "client-a"
        self.client_secret = "client-a-secret"
        self.cdb = {
            "client-a": {"client_secret": self.client_secret},
            "client-b": {"client_secret": "client-b-secret"},
        }
        self.keyjar = KeyJar()
        self.keyjar.add_symmetric("client-a", self.client_secret)

    def assertion(self, jti="assertion-1", exp=None, iss=None, sub=None):
        now = utc_time_sans_frac()
        token = AuthnToken(
            iss=iss or self.client_id,
            sub=sub or iss or self.client_id,
            aud="https://op.example.com/token",
            jti=jti,
            exp=now + 60 if exp is None else exp,
            iat=now,
        )
        keys = self.keyjar.get_signing_key("oct", owner="client-a")
        return token.to_jwt(key=keys, algorithm="HS256")

    @staticmethod
    def request(assertion, **kwargs):
        return AccessTokenRequest(
            client_assertion=assertion,
            client_assertion_type=JWT_BEARER,
            **kwargs,
        )


class TestClientAssertionReplay:
    def test_assertion_can_only_be_used_once(self):
        provider = _ClientAssertionProvider()
        assertion = provider.assertion()
        authn = ClientSecretJWT(provider)

        cid, method = authn.verify(provider.request(assertion))
        assert (cid, method) == ("client-a", "client_secret_jwt")

        with pytest.raises(AuthnFailure):
            authn.verify(provider.request(assertion))

    def test_assertion_cannot_be_replayed_by_another_client(self):
        provider = _ClientAssertionProvider()
        assertion = provider.assertion()
        authn = ClientSecretJWT(provider)

        # Client B cannot use an assertion that was issued to client A.
        with pytest.raises(AuthnFailure):
            authn.verify(provider.request(assertion, client_id="client-b"))

        # The same holds after client A used the assertion successfully.
        authn.verify(provider.request(assertion))
        with pytest.raises(AuthnFailure):
            authn.verify(provider.request(assertion, client_id="client-b"))

    def test_expired_assertion_is_rejected(self):
        provider = _ClientAssertionProvider()
        assertion = provider.assertion(exp=utc_time_sans_frac() - 1)

        with pytest.raises(AuthnFailure):
            ClientSecretJWT(provider).verify(provider.request(assertion))

    def test_new_assertion_is_accepted(self):
        provider = _ClientAssertionProvider()
        authn = ClientSecretJWT(provider)

        authn.verify(provider.request(provider.assertion(jti="assertion-1")))
        authn.verify(provider.request(provider.assertion(jti="assertion-2")))
