import pytest

from oic.extension.device_flow import (
    AuthorizationRequest,
    DeviceFlowServer,
    DeviceState,
    TokenRequest,
)
from oic.oauth2 import Server
from oic.oauth2.message import AccessTokenResponse, ErrorResponse

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
CLIENT_ID = "client_1"
OTHER_CLIENT_ID = "client_2"


@pytest.fixture
def server():
    return DeviceFlowServer(Server(), verification_uri="https://op.example.com/device")


def _device_request(client_id=CLIENT_ID):
    return AuthorizationRequest(client_id=client_id, response_type="device_code")


def _token_request(device_code, client_id=CLIENT_ID):
    return TokenRequest(grant_type=GRANT_TYPE, device_code=device_code, client_id=client_id)


class TestDeviceEndpoint:
    def test_issues_response_and_state(self, server):
        resp = server.device_endpoint(_device_request())

        assert resp["device_code"]
        assert resp["user_code"]
        assert resp["verification_uri"] == "https://op.example.com/device"
        assert resp["expires_in"] == server.device_code_life_time
        assert resp["interval"] == server.interval

        state = server.device_states[resp["device_code"]]
        assert isinstance(state, DeviceState)
        assert state.client_id == CLIENT_ID
        assert state.user_code == resp["user_code"]
        assert state.authorized is False
        assert server.user_code2device[resp["user_code"]] == resp["device_code"]


class TestTokenEndpoint:
    def test_authorization_pending(self, server):
        resp = server.device_endpoint(_device_request())
        token_resp = server.token_endpoint(_token_request(resp["device_code"]))

        assert isinstance(token_resp, ErrorResponse)
        assert token_resp["error"] == "authorization_pending"

    def test_unknown_device_code(self, server):
        token_resp = server.token_endpoint(_token_request("no-such-code"))

        assert isinstance(token_resp, ErrorResponse)
        assert token_resp["error"] == "invalid_grant"

    def test_slow_down(self, server):
        server.device_endpoint(_device_request())
        resp = server.device_endpoint(_device_request())
        dc = resp["device_code"]

        first = server.token_endpoint(_token_request(dc))
        assert first["error"] == "authorization_pending"

        # immediate second poll is too fast
        second = server.token_endpoint(_token_request(dc))
        assert isinstance(second, ErrorResponse)
        assert second["error"] == "slow_down"

        # RFC 8628: interval grows by 5 seconds on slow_down
        state = server.device_states[dc]
        assert state.interval == server.interval + 5

    def test_expired_token(self, server):
        resp = server.device_endpoint(_device_request())
        dc = resp["device_code"]
        server.device_states[dc].expires_at = 1  # long gone

        token_resp = server.token_endpoint(_token_request(dc))
        assert isinstance(token_resp, ErrorResponse)
        assert token_resp["error"] == "expired_token"

    def test_expired_state_check(self, server):
        resp = server.device_endpoint(_device_request())
        state = server.device_states[resp["device_code"]]
        assert not state.is_expired()
        assert state.is_expired(now=state.expires_at + 1)

    def test_cross_client_polling_rejected(self, server):
        resp = server.device_endpoint(_device_request())
        dc = resp["device_code"]
        server.device_auth(resp["user_code"])

        # another client must not be able to redeem the device code
        token_resp = server.token_endpoint(_token_request(dc, client_id=OTHER_CLIENT_ID))
        assert isinstance(token_resp, ErrorResponse)
        assert token_resp["error"] == "invalid_grant"
        assert "access_token" not in token_resp

        # state must be untouched so the legitimate client can still redeem
        assert dc in server.device_states
        token_resp = server.token_endpoint(_token_request(dc, client_id=CLIENT_ID))
        assert isinstance(token_resp, AccessTokenResponse)
        assert token_resp["access_token"]

    def test_full_flow_issues_token_and_consumes_state(self, server):
        resp = server.device_endpoint(_device_request())
        dc = resp["device_code"]

        pending = server.token_endpoint(_token_request(dc))
        assert pending["error"] == "authorization_pending"

        server.device_auth(resp["user_code"])
        assert server.device_states[dc].authorized is True

        # avoid slow_down by resetting the poll timestamp
        server.device_states[dc].last_poll_at = 0
        token_resp = server.token_endpoint(_token_request(dc))
        assert isinstance(token_resp, AccessTokenResponse)
        assert token_resp["access_token"]
        assert token_resp["token_type"] == "Bearer"

        # device code is consumed; further polls fail
        assert dc not in server.device_states
        assert resp["user_code"] not in server.user_code2device
        again = server.token_endpoint(_token_request(dc))
        assert again["error"] == "invalid_grant"

    def test_access_denied(self, server):
        resp = server.device_endpoint(_device_request())
        server.device_auth(resp["user_code"], accept=False)

        token_resp = server.token_endpoint(_token_request(resp["device_code"]))
        assert isinstance(token_resp, ErrorResponse)
        assert token_resp["error"] == "access_denied"
