from oic import rndstr
from oic.extension.single import SingleClient, SingleService
from oic.oauth2.message import (
    SINGLE_OPTIONAL_INT,
    SINGLE_OPTIONAL_STRING,
    SINGLE_REQUIRED_STRING,
    AccessTokenResponse,
    ErrorResponse,
    Message,
)
from oic.utils.time_util import time_sans_frac


class AuthorizationRequest(Message):
    c_param = {
        "response_type": SINGLE_REQUIRED_STRING,
        "client_id": SINGLE_REQUIRED_STRING,
        "scope": SINGLE_OPTIONAL_STRING,
    }


class AuthorizationResponse(Message):
    c_param = {
        "device_code": SINGLE_REQUIRED_STRING,
        "user_code": SINGLE_REQUIRED_STRING,
        "verification_uri": SINGLE_REQUIRED_STRING,
        "expires_in": SINGLE_OPTIONAL_INT,
        "interval": SINGLE_OPTIONAL_INT,
    }


class TokenRequest(Message):
    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "device_code": SINGLE_REQUIRED_STRING,
        "client_id": SINGLE_REQUIRED_STRING,
    }


class DeviceState:
    """Complete state of one device authorization session.

    Everything known about a device code lives here: which client it was
    issued to, the user code it maps to, when it expires, the polling
    interval, when it was last polled and whether the user has confirmed
    or denied the authorization.
    """

    def __init__(self, device_code, user_code, client_id, expires_at, interval):
        self.device_code = device_code
        self.user_code = user_code
        self.client_id = client_id
        self.expires_at = expires_at
        self.interval = interval
        self.last_poll_at = 0  # 0 means "never polled"
        self.authorized = False
        self.denied = False

    def is_expired(self, now=None):
        if now is None:
            now = time_sans_frac()
        return now >= self.expires_at


class DeviceFlowServer(SingleService):
    def __init__(self, host, verification_uri=""):
        SingleService.__init__(self, host)
        self.host = host
        # device_code -> DeviceState, the single source of truth
        self.device_states: dict[str, DeviceState] = {}
        # user_code -> device_code, used when the user confirms/denies
        self.user_code2device: dict[str, str] = {}
        self.device_code_life_time = 900  # 15 minutes
        self.interval = 5  # minimum seconds between polls
        self.verification_uri = verification_uri

    def device_endpoint(self, request, authn=None):
        _req = AuthorizationRequest(**request)
        device_code = rndstr(10)
        user_code = rndstr(6)

        state = DeviceState(
            device_code=device_code,
            user_code=user_code,
            client_id=_req["client_id"],
            expires_at=time_sans_frac() + self.device_code_life_time,
            interval=self.interval,
        )
        self.device_states[device_code] = state
        self.user_code2device[user_code] = device_code

        return AuthorizationResponse(
            device_code=device_code,
            user_code=user_code,
            verification_uri=self.verification_uri,
            expires_in=self.device_code_life_time,
            interval=self.interval,
        )

    def token_endpoint(self, request, authn=None):
        _req = TokenRequest(**request)
        _dc = _req["device_code"]

        state = self.device_states.get(_dc)
        if state is None:
            return ErrorResponse(error="invalid_grant", error_description="Unknown device_code")

        if state.is_expired():
            return ErrorResponse(error="expired_token")

        # The device code is bound to the client it was issued to.
        if state.client_id != _req["client_id"]:
            return ErrorResponse(error="invalid_grant", error_description="device_code was issued to another client")

        now = time_sans_frac()
        if state.last_poll_at and now - state.last_poll_at < state.interval:
            # RFC 8628 section 3.5: polling too fast, increase the interval.
            state.interval += 5
            return ErrorResponse(error="slow_down")
        state.last_poll_at = now

        if state.denied:
            return ErrorResponse(error="access_denied")

        if not state.authorized:
            return ErrorResponse(error="authorization_pending")

        # User has confirmed; issue a token and consume the device code.
        del self.device_states[_dc]
        self.user_code2device.pop(state.user_code, None)
        return AccessTokenResponse(access_token=rndstr(32), token_type="Bearer", expires_in=3600)

    def device_auth(self, user_code, accept=True):
        device_code = self.user_code2device[user_code]
        state = self.device_states[device_code]
        if accept:
            state.authorized = True
        else:
            state.denied = True


class DeviceFlowClient(SingleClient):
    def __init__(self, host):
        SingleClient.__init__(self, host)
        self.requests = {
            "authorization": self.authorization_request,
            "token": self.token_request,
        }

    def authorization_request(self, scope=""):
        req = AuthorizationRequest(client_id=self.host.client_id, response_type="device_code")
        if scope:
            req["scope"] = scope

        http_response = self.host.http_request(
            self.host.provider_info["device_authorization_endpoint"],
            "POST",
            req.to_urlencoded(),
        )

        response = self.host.parse_request_response(AuthorizationResponse, http_response, "json")

        return response

    def token_request(self, device_code=""):
        req = TokenRequest(
            grant_type="urn:ietf:params:oauth:grant-type:device_code",
            device_code=device_code,
            client_id=self.host.client_id,
        )

        http_response = self.host.http_request(self.host.provider_info["token_endpoint"], "POST", req.to_urlencoded())

        response = self.host.parse_request_response(AccessTokenResponse, http_response, "json")

        return response
