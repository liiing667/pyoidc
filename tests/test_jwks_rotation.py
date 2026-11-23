import pytest
import responses
from jwkest import BadSignature
from jwkest.jws import JWS

from oic.oauth2.message import Message
from oic.utils.keyio import KeyJar, UpdateFailed, build_keyjar

ISSUER = "https://issuer.example"
JWKS_URI = "https://issuer.example/jwks"


def _signing_key_with_kid(kid):
    _, keyjar, _ = build_keyjar([{"type": "RSA", "use": ["sig"]}])
    key = keyjar.get_signing_key("RSA")[0]
    key.kid = kid
    return key


def _token(key, value):
    return Message(iss=ISSUER, a=value).to_jwt([key], "RS256")


def test_rotated_key_reusing_kid_verifies_old_and_new_tokens():
    old_key = _signing_key_with_kid("shared")
    new_key = _signing_key_with_kid("shared")
    old_token = _token(old_key, "old")
    new_token = _token(new_key, "new")

    keyjar = KeyJar()
    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, JWKS_URI, json={"keys": [old_key.serialize()]})
        rsps.add(responses.GET, JWKS_URI, json={"keys": [new_key.serialize()]})

        keyjar.add(ISSUER, JWKS_URI)

        assert Message().from_jwt(old_token, keyjar=keyjar)["a"] == "old"
        # The kid is already known, so verification has to notice that the
        # new token was signed with a different key and refresh the JWKS.
        assert Message().from_jwt(new_token, keyjar=keyjar)["a"] == "new"

        # Both keys survive the overlap, which keeps tokens from before the
        # rotation verifiable.
        assert Message().from_jwt(old_token, keyjar=keyjar)["a"] == "old"

    # Identify the signer for each token, independent of pyoidc's selection.
    assert JWS().verify_compact(old_token, [old_key])
    assert JWS().verify_compact(new_token, [new_key])
    with pytest.raises(BadSignature):
        JWS().verify_compact(old_token, [new_key])
    with pytest.raises(BadSignature):
        JWS().verify_compact(new_token, [old_key])


def test_failed_refresh_keeps_the_previous_generation():
    old_key = _signing_key_with_kid("shared")
    old_token = _token(old_key, "old")

    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, JWKS_URI, json={"keys": [old_key.serialize()]})
        keyjar = KeyJar()
        bundle = keyjar.add(ISSUER, JWKS_URI)

        assert Message().from_jwt(old_token, keyjar=keyjar)["a"] == "old"
        generation = bundle.generation
        old_keys = bundle.get_keys_with_kid("shared")

        # Make the cache stale and fail the refresh.  The complete previous
        # key set must still be visible instead of an empty/half updated one.
        bundle.time_out = 0
        rsps.add(responses.GET, JWKS_URI, status=500)

        assert bundle.available_keys() == old_keys
        assert bundle.generation == generation

        # A later retry can still commit a new generation.
        new_key = _signing_key_with_kid("shared")
        rsps.add(responses.GET, JWKS_URI, json={"keys": [new_key.serialize()]})
        bundle.time_out = 0

        keys = bundle.keys()
        assert bundle.generation > generation
        assert len(keys) == 2
        assert {k.kid for k in keys} == {"shared"}


def test_malformed_refresh_does_not_commit_partially():
    old_key = _signing_key_with_kid("shared")
    new_key = _signing_key_with_kid("shared")

    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, JWKS_URI, json={"keys": [old_key.serialize()]})
        keyjar = KeyJar()
        bundle = keyjar.add(ISSUER, JWKS_URI)

        assert bundle.keys()
        generation = bundle.generation
        old_keys = bundle.keys()
        old_jwks = bundle.imp_jwks

        # The first key is fine, the second one is not.  Neither the keys nor
        # any cache metadata may be committed in that case.
        rsps.add(responses.GET, JWKS_URI, json={"keys": [new_key.serialize(), None]})
        bundle.time_out = 0
        with pytest.raises(UpdateFailed):
            bundle.update()

        assert bundle.available_keys() == old_keys
        assert bundle.generation == generation
        assert bundle.imp_jwks == old_jwks
