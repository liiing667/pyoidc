import threading

import pytest
from freezegun import freeze_time

from oic.oic.message import AuthorizationRequest
from oic.utils.sdb import AuthnEvent, DictRefreshDB, ExpiredToken, SessionDB, create_session_db
from oic.utils.session_backend import DictSessionBackend

CLIENT_ID = "client1"

AUTHZ_REQ = AuthorizationRequest(
    response_type="code",
    client_id=CLIENT_ID,
    redirect_uri="http://example.com/authz",
    scope=["openid", "offline_access"],
    state="state",
)


def _issue_refresh_token(sdb):
    """Create a session and return its first refresh-token response."""
    authn_event = AuthnEvent("uid", "salt")
    sid = sdb.create_authz_session(authn_event, AUTHZ_REQ)
    sdb.do_sub(sid, authn_event.salt)
    info = sdb.upgrade_to_token(sdb[sid]["code"], issue_refresh=True)
    return sid, info


def test_rotation_issues_new_value_and_revokes_old(session_db_factory):
    sdb = session_db_factory("https://example.com/")
    sid, info = _issue_refresh_token(sdb)
    old_refresh = info["refresh_token"]
    old_access = info["access_token"]
    lineage = sdb.get_refresh_token_lineage(old_refresh)
    assert lineage

    new_info = sdb.refresh_token(old_refresh, CLIENT_ID)

    assert new_info["refresh_token"] != old_refresh
    assert new_info["access_token"] != old_access
    assert sdb.get_refresh_token_lineage(new_info["refresh_token"]) == lineage
    assert not sdb.is_valid(old_refresh, CLIENT_ID)
    assert not sdb.is_valid(old_access, CLIENT_ID)
    assert sdb.is_valid(new_info["refresh_token"], CLIENT_ID)
    assert sdb.is_valid(new_info["access_token"], CLIENT_ID)


def test_refresh_token_is_bound_to_client(session_db_factory):
    sdb = session_db_factory("https://example.com/")
    _, info = _issue_refresh_token(sdb)
    refresh = info["refresh_token"]

    with pytest.raises(ExpiredToken):
        sdb.refresh_token(refresh, "other-client")

    # A wrong client must not consume or rotate the token.
    assert sdb.is_valid(refresh, CLIENT_ID)
    assert sdb.is_valid(info["access_token"], CLIENT_ID)


def test_reuse_revokes_the_whole_lineage(session_db_factory):
    sdb = session_db_factory("https://example.com/")
    sid, info = _issue_refresh_token(sdb)
    old_refresh = info["refresh_token"]
    new_info = sdb.refresh_token(old_refresh, CLIENT_ID)
    assert sdb[sid]["refresh_token"] == new_info["refresh_token"]

    with pytest.raises(ExpiredToken):
        sdb.refresh_token(old_refresh, CLIENT_ID)

    assert sdb[sid]["revoked"] is True
    assert not sdb.is_valid(old_refresh, CLIENT_ID)
    assert not sdb.is_valid(new_info["refresh_token"], CLIENT_ID)
    assert not sdb.is_valid(new_info["access_token"], CLIENT_ID)


def test_concurrent_refresh_keeps_a_single_generation(session_db_factory):
    sdb = session_db_factory("https://example.com/")
    sid, info = _issue_refresh_token(sdb)
    old_refresh = info["refresh_token"]
    results = []

    def refresh():
        try:
            results.append(sdb.refresh_token(old_refresh, CLIENT_ID))
        except ExpiredToken:
            results.append(None)

    threads = [threading.Thread(target=refresh) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    successful = [result for result in results if result is not None]
    assert len(successful) == 1
    assert sdb[sid]["refresh_token"] == successful[0]["refresh_token"]
    assert not sdb.is_valid(old_refresh, CLIENT_ID)
    # The losing request detects reuse and revokes the complete lineage.
    assert sdb[sid]["revoked"] is True
    assert not sdb.is_valid(successful[0]["refresh_token"], CLIENT_ID)


def test_expired_refresh_token_is_rejected(session_db_factory):
    sdb = session_db_factory("https://example.com/")
    with freeze_time("2000-01-01"):
        _, info = _issue_refresh_token(sdb)

    with pytest.raises(ExpiredToken):
        sdb.refresh_token(info["refresh_token"], CLIENT_ID)


def test_legacy_refresh_db_still_accepts_its_tokens():
    refresh_db = DictRefreshDB()
    token = refresh_db.create_token(CLIENT_ID, "uid", "openid", "sub", "authzreq", "sid")
    sdb = SessionDB("https://example.com/", {}, refresh_db=refresh_db)

    assert sdb.is_valid(token, CLIENT_ID)


def test_recreated_session_db_can_rotate_the_current_token():
    backend = DictSessionBackend()
    sdb1 = create_session_db("https://example.com/", "secret", "password", db=backend)
    sdb2 = create_session_db("https://example.com/", "secret", "password", db=backend)
    _, info = _issue_refresh_token(sdb1)
    old_refresh = info["refresh_token"]
    lineage = sdb1.get_refresh_token_lineage(old_refresh)

    # The second SessionDB has its own token storage but shares the session
    # backend.  The token itself carries client and lineage binding.
    assert sdb2.is_valid(old_refresh, CLIENT_ID)
    new_info = sdb2.refresh_token(old_refresh, CLIENT_ID)

    assert sdb2.get_refresh_token_lineage(new_info["refresh_token"]) == lineage
    assert not sdb2.is_valid(old_refresh, CLIENT_ID)
    assert sdb2.is_valid(new_info["refresh_token"], CLIENT_ID)
