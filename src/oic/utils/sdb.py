import base64
import copy
import hashlib
import json
import logging
import threading
import uuid
import warnings
from binascii import Error
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from oic import rndstr
from oic.exception import ImproperlyConfigured
from oic.oauth2.message import AuthorizationRequest
from oic.utils import tobytes
from oic.utils.session_backend import AuthnEvent, DictSessionBackend, SessionBackend
from oic.utils.time_util import utc_time_sans_frac

__author__ = "rohe0002"

logger = logging.getLogger(__name__)

# A single lock shared by all SessionDB instances: refresh-token rotation and
# revocation always have to be serialized, also when several SessionDB objects
# are backed by the same (shared) session backend.
_REFRESH_LOCK = threading.RLock()


def lv_pack(*args):
    s = []
    for a in args:
        s.append("{}:{}".format(len(a), a))
    return "".join(s)


def lv_unpack(txt):
    txt = txt.strip()
    res = []
    while txt:
        length, v = txt.split(":", 1)
        res.append(v[: int(length)])
        txt = v[int(length) :]
    return res


class ExpiredToken(Exception):
    pass


class RefreshTokenReuse(ExpiredToken):
    """Raised when an already rotated refresh token is presented again."""


class WrongTokenType(Exception):
    pass


class AccessCodeUsed(Exception):
    pass


class UnknownToken(Exception):
    pass


def pairwise_id(sub, sector_identifier, seed):
    return hashlib.sha256(("{}{}{}".format(sub, sector_identifier, seed)).encode("utf-8")).hexdigest()


class Crypt:
    def __init__(self, password, mode=None):
        self.key = base64.urlsafe_b64encode(hashlib.sha256(password.encode("utf-8")).digest())
        self.core = Fernet(self.key)

    def encrypt(self, text):
        # Padding to blocksize of AES
        text = tobytes(text)
        if len(text) % 16:
            text += b" " * (16 - len(text) % 16)
        return self.core.encrypt(tobytes(text))

    def decrypt(self, ciphertext):
        return self.core.decrypt(ciphertext)


class Token:
    def __init__(self, typ, lifetime=0, token_storage=None, **kwargs):
        self.type = typ
        self.lifetime = lifetime
        self.args = kwargs
        if typ == "R":
            if token_storage is None:
                raise ImproperlyConfigured("token_storage kwarg must be passed in for refresh token.")
        self.token_storage = token_storage
        # Per-token state.  This is deliberately kept next to the token factory
        # and not in the session dictionary: the session represents the whole
        # lineage, while consumption/revocation must be tracked per token
        # generation.  ``token_storage`` alone is keyed by ``sid`` and can
        # therefore not distinguish an old token from its replacement.
        self._token_meta: dict[str, dict[str, Any]] = {}

    def __call__(self, sid, *args, **kwargs):
        """Return a token.

        :param sid: Session id
        :return:
        """
        raise NotImplementedError

    def key(self, **kwargs):
        """Return a key - the session id."""
        return rndstr(32)

    def type_and_key(self, token):
        """Return type of Token (A=Access code, T=Token, R=Refresh token) and the session id.

        :param token: A token
        :return: tuple of token type and session id
        """
        raise NotImplementedError

    def get_key(self, token):
        """Return session id.

        :param token: A token
        :return: The session id
        """
        raise NotImplementedError

    def get_type(self, token):
        """Return token type.

        :param token: A token
        :return: Type of Token (A=Access code, T=Token, R=Refresh token)
        """
        raise NotImplementedError

    def expires_at(self, token):
        """Return the expiry timestamp of the token.

        :param token: A token
        :return: Timestamp of the token expiry in UTC
        """
        raise NotImplementedError

    def is_expired(self, token, when=None):
        """Return if token is still valid."""
        if when is None:
            now = utc_time_sans_frac()
        else:
            now = when
        eat = self.expires_at(token)
        return bool(now > eat)

    def register_token(self, token, sid=None, client_id=None, lineage=None):
        """Register the state belonging to a concrete token value.

        :param token: The token value
        :param sid: The session the token belongs to
        :param client_id: The client the token was issued to
        :param lineage: Identifier shared by a refresh-token family
        :return: The metadata dictionary for the token
        """
        meta = self._token_meta.setdefault(token, {})
        if sid is not None:
            meta["sid"] = sid
        if client_id is not None:
            meta["client_id"] = client_id
        if lineage is not None:
            meta["lineage"] = lineage
        meta.setdefault("consumed", False)
        meta.setdefault("revoked", False)
        return meta

    def get_token_meta(self, token):
        """Return per-token state, or ``None`` for unknown/legacy tokens."""
        return self._token_meta.get(token)

    def get_lineage(self, token):
        """Return the refresh-token lineage identifier for ``token``."""
        meta = self._token_meta.get(token)
        if meta is not None:
            return meta.get("lineage")
        return None

    def consume_token(self, token, replaced_by=None):
        """Mark a token value as consumed by a successful rotation."""
        meta = self._token_meta.get(token)
        if meta is None:
            return None
        meta["consumed"] = True
        if replaced_by is not None:
            meta["replaced_by"] = replaced_by
        return meta

    def revoke_token_state(self, token):
        """Mark a single token value as revoked without touching its lineage."""
        meta = self._token_meta.get(token)
        if meta is not None:
            meta["revoked"] = True
        return meta

    def revoke_lineage(self, lineage):
        """Revoke every known token value belonging to ``lineage``."""
        if lineage is None:
            return []
        revoked = []
        for token, meta in list(self._token_meta.items()):
            if meta.get("lineage") == lineage:
                meta["revoked"] = True
                revoked.append(token)
        return revoked

    def invalidate(self, token):
        """Mark the refresh token as invalidated."""
        meta = self._token_meta.get(token)
        if meta is not None:
            meta["revoked"] = True
            return
        if self.get_type(token) != "R":
            return
        sid = self.get_key(token)
        try:
            self.token_storage[sid]["revoked"] = True
        except (KeyError, TypeError):
            pass

    def valid(self, token):
        try:
            typ, key = self.type_and_key(token)
        except (Error, InvalidToken):
            raise WrongTokenType from None
        if typ != self.type:
            raise WrongTokenType
        if typ == "R":
            meta = self._token_meta.get(token)
            if meta is not None:
                return not meta.get("revoked", False) and not meta.get("consumed", False)
            try:
                return not self.token_storage[key].get("revoked", False)
            except (KeyError, TypeError):
                return False
        else:
            return True


class DefaultToken(Token):
    def __init__(self, secret, password, typ="", **kwargs):
        Token.__init__(self, typ, **kwargs)
        self.crypt = Crypt(password)

    def __call__(self, sid="", ttype="", **kwargs):
        """Return a token.

        :param ttype: Type of token
        :param prev: Previous token, if there is one to go from
        :param sid: Session id
        :return:
        """
        if not ttype and self.type:
            ttype = self.type
        else:
            ttype = "A"

        tmp = ""
        rnd = ""
        while rnd == tmp:  # Don't use the same random value again
            rnd = rndstr(32)  # Ultimate length multiple of 16

        issued_at = "{}".format(utc_time_sans_frac())
        sinfo = kwargs.get("sinfo") or {}
        lineage = kwargs.pop("lineage", None)
        if lineage is None and isinstance(sinfo, dict):
            lineage = sinfo.get("lineage")
        client_id = kwargs.pop("client_id", None)
        if client_id is None and isinstance(sinfo, dict):
            client_id = sinfo.get("client_id")

        if ttype == "R":
            # kwargs["sinfo"] is a dictionary and we do not want updates...
            self.token_storage[sid] = copy.deepcopy(kwargs["sinfo"])

        # Client and lineage are bound into the token itself.  This keeps the
        # binding available even when the in-memory per-token metadata is lost
        # (for example after a restart of the process).
        payload = lv_pack(rnd, ttype, sid, issued_at, str(client_id or ""), str(lineage or ""))
        return base64.b64encode(self.crypt.encrypt(payload.encode())).decode("utf-8")

    def key(self, user="", areq=None, **kwargs):
        """Return a key - the session id - that are based on some session connected data.

        :param user: User id
        :param areq: The authorization request
        :return: A hash
        """
        csum = hashlib.new("sha224")
        csum.update(rndstr(32).encode("utf-8"))
        return csum.hexdigest()  # 56 bytes long, 224 bits

    def _split_token_parts(self, token):
        """Decode a token into the full list of fields."""
        plain = self.crypt.decrypt(base64.b64decode(token)).decode()
        # order: rnd, type, sid, iat, client_id, lineage
        parts = lv_unpack(plain)
        # Tokens issued before client/lineage binding only contain four fields.
        while len(parts) < 6:
            parts.append("")
        return parts

    def _split_token(self, token):
        """Decode the token.

        :param token: A token
        :return: Tuple of sid, type, iat, salt
        """
        p = self._split_token_parts(token)
        return p[1], p[2], int(p[3]), p[0]

    def get_info(self, token):
        """Return decoded information about ``token``."""
        p = self._split_token_parts(token)
        return {
            "type": p[1],
            "sid": p[2],
            "iat": int(p[3]),
            "rnd": p[0],
            "client_id": p[4] or None,
            "lineage": p[5] or None,
        }

    def get_lineage(self, token):
        """Return the refresh-token lineage bound into the token."""
        meta = self._token_meta.get(token)
        if meta is not None and meta.get("lineage"):
            return meta["lineage"]
        try:
            return self.get_info(token).get("lineage")
        except Exception:  # nosec
            return None

    def type_and_key(self, token):
        """Return type of Token (A=Access code, T=Token, R=Refresh token) and the session id.

        :param token: A token
        :return: tuple of token type and session id
        """
        a, b, _, _ = self._split_token(token)
        return a, b

    def get_key(self, token):
        """Return session id.

        :param token: A token
        :return: The session id
        """
        return self._split_token(token)[1]

    def get_type(self, token):
        """Return token type.

        :param token: A token
        :return: Type of Token (A=Access code, T=Token, R=Refresh token)
        """
        return self._split_token(token)[0]

    def expires_at(self, token):
        """Return expiry time.

        :param token: A token
        :return: expiry timestamp
        """
        return self._split_token(token)[2] + self.lifetime


class RefreshDB:
    """Database for refresh token storage."""

    def __init__(self):
        warnings.warn(
            "Using `RefreshDB` is deprecated, please use `Token` and `refresh_token_factory` instead.",
            DeprecationWarning,
            stacklevel=2,
        )

    def get(self, refresh_token):
        """Retrieve info about the authentication proces from the refresh token.

        :return: Dictionary with info
        :raises: KeyError
        """
        raise NotImplementedError

    def store(self, token, info):
        """Store the information about the authentication process.

        :param token: Token
        :param info: Information associated with token to be stored
        """
        raise NotImplementedError

    def remove(self, token):
        """Remove the token and related information from the internal storage.

        :param token: Token to be removed
        """
        raise NotImplementedError

    def create_token(self, client_id, uid, scopes, sub, authzreq, sid):
        """Create refresh token for given combination of client_id and sub and store it in internal storage.

        :param client_id: Client_id of the consumer
        :param uid: User identification
        :param scopes: Scopes associated with the token
        :param sub: Sub identifier
        :param authzreq: Authorization request
        :param sid: Session ID
        :return: Refresh token
        """
        refresh_token = "Refresh_{}".format(rndstr(5 * 16))
        self.store(
            refresh_token,
            {
                "client_id": client_id,
                "uid": uid,
                "scope": scopes,
                "sub": sub,
                "authzreq": authzreq,
                "sid": sid,
            },
        )
        return refresh_token

    def verify_token(self, client_id, refresh_token):
        """Verify if the refresh token belongs to client_id."""
        if not refresh_token.startswith("Refresh_"):
            raise WrongTokenType
        try:
            stored_cid = self.get(refresh_token).get("client_id")
        except KeyError:
            return False
        return client_id == stored_cid

    def revoke_token(self, token):
        """Remove token from database."""
        self.remove(token)


class DictRefreshDB(RefreshDB):
    """Dictionary based implementation of RefreshDB."""

    def __init__(self):
        super().__init__()
        warnings.warn(
            "Using `DictRefreshDB` is deprecated, please use `Token` and `refresh_token_factory` instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        self._db: dict[str, dict[str, str]] = {}

    def get(self, refresh_token):
        """Retrieve info for given token from dictionary."""
        return self._db[refresh_token].copy()

    def store(self, token, info):
        """Add token and info to the dictionary."""
        self._db[token] = info

    def remove(self, token):
        """Remove the token from the dictionary."""
        self._db.pop(token)


def create_session_db(
    base_url,
    secret,
    password,
    db=None,
    token_expires_in=3600,
    grant_expires_in=600,
    refresh_token_expires_in=86400,
):
    """Construct SessionDB instance.

    Using this you can create a very basic non persistent
    session database that issues opaque DefaultTokens.

    :param base_url: Same as base_url parameter of `SessionDB`.
    :param secret: Secret to pass to `DefaultToken` class.
    :param password: Secret key to pass to `DefaultToken` class.
    :param db: Storage for the session data, usually a dict.
    :param token_expires_in: Expiry time for access tokens in seconds.
    :param grant_expires_in: Expiry time for access codes in seconds.
    :param refresh_token_expires_in: Expiry time for refresh tokens.

    :return: A constructed `SessionDB` object.
    """
    code_factory = DefaultToken(secret, password, typ="A", lifetime=grant_expires_in)
    token_factory = DefaultToken(secret, password, typ="T", lifetime=token_expires_in)
    db = DictSessionBackend() if db is None else db
    refresh_token_factory = DefaultToken(secret, password, typ="R", lifetime=refresh_token_expires_in, token_storage={})

    return SessionDB(
        base_url,
        db,
        refresh_db=None,
        code_factory=code_factory,
        token_factory=token_factory,
        refresh_token_factory=refresh_token_factory,
    )


class SessionDB:
    def __init__(
        self,
        base_url,
        db,
        refresh_db=None,
        refresh_token_expires_in=None,
        token_factory=None,
        code_factory=None,
        refresh_token_factory=None,
        sm_salt="",
    ):
        """Object to store the session related information.

        :param db: Database for storing the session information.
        """
        if refresh_token_expires_in is not None:
            warnings.warn(
                "Setting a `refresh_token_expires_in` has no effect, please set the expiration on "
                "`refresh_token_factory`.",
                DeprecationWarning,
                stacklevel=2,
            )
        self.base_url = base_url
        if not isinstance(db, SessionBackend):
            warnings.warn(
                "Please use `SessionBackend` to ensure proper API for the database.",
                DeprecationWarning,
                stacklevel=2,
            )
        self._db = db
        # Rotation, reuse detection and revocation of a refresh-token lineage
        # have to be serialized.  The lock is shared by all SessionDB objects
        # because they may use the same session backend.
        self._refresh_lock = _REFRESH_LOCK

        self.sm_salt = sm_salt or rndstr(32)

        self.token_factory = {"code": code_factory, "access_token": token_factory}

        self.token_factory_order = ["code", "access_token"]

        # TODO: This should simply be a factory like all the others too,
        #       even for the default case.

        if refresh_token_factory:
            if refresh_db:
                raise ImproperlyConfigured("Only use one of refresh_db or refresh_token_factory")
            self._refresh_db = None
            self.token_factory["refresh_token"] = refresh_token_factory
            self.token_factory_order.append("refresh_token")
        elif refresh_db:
            warnings.warn(
                "Using `refresh_db` is deprecated, please use `refresh_token_factory`",
                DeprecationWarning,
                stacklevel=2,
            )
            self._refresh_db = refresh_db
        else:
            # Not configured
            self._refresh_db = None
            self.token_factory["refresh_token"] = None

        self.access_token = self.token_factory["access_token"]
        self.token = self.access_token

    def _get_token_key(self, item, order=None):
        if order is None:
            order = self.token_factory_order

        for key in order:
            try:
                return self.token_factory[key].get_key(item)
            except Exception:  # nosec
                # FIXME: Catch specific exception
                pass

        logger.info("Unknown token format")
        raise KeyError(item)

    def _get_token_type_and_key(self, item, order=None):
        if order is None:
            order = self.token_factory_order

        for key in order:
            try:
                return self.token_factory[key].type_and_key(item)
            except Exception:  # nosec
                # FIXME: Catch specific exception.
                pass

        logger.info("Unknown token format")
        raise KeyError(item)

    def _get_token_type(self, item, order=None):
        if order is None:
            order = self.token_factory_order

        for key in order:
            try:
                return self.token_factory[key].get_type(item)
            except Exception:  # nosec
                # FIXME: Catch specific exception
                pass

        logger.info("Unknown token format or invalid token")
        raise KeyError(item)

    def __getitem__(self, item):
        """Return Session item.

        :param item: authz grant code or refresh token
        """
        try:
            return self._db[item]
        except KeyError:
            sid = self._get_token_key(item)
            return self._db[sid]

    def __setitem__(self, key, value):
        """Assign Session item.

        :param key: authz grant code or refresh token
        """
        self._db[key] = value

    def __delitem__(self, sid):
        """Actually delete the pointed session from this SessionDB instance.

        :param sid: session identifier
        """
        del self._db[sid]

    def update(self, key, attribute, value):
        if key in self._db:
            pass
        else:
            sid = self._get_token_key(key)

            if sid not in self._db:
                raise KeyError
            else:
                key = sid

        item = self._db[key]
        item[attribute] = value
        self._db[key] = item

    def update_by_token(self, token, attribute, value):
        (typ, key) = self._get_token_type_and_key(token)
        return self.update(key, attribute, value)

    def do_sub(self, sid, client_salt, sector_id="", subject_type="public"):
        """Construct a sub (subject identifier).

        :param sid: Session identifier
        :param sector_id: Possible sector identifier
        :param subject_type: 'public'/'pairwise'
        :param client_salt: client specific salt - used in pairwise
        :return:
        """
        authn_event = self.get_authentication_event(sid)
        uid = authn_event.uid
        user_salt = authn_event.salt

        if subject_type == "public":
            sub = hashlib.sha256("{}{}".format(uid, user_salt).encode("utf-8")).hexdigest()
        else:
            sub = pairwise_id(uid, sector_id, "{}{}".format(client_salt, user_salt))

        self.update(sid, "sub", sub)

        return sub

    def create_authz_session(self, aevent, areq, id_token=None, oidreq=None, **kwargs):
        """Create session holding info about the Authorization event.

        :param aevent: An AuthnEvent instance
        :param areq: The AuthorizationRequest instance
        :param id_token: An IDToken instance
        :param oidreq: An OpenIDRequest instance
        :return: The session identifier, which is the database key
        """
        sid = self.token_factory["code"].key(user=aevent.uid, areq=areq)
        access_grant = self.token_factory["code"](sid=sid)

        _dic = {
            "oauth_state": "authz",
            "code": access_grant,
            "code_used": False,
            "authzreq": areq.to_json(),
            "client_id": areq["client_id"],
            "response_type": areq["response_type"],
            "revoked": False,
            "authn_event": aevent.to_json(),
        }

        _dic.update(kwargs)

        try:
            _val = areq["nonce"]
            if _val:
                _dic["nonce"] = _val
        except (AttributeError, KeyError):
            pass

        for key in ["redirect_uri", "state", "scope", "si_redirects"]:
            try:
                _dic[key] = areq[key]
            except KeyError:
                pass

        if id_token:
            _dic["id_token"] = id_token
        if oidreq:
            _dic["oidreq"] = oidreq.to_json()

        self._db[sid] = _dic

        return sid

    def get_authentication_event(self, sid):
        """Return AuthnEvent based on sid."""
        # This is a compatibility shim for older sessions
        if isinstance(self._db[sid]["authn_event"], dict):
            return AuthnEvent(**self._db[sid]["authn_event"])
        else:
            return AuthnEvent.from_json(self._db[sid]["authn_event"])

    def get_token(self, sid):
        if self._db[sid]["oauth_state"] == "authz":
            return self._db[sid]["code"]
        elif self._db[sid]["oauth_state"] == "token":
            return self._db[sid]["access_token"]

    def upgrade_to_token(  # nosec
        self,
        token=None,
        issue_refresh=False,
        id_token="",
        oidreq=None,
        key=None,
        access_grant="",
    ):
        """Promote session to token.

        :param token: The access grant
        :param issue_refresh: If a refresh token should be issued
        :param id_token: An IDToken instance
        :param oidreq: An OpenIDRequest instance
        :param key: The session key. One of token or key must be given.
        :return: The session information as a dictionary
        """
        if token:
            try:
                (_, key) = self.token_factory["code"].type_and_key(token)
            except Exception:
                raise WrongTokenType("Not a grant token") from None

            dic = self._db[key]

            if dic["code_used"]:
                raise AccessCodeUsed
            _at = self.access_token(sid=key, sinfo=dic)
            dic["code_used"] = True
        else:
            dic = self._db[key]
            _at = self.access_token(sid=key, sinfo=dic)

        dic["access_token"] = _at
        dic["access_token_scope"] = "?"  # nosec
        dic["oauth_state"] = "token"
        dic["token_type"] = "Bearer"  # nosec

        if id_token:
            dic["id_token"] = id_token
        if oidreq:
            dic["oidreq"] = oidreq

        if issue_refresh:
            if "authn_event" in dic:
                authn_event = AuthnEvent.from_json(dic["authn_event"])
            else:
                authn_event = None
            if authn_event:
                uid = authn_event.uid
            else:
                uid = None

            if self._refresh_db:
                refresh_token = self._refresh_db.create_token(
                    dic["client_id"],
                    uid,
                    dic.get("scope"),
                    dic["sub"],
                    dic["authzreq"],
                    key,
                )
                dic["refresh_token"] = refresh_token
            elif self.token_factory["refresh_token"] is not None:
                factory = self.token_factory["refresh_token"]
                lineage = dic.get("refresh_token_lineage") or self._lineage_for_sid(key)
                refresh_token = factory(
                    key,
                    sinfo=dic,
                    lineage=lineage,
                    client_id=dic.get("client_id"),
                )
                factory.register_token(
                    refresh_token,
                    sid=key,
                    client_id=dic.get("client_id"),
                    lineage=lineage,
                )
                dic["refresh_token"] = refresh_token
        self._db[key] = dic
        return dic

    def refresh_token(self, rtoken, client_id):  # noqa: C901 # was 16
        """Rotate a refresh token and issue a new access token.

        The presented token is consumed and replaced by a new token in the same
        lineage.  Reusing an already consumed token revokes the complete
        lineage.

        :param rtoken: Refresh token
        :param client_id: Client ID
        :return: Dictionary with session info
        :raises: ExpiredToken for invalid, expired or reused refresh token
                 WrongTokenType for wrong token type
        """
        # assert that it is a refresh token and that it is valid
        if self._refresh_db:
            if self._refresh_db.verify_token(client_id, rtoken):
                # Valid refresh token
                _info = self._refresh_db.get(rtoken)
                try:
                    sid = _info["sid"]
                except KeyError:
                    areq = json.loads(_info["authzreq"])
                    sid = self.token_factory["code"].key(user=_info["uid"], areq=areq)
                    dic = _info
                    dic["response_type"] = areq["response_type"].split(" ")
                else:
                    try:
                        dic = self._db[sid]
                    except KeyError:
                        dic = _info

                access_token = self.access_token(sid=sid, sinfo=dic)
                try:
                    at = dic["access_token"]
                except KeyError:
                    pass
                else:
                    if at:
                        self._invalidate_access_token(at)
            else:
                raise ExpiredToken
            dic["access_token"] = access_token
            dic["token_type"] = "Bearer"  # nosec
            dic["refresh_token"] = rtoken
            dic["revoked"] = False
            self._db[sid] = dic
            return dic

        factory = self.token_factory["refresh_token"]
        if factory is None:
            raise WrongTokenType

        with self._refresh_lock:
            meta = factory.get_token_meta(rtoken)

            # An explicitly revoked token stays rejected.  This is deliberately
            # checked before reuse detection: revoking a token is not a signal
            # that its whole lineage has to be destroyed.
            if meta is not None and meta.get("revoked"):
                raise ExpiredToken

            try:
                typ, sid = factory.type_and_key(rtoken)
            except KeyError:
                # JWT factories keep a jti -> sid mapping.  A token that is
                # valid but not present in this factory (for example an access
                # token) is rejected like an expired refresh token, matching
                # the historical behaviour.
                if meta is not None and meta.get("consumed"):
                    self._revoke_refresh_lineage(factory, meta.get("lineage"), meta.get("sid"))
                raise RefreshTokenReuse from None
            except Exception:
                # A consumed token may already have been removed by the token
                # factory (JWT based factories do that in invalidate()).
                if meta is not None and meta.get("consumed"):
                    self._revoke_refresh_lineage(factory, meta.get("lineage"), meta.get("sid"))
                    raise RefreshTokenReuse from None
                raise WrongTokenType from None

            if typ != factory.type:
                raise WrongTokenType

            # Expired tokens keep their historical behaviour (a plain
            # ExpiredToken, no lineage revocation).
            if factory.is_expired(rtoken):
                raise ExpiredToken

            if meta is not None:
                bound_client = meta.get("client_id")
                if bound_client is not None and bound_client != client_id:
                    raise ExpiredToken

            dic = self._refresh_session_info(factory, sid)

            bound_client = dic.get("client_id")
            if bound_client is not None and bound_client != client_id:
                raise ExpiredToken

            # The session always records the most recently issued refresh
            # token.  Comparing the presented value against it also works when
            # the per-process token metadata is not available (for example
            # when several frontends share one session backend).
            current_rt = dic.get("refresh_token")
            if current_rt and current_rt != rtoken:
                lineage = meta.get("lineage") if meta is not None else None
                if lineage is None:
                    lineage = factory.get_lineage(rtoken)
                self._revoke_refresh_lineage(factory, lineage, sid)
                raise RefreshTokenReuse

            # Reuse of a token that was already rotated means that one of the
            # two parties (the legitimate client or an attacker) is using an
            # old generation.  Revoke the complete lineage, including the
            # currently valid generation and its access token.
            if meta is not None and meta.get("consumed"):
                self._revoke_refresh_lineage(factory, meta.get("lineage"), sid)
                raise RefreshTokenReuse

            lineage = None
            if meta is not None:
                lineage = meta.get("lineage")
            if lineage is None:
                lineage = factory.get_lineage(rtoken)
            if lineage is None:
                lineage = dic.get("refresh_token_lineage") or self._lineage_for_sid(sid)

            if meta is None:
                meta = factory.register_token(
                    rtoken,
                    sid=sid,
                    client_id=bound_client,
                    lineage=lineage,
                )
            else:
                meta["lineage"] = lineage
                meta.setdefault("sid", sid)
                meta.setdefault("client_id", bound_client)

            old_at = dic.get("access_token")
            new_at = self.access_token(sid=sid, sinfo=dic)

            # Work on a copy of the session so that nothing is visible in the
            # backend until the rotation is ready to be committed as a whole.
            new_dic = dict(dic)
            new_dic["access_token"] = new_at
            new_dic["token_type"] = "Bearer"  # nosec
            new_dic["revoked"] = False

            storage = getattr(factory, "token_storage", None)
            old_storage_entry = None
            if isinstance(storage, dict) and sid in storage:
                old_storage_entry = copy.deepcopy(storage[sid])

            try:
                new_rt = factory(
                    sid,
                    sinfo=new_dic,
                    lineage=lineage,
                    client_id=bound_client,
                )
            except Exception:
                if isinstance(storage, dict):
                    if old_storage_entry is None:
                        storage.pop(sid, None)
                    else:
                        storage[sid] = old_storage_entry
                if new_at != old_at:
                    self._invalidate_access_token(new_at)
                raise

            new_dic["refresh_token"] = new_rt
            factory.register_token(
                new_rt,
                sid=sid,
                client_id=bound_client,
                lineage=lineage,
            )

            # Consuming the old generation and issuing the new one is a single
            # logical commit.  If the session backend rejects the write, roll
            # the token state back so that the old generation remains usable.
            old_meta = dict(meta)
            factory.consume_token(rtoken, replaced_by=new_rt)
            try:
                self._db[sid] = new_dic
            except Exception:
                meta.clear()
                meta.update(old_meta)
                factory.revoke_token_state(new_rt)
                try:
                    factory.invalidate(new_rt)
                except Exception:  # nosec
                    pass
                if isinstance(storage, dict):
                    if old_storage_entry is None:
                        storage.pop(sid, None)
                    else:
                        storage[sid] = old_storage_entry
                if new_at != old_at:
                    self._invalidate_access_token(new_at)
                raise

            self._sync_refresh_factory_storage(factory, sid, new_dic)
            if old_at and old_at != new_at:
                self._invalidate_access_token(old_at)
            return new_dic

    @staticmethod
    def _lineage_for_sid(sid):
        """Return the deterministic refresh-token lineage for a session."""
        return hashlib.sha256("refresh-token-lineage:{}".format(sid).encode("utf-8")).hexdigest()

    def _invalidate_access_token(self, token):
        """Invalidate an access token if the configured factory supports it."""
        if not token:
            return
        invalidate = getattr(self.access_token, "invalidate", None)
        if invalidate is not None:
            invalidate(token)

    def _refresh_session_info(self, factory, sid):
        """Return a copy of the session information for refresh handling."""
        try:
            return dict(self._db[sid])
        except KeyError:
            # Session is cleared, use the storage in the token factory.
            storage = getattr(factory, "token_storage", None) or {}
            try:
                return dict(storage[sid])
            except KeyError:
                raise ExpiredToken from None

    def _sync_refresh_factory_storage(self, factory, sid, dic):
        """Keep the opaque token factory's session copy in sync."""
        storage = getattr(factory, "token_storage", None)
        if isinstance(storage, dict) and isinstance(storage.get(sid), dict):
            storage[sid].update(dict(dic))

    def _revoke_refresh_lineage(self, factory, lineage, sid=None):
        """Revoke all known generations of a refresh-token lineage."""
        if lineage is None and sid is not None:
            lineage = self._lineage_for_sid(sid)
        if sid is None:
            return factory.revoke_lineage(lineage)

        try:
            dic = dict(self._db[sid])
        except KeyError:
            storage = getattr(factory, "token_storage", None) or {}
            try:
                dic = dict(storage[sid])
            except KeyError:
                return factory.revoke_lineage(lineage)

        current_rt = dic.get("refresh_token")
        if current_rt:
            if lineage is not None and factory.get_token_meta(current_rt) is None:
                # The current generation may have been issued by another
                # process that shares the session backend.
                factory.register_token(
                    current_rt,
                    sid=sid,
                    client_id=dic.get("client_id"),
                    lineage=lineage,
                )
            factory.revoke_token_state(current_rt)

        current_at = dic.get("access_token")
        if current_at:
            self._invalidate_access_token(current_at)

        revoked = factory.revoke_lineage(lineage)
        if current_rt and current_rt not in revoked:
            revoked.append(current_rt)

        dic["revoked"] = True
        self._db[sid] = dic
        self._sync_refresh_factory_storage(factory, sid, dic)
        return revoked

    def get_refresh_token_lineage(self, rtoken):
        """Return the lineage identifier bound to a refresh token."""
        if self._refresh_db:
            return None
        factory = self.token_factory["refresh_token"]
        if factory is None:
            return None
        return factory.get_lineage(rtoken)

    def is_valid(self, token, client_id=None):
        """Check validity of the given token.

        :param token: Access or refresh token
        :param client_id: Client ID, needed only for Refresh token
        """
        if token.startswith("Refresh_"):
            if self._refresh_db is None:
                return False
            return self._refresh_db.verify_token(client_id, token)

        try:
            typ, sid = self._get_token_type_and_key(token)
        except KeyError:
            return False

        if self.is_revoked(sid):
            return False

        if typ == "A":
            _dic = self._db[sid]
            if _dic["code"] != token:
                return False
            elif _dic["oauth_state"] != "authz":
                return False

        elif typ == "T":
            _dic = self._db[sid]
            if _dic["access_token"] != token:
                return False

            if not self.access_token.valid(token):
                return False

        elif typ == "R":
            factory = self.token_factory["refresh_token"]
            if factory is None:
                return False

            meta = factory.get_token_meta(token)
            if meta is not None:
                if client_id is not None and meta.get("client_id") is not None and meta["client_id"] != client_id:
                    return False
                if meta.get("consumed", False) or meta.get("revoked", False):
                    return False

            if client_id is not None:
                try:
                    session = self._db[sid]
                except KeyError:
                    session = None
                if session is not None and session.get("client_id") not in (None, client_id):
                    return False

            if factory.is_expired(token):
                return False
            if factory.valid(token):
                return True

            # With opaque tokens the factory may not know the token after a
            # restart (its in-memory storage was recreated).  The session is
            # authoritative in that case.
            try:
                session = self._db[sid]
            except KeyError:
                return False
            return session.get("refresh_token") == token and not session.get("revoked", False)
        return True

    def is_revoked(self, sid):
        try:
            return self[sid]["revoked"]
        except KeyError:
            return False

    def revoke_token(self, token):
        """Revoke access token.

        :param token: access token
        """
        _, sid = self._get_token_type_and_key(token)

        self.update(sid, "revoked", True)
        return True

    def revoke_refresh_token(self, rtoken):
        """Revoke refresh token.

        :param rtoken: Refresh token
        """
        if self._refresh_db:
            self._refresh_db.revoke_token(rtoken)
        elif self.token_factory["refresh_token"] is not None:
            self.token_factory["refresh_token"].invalidate(rtoken)

        return True

    def revoke_all_tokens(self, token):
        """Mark session as revoked but also explicitly revoke refresh token.

        :param token: access token
        """
        _, sid = self._get_token_type_and_key(token)

        try:
            rtoken = self._db[sid]["refresh_token"]
        except KeyError:
            pass
        else:
            factory = self.token_factory.get("refresh_token")
            meta = factory.get_token_meta(rtoken) if factory is not None else None
            if factory is not None and meta is not None and meta.get("lineage"):
                self._revoke_refresh_lineage(factory, meta["lineage"], sid)
            else:
                self.revoke_refresh_token(rtoken)

        self.revoke_token(token)
        return True

    def get_client_id_for_session(self, sid):
        _dict = self._db[sid]
        return _dict["client_id"]

    def get_client_ids_for_uid(self, uid: str) -> list[str]:
        """Return client_ids for a given uid."""
        return self._db.get_client_ids_for_uid(uid)

    def get_verify_logout(self, uid: str) -> str | None:
        """Return logout verification key for given uid."""
        return self._db.get_verified_logout(uid)

    def get_token_ids(self, uid: str) -> list[str]:
        """Return id_tokens for given uid."""
        return self._db.get_token_ids(uid)

    def set_verify_logout(self, uid: str) -> None:
        """Save the key that is used for logout verification."""
        for sid in self._db.get_by_uid(uid):
            _dict = self._db[sid]
            _dict["verified_logout"] = uuid.uuid4().urn

    def is_revoke_uid(self, uid: str) -> bool:
        """Return if the uid session has been revoked."""
        return self._db.is_revoke_uid(uid)

    def revoke_uid(self, uid: str) -> None:
        """Mark all sessions for the given uid as revoked."""
        for sid in self._db.get_by_uid(uid):
            self.update(sid, "revoked", True)

    def duplicate(self, sinfo):
        _dic = copy.copy(sinfo)
        areq = AuthorizationRequest().from_json(_dic["authzreq"])
        sid = self.token_factory["code"].key(user=_dic["sub"], areq=areq)

        _dic["code"] = self.token_factory["code"](sid=sid, sinfo=sinfo)
        _dic["code_used"] = False

        for key in [
            "access_token",
            "access_token_scope",
            "oauth_state",
            "token_type",
            "token_expires_at",
            "expires_in",
            "client_id_issued_at",
            "id_token",
            "oidreq",
            "refresh_token",
        ]:
            try:
                del _dic[key]
            except KeyError:
                pass

        self._db[sid] = _dic
        self._db.update(sid, "sub", _dic["sub"])

        return sid

    def read(self, token):
        (typ, key) = self._get_token_type_and_key(token)

        if typ != "T":  # not a access grant
            raise WrongTokenType("Not a grant token")

        return self._db[key]

    def get_by_sub(self, sub: str) -> list[str]:
        """Return session ids based on `sub` (external user identifier)."""
        return self._db.get_by_sub(sub)

    def make_smid(self, sid: str) -> str:
        """Create a session management ID.

        :param sid:
        :return: A session management ID
        """
        return hashlib.sha256("{}{}".format(sid, self.sm_salt).encode("utf-8")).hexdigest()

    def get(self, attr: str, val: Any) -> list[str]:
        """Return session ids based on attribute name and value."""
        return self._db.get(attr, val)

    def get_by_uid(self, uid: str) -> list[str]:
        """Return session ids (keys) based on `uid` (internal user identifier)."""
        return self._db.get_by_uid(uid)

    def get_uid_by_sub(self, sub: str) -> str:
        """Return session ids based on `sub` (external user identifier)."""
        return self._db.get_uid_by_sub(sub)

    def get_uid_by_sid(self, sub: str) -> str:
        """Return User id based on sub."""
        return self._db.get_uid_by_sid(sub)


def session_get(db, attr, val):
    """Return session ID based on attribute having value val."""
    if isinstance(db, (SessionBackend, SessionDB)):
        if attr == "uid":
            return db.get_by_uid(val)
        else:
            return db.get(attr, val)
    elif isinstance(db, dict):
        warnings.warn(
            "Using a regular dictionary is deprecated, please use `SessionDB` or `SessionBackend` instead.",
            DeprecationWarning,
            stacklevel=2,
        )

        if attr == "uid":
            for _key, _val in db.items():
                if _val["authn_event"]["uid"] == val:
                    return _key
        else:
            for _key, _val in db.items():
                if _val.get(attr) == val:
                    return _key
        return None
    else:
        raise ValueError("Unknown session database type")


def session_extended_get(db, sub, attr, val):
    """Return session ID based on subject_id and attribute attr having value val."""
    if isinstance(db, (SessionBackend, SessionDB)):
        for sid in db.get_by_sub(sub):
            try:
                if db[sid][attr] == val:
                    return sid
            except KeyError:
                continue
        return None
    elif isinstance(db, dict):
        warnings.warn(
            "Using a regular dictionary is deprecated, please use `SessionDB` or `SessionBackend` instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        for _key, _val in db.items():
            try:
                if _val["sub"] == sub and _val[attr] == val:
                    return _key
            except KeyError:
                continue
        return None
    else:
        raise ValueError("Unknown session database type")


def session_set(db, attr, val):
    if isinstance(db, SessionBackend):
        db[attr] = val
    elif isinstance(db, SessionDB):
        db._db.set(attr, val)
    elif isinstance(db, dict):
        warnings.warn(
            "Using a regular dictionary is deprecated, please use `SessionDB` or `SessionBackend` instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        db[attr] = val
    else:
        raise ValueError("Unknown session database type")


def session_update(db, key, attr, val):
    if isinstance(db, SessionBackend):
        db.update(key, attr, val)
    elif isinstance(db, SessionDB):
        db._db.update(key, attr, val)
    elif isinstance(db, dict):
        warnings.warn(
            "Using a regular dictionary is deprecated, please use `SessionDB` or `SessionBackend` instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        item = db[key]
        item[attr] = val
        db[key] = item
    else:
        raise ValueError("Unknown session database type")
