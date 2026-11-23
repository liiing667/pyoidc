import time

from jwkest import jws

from oic.oauth2.message import AccessTokenResponse, AuthorizationResponse
from oic.utils.time_util import utc_time_sans_frac

__author__ = "roland"


def _id_token_hash_alg(alg):
    """Return the hash functor name used by at_hash/c_hash for ``alg``."""
    if alg == "none":
        return None
    if alg == "EdDSA":
        return "HS512"
    if alg == "ES256K":
        return "HS256"
    if isinstance(alg, str) and alg[:2] in ("HS", "RS", "ES", "PS") and alg[-3:] in ("256", "384", "512"):
        return "HS" + alg[-3:]
    return None


def _id_token_binds(id_token, tokens, code=None):
    """Check whether an ID Token is bound to the given token/code.

    This is only used when the response that carried the ID Token did not
    carry the token itself.  Without a matching at_hash/c_hash there is no
    evidence that the signed claims and the token belong together.
    """
    try:
        hfunc = _id_token_hash_alg(id_token.jws_header["alg"])
    except (AttributeError, KeyError, TypeError):
        # Be conservative for plain mappings that predate the IdToken object:
        # at_hash/c_hash still have to match a real token/code below.
        hfunc = "HS256"

    if hfunc is None:
        return False

    at_hash = id_token.get("at_hash")
    if at_hash:
        for token in tokens:
            access_token = getattr(token, "access_token", None)
            if access_token and at_hash == jws.left_hash(access_token, hfunc):
                return True

    c_hash = id_token.get("c_hash")
    if code and c_hash and c_hash == jws.left_hash(code, hfunc):
        return True

    return False


class Token:
    def __init__(self, resp=None):
        self.scope: list[str] = []
        self.token_expiration_time = 0
        self.access_token = None
        self.refresh_token = None
        self.token_type: str | None = None
        self.replaced = False
        self.id_token = None

        if resp:
            for prop, val in resp.items():
                setattr(self, prop, val)

            try:
                _expires_in = resp["expires_in"]
            except KeyError:
                return

            if _expires_in:
                _tet = utc_time_sans_frac() + int(_expires_in)
            else:
                _tet = 0
            self.token_expiration_time = int(_tet)

    def is_valid(self):
        if self.token_expiration_time:
            if utc_time_sans_frac() > self.token_expiration_time:
                return False

        return True

    def __str__(self):
        return "{}".format(self.__dict__)

    def keys(self):
        return self.__dict__.keys()

    def __eq__(self, other):
        skeys = self.keys()
        okeys = other.keys()
        if set(skeys) != set(okeys):
            return False

        for key in skeys:
            if getattr(self, key) != getattr(other, key):
                return False

        return True


class Grant:
    _authz_resp = AuthorizationResponse
    _acc_resp = AccessTokenResponse
    _token_class = Token

    def __init__(self, exp_in=600, resp=None, seed=""):
        self.grant_expiration_time = 0
        self.exp_in = exp_in
        self.seed = seed
        self.tokens: list[Token] = []
        self.id_token = None
        self.code: str | None = None
        if resp:
            self.add_code(resp)
            self.add_token(resp)

    @classmethod
    def from_code(cls, resp):
        instance = cls()
        instance.add_code(resp)
        return instance

    def add_code(self, resp):
        try:
            self.code = resp["code"]
            self.grant_expiration_time = utc_time_sans_frac() + self.exp_in
        except KeyError:
            pass

    def add_token(self, resp):
        """Add token to store.

        :param resp: An Authorization Response instance
        """
        if "access_token" in resp:
            tok = self._token_class(resp)
            self.tokens.append(tok)

    def is_valid(self):
        if utc_time_sans_frac() > self.grant_expiration_time:
            return False
        else:
            return True

    def __str__(self):
        return "{}".format(self.__dict__)

    def keys(self):
        return self.__dict__.keys()

    def update(self, resp):
        if "access_token" in resp or "id_token" in resp:
            tok = self._token_class(resp)
            if tok not in self.tokens:
                for otok in self.tokens:
                    otok.replaced = True
                self.tokens.append(tok)

        if "code" in resp:
            self.add_code(resp)

    def get_token(self, scope=""):
        token = None
        if scope:
            for token in self.tokens:
                if scope in token.scope and not token.replaced:
                    return token
        else:
            for token in self.tokens:
                if token.is_valid() and not token.replaced:
                    return token

        return token

    def delete_token(self, token):
        """Remove the specified token if it exists."""
        try:
            self.tokens.remove(token)
        except ValueError:
            pass

    def get_id_token(self):
        now = time.time()

        if self.id_token and self.id_token.get("exp", 0) >= now:
            return self.id_token

        active = [tok for tok in self.tokens if not tok.replaced and tok.is_valid()]

        # Prefer the ID Token that arrived in the same response as the current
        # token.  This keeps the signed claims, the hash and the token that is
        # actually used by the client together.
        for tok in active:
            id_token = getattr(tok, "id_token", None)
            if id_token and id_token.get("exp", 0) >= now:
                return id_token

        # No token is currently usable.  The most recent response is still a
        # self-contained pair, so its own ID Token may be used (for example as
        # an id_token_hint), but an ID Token from an earlier response must not
        # be borrowed for it.
        if not active and self.tokens:
            id_token = getattr(self.tokens[-1], "id_token", None)
            if id_token and id_token.get("exp", 0) >= now:
                return id_token

        # A pure ID Token response has no access token to pair with.
        if not any(getattr(tok, "access_token", None) for tok in self.tokens):
            for tok in self.tokens:
                id_token = getattr(tok, "id_token", None)
                if id_token and id_token.get("exp", 0) >= now:
                    return id_token

        # The token response may not contain a fresh ID Token.  Reuse an
        # earlier one only if its hash proves that it belongs to the current
        # token or the code stored in this grant.
        for tok in self.tokens:
            id_token = getattr(tok, "id_token", None)
            if id_token and id_token.get("exp", 0) >= now and _id_token_binds(id_token, active, self.code):
                return id_token

        return None

    def join(self, grant):
        if not self.exp_in:
            self.exp_in = grant.exp_in
        if not self.grant_expiration_time:
            self.grant_expiration_time = grant.grant_expiration_time
        if not self.seed:
            self.seed = grant.seed
        for token in grant.tokens:
            if token not in self.tokens:
                for otok in self.tokens:
                    if token.scope == otok.scope:
                        otok.replaced = True
                self.tokens.append(token)
