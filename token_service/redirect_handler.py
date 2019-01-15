import base64
import datetime
import json
import jwt
import logging
import requests
from calendar import timegm
logger = logging.getLogger(__name__)
try:
    from urllib.parse import quote
except ImportError:
    from urllib import quote
from django.http import (
        HttpResponse,
        HttpResponseBadRequest,
        HttpResponseRedirect,
        JsonResponse,
        HttpResponseServerError)
from django.utils.timezone import now
from .util import generate_nonce, build_redirect_url, sha256, is_str
from .config import Config
# Moved from lazy import.
#    TODO: assumed that lazy import was needed for crypt initialisation
#          but there's a runtime exception when using non-initialised crypt
from . import models
from .util import logging_sensitive

STANDARD_OPENID_CONNECT = 'OpenID Connect'
STANDARD_OAUTH2 = 'OAuth 2.0'
SUPPORTED_STANDARDS = [STANDARD_OPENID_CONNECT, STANDARD_OAUTH2]
PROVIDER_GLOBUS = 'globus'
PROVIDER_GOOGLE = 'google'
PROVIDER_AUTH0 = 'auth0'
DEFAULT_PROVIDER = PROVIDER_AUTH0

def is_supported(provider):
    return Config['providers'][provider]['standard'] in SUPPORTED_STANDARDS


def is_openid(provider):
    return Config['providers'][provider]['standard'] == STANDARD_OPENID_CONNECT


def is_oauth2(provider):
    return Config['providers'][provider]['standard'] == STANDARD_OAUTH2


def get_or_update_OIDC_cache(provider_tag):
    provider_config = Config['providers'][provider_tag]
    meta_url = provider_config['metadata_url']
    cache = models.OIDCMetadataCache.objects.filter(provider=provider_tag)
    if cache.count() == 0 or (cache[0].retrieval_time + datetime.timedelta(hours=24)) < now():
        # not cached, or cached entry is more than 1 day old
        response = requests.get(meta_url)
        if response.status_code != 200:
            raise RuntimeError('could not retrieve openid metadata from {}, returned error: {}\n{}'.format(
                meta_url, response.status_code, response.content.decode('utf-8')))
        content = response.content.decode('utf-8')
        meta = json.loads(content)
        # cache this metadata
        if cache.count() == 0:  # create
            logging.info('Creating new OIDC metadata cache entry for [{}]'.format(provider_tag))
            models.OIDCMetadataCache.objects.create(provider=provider_tag, value=content, retrieval_time=now())
        else:  # update
            logging.info('Updating OIDC metadata cache for [{}]'.format(provider_tag))
            c = cache[0]
            c.value = content
            c.retrieval_time = now()
            c.save()
    else:
        meta = json.loads(cache[0].value)
    return meta


def get_provider_config(provider, key, *args):
    """
    Retrieve key from provider config.
    If provider is openid, and key is not in the config,
        (try to) get the key from the metadata
    Raises a RuntimeError when provider standard is not supported.

    If a 3rd argument is provided, it is treated as a default value.
    If not such default value is provided, raise a KeyError on failure to get key
    """
    if '|' in provider and not provider.startswith('|') and not provider.endswith('|'):
        terms = provider.split('|')
        if len(terms) <= 1:
            raise RuntimeError('Found provider separator in provider name {}, but could not split'.format(
                provider))
        else:
            if len(terms) > 2:
                logger.warn('Received provider with more than two terms: {}'.format(provider))
            provider = terms[0]
            backend = terms[1]
            logger.debug('Split provider into provider: {}, backend: {}'.format(provider, backend))
    config = Config['providers'][provider]

    if not is_supported(provider):
        raise RuntimeError('could not get {} from provider {} with unrecognized standard {}'.format(
            key, provider, config['standard']))

    msg = None
    if key in config:
        data = config[key]
        logging.debug("Got %s for %s from provider %s config", data, key, provider)
        return data
    else:
        if is_openid(provider):
            meta = get_or_update_OIDC_cache(provider)
            if key in meta:
                data = meta[key]
                logging.debug("Got %s for %s from provider %s openid metadata", data, key, provider)
                return data
            else:
                msg = "No %s config from openid provider" % key
        else:
            msg = "No %s config from provider" % key

    if msg:
        if len(args) > 0:
            default = args[0]
            logging.debug("%s, returning default %s", msg, default)
            return default
        else:
            logging.warn(msg)
            raise KeyError(msg)


def get_handler(request=None, token=None):
    if not request and not token:
        return RedirectHandler()
    if request:
        state = request.GET.get('state')
        provider = request.GET.get('provider')
        if not provider and state:
            w = get_pending_by_state(state)
            if not w:
                return None
            provider = w.provider
        elif not provider and not state:
            return None
    elif token:
        provider = token.provider

    if provider == PROVIDER_GLOBUS:
        return GlobusRedirectHandler()
    elif provider.startswith(PROVIDER_AUTH0):
        return Auth0RedirectHandler()
    else:
        return RedirectHandler()


def get_pending_by_state(state):
    return get_pending_by_field_one('state', state)


def get_pending_by_nonce(nonce):
    return get_pending_by_field_one('nonce', nonce)


def get_pending_by_field(fieldname, fieldval):
    # TODO update with native encrypted filtering
    queryset = models.PendingCallback.objects.all()
    pending = []
    for q in queryset:
        if getattr(q, fieldname) == fieldval:
            pending.append(q)
    return pending


def get_pending_by_field_one(fieldname, fieldval):
    pending = get_pending_by_field(fieldname, fieldval)
    if len(pending) != 1:
        return None
    else:
        return pending[0]


def get_validator(provider=DEFAULT_PROVIDER):
    inv = RuntimeError('invalid provider {}'.format(str(provider)))
    if not provider:
        return Auth0Validator()
    if provider == PROVIDER_GOOGLE:
        return GoogleValidator()
    elif provider.startswith(PROVIDER_AUTH0):
        return Auth0Validator()
    elif provider == PROVIDER_GLOBUS:
        return GlobusValidator()
    else:
        raise inv


def get_user(provider, sub, user_name=None, name=None, warn=True):
    """
    Get user with sub and provider.

    When user_name is provided, and the user does not exist yet;
    creates one.

    Raises an error when not unique (but is forced by schema)
    """
    users = models.User.objects.filter(sub=sub, provider=provider)
    nusers = len(users)

    msg = "user for provider {} and sub {}".format(provider, sub)
    if nusers == 0:
        if user_name is not None:
            logging.info("No %s found, creating one with user_name %s and name %s",
                         msg, user_name, name)
            kwargs = {
                'sub': sub,
                'provider': provider,
                'user_name': user_name,
            }
            if name is not None:
                kwargs['name'] = name

            user = models.User(**kwargs)
            user.save()
        else:
            if warn:
                report = logging.warn
            else:
                report = logging.debug
            report("No %s found, not user_name/name provided", msg)
            user = None
    elif nusers > 1:
        logging.exception("Found more than one user for provider %s and sub %s" % (provider, sub))
        raise
    else:
        logging.info("Existing user for provider %s and sub %s", provider, sub)
        user = users[0]

    return user


class RedirectHandler(object):
    '''
    This is the top level handler of authorization redirects and authorization url generation.

    For non-standard APIs which do not conform to OAuth 2.0 (specifically RFC 6749 sec 4.1), extensions may be required.
    (RFC 6749 sec 4.1.1 https://tools.ietf.org/html/rfc6749#section-4.1.1)
    Example: Dropbox APIv2 does not completely conform to RFC 6749#4.1.1 (authorization) nor 6749#4.1.3 (token exchange)

    State/nonce values in the urls generated by this class must not be modified by the client application or end user.
    Requests received which do not match state/nonce values generated by this class will be rejected.

    Does not yet support webfinger OpenID issuer discovery/specification.
    '''
    # TODO SSL Cert verification on all https requests. Force SSL on urls.
    #   Attempt to autodetect cacert location based on os, otherwise pull Mozilla's https://curl.haxx.se/ca/cacert.pem
    #   also look at default ssl verification in requests package, and in pyoidc package, could rely on them

    IDTOKEN_USER_NAME = ['preferred_username', 'email']
    IDTOKEN_NAME = ['name']
    IDTOKEN_EMAIL = ['email']

    def __init__(self):
        # timeout in seconds for authorization callbacks to be received
        # default is 300 (5 minutes)
        self.authorization_timeout = int(Config.get('authorization_timeout', 60*5))

    def add(self, uid, scopes, provider_tag, return_to=None):
        '''
        uid: unique user identifier
        scopes: iterable of strings, used by OAuth2 and OpenID. If requesting authentication
                    via an OpenID provider, this must include 'openid'.
        provider_tag: matched against provider dictionary keys in the configuration loaded at startup
        '''
        logging.debug('adding callback waiter with uid %s, scopes %s, provider %s, return_to %s',
                      uid, scopes, provider_tag, return_to)
        additional_scopes = get_provider_config(provider_tag, 'additional_scopes', [])
        if additional_scopes:
            logging.debug("Add additional scopes %s for provider %s to current scopes %s",
                          additional_scopes, provider_tag, scopes)
            scopes.extend(additional_scopes)
        if uid is None:
            uid = ''
        if return_to is None:
            return_to = ''
        else:
            # santize input TODO what to do if no protocol specified
            return_to = return_to.strip('/')

        # enforce uniqueness of nonces
        # TODO cleanup old ones after authorization url expiration threshold
        while True:
            nonce = generate_nonce(64)  # url safe 32byte (64byte hex)
            if self.is_nonce_unique(nonce):
                break
        while True:
            state = generate_nonce(64)
            if self.is_nonce_unique(state):
                break

        n_db = models.Nonce(value=nonce)
        n_db.save()
        s_db = models.Nonce(value=state)
        s_db.save()

        url = self._generate_authorization_url(state, nonce, scopes, provider_tag)
        pending = models.PendingCallback(
                uid=uid,
                state=state,
                nonce=nonce,
                provider=provider_tag,
                url=url,
                return_to=return_to
        )
        pending.save()
        # create scopes if not exist:
        for scope in scopes:
            s, created = models.Scope.objects.get_or_create(name=scope)
            pending.scopes.add(s)

        pending.save()
        return url, nonce

    def accept(self, request):
        '''
        Accept a request conforming to Authorization Code Flow OIDC Core 1.0 section 3.1.2.5
        (http://openid.net/specs/openid-connect-core-1_0.html#AuthResponse)

        request is a django.http.HttpRequest

        Returns an HttpResponse, with corresponding values filled in for client
        '''
        state = request.GET.get('state')
        code = request.GET.get('code')
        if not code:
            return HttpResponseBadRequest('callback did not contain an authorization code')
        if not state:
            return HttpResponseBadRequest('callback state did not match expected')

        w = get_pending_by_state(state)
        if not w:
            return HttpResponseBadRequest('callback request from login is malformed, or authorization session expired')
        else:
            logging.debug('accepted request maps to pending callback object: %s', vars(w))
            if now() > w.creation_time + datetime.timedelta(seconds=Config['url_expiration_timeout']):
                logging.warn('authorization url has expired object: %s', vars(w))
                return HttpResponseBadRequest('This authorization url has expired, please retry')
            provider = w.provider
            token_endpoint = get_provider_config(provider, 'token_endpoint')

            client_id = Config['providers'][provider]['client_id']
            client_secret = Config['providers'][provider]['client_secret']
            redirect_uri = Config['redirect_uri']

            token_response = self._token_request(
                    token_endpoint,
                    client_id,
                    client_secret,
                    code,
                    redirect_uri)
            if token_response.status_code not in [200, 302]:
                return HttpResponseServerError('could not acquire token from provider' + str(vars(token_response)))

            if provider == PROVIDER_GLOBUS:
                handler = GlobusRedirectHandler()
            elif provider == PROVIDER_AUTH0:
                handler = Auth0RedirectHandler()
            else:
                handler = self
            (success, msg, user, token, nonce) = handler._handle_token_response(w, token_response)

            if not success:
                return HttpResponseServerError(msg + ':' + token_response)

            if w.return_to:
                ret = HttpResponseRedirect(build_redirect_url(w.return_to, token))
            else:
                ret = HttpResponse('Successfully authenticated user. Browser tab can be safely closed.')

            w.delete()
            return ret

    def get_user_name_name(self, provider, id_token):
        def _attr(keys, what):
            for key in keys:
                if key in id_token:
                    return id_token[key]
            logging.warn("no attribute found in id_token for %s, tried %s; returning empty string",
                         what, ', '.join(keys))
            return ''

        user_name = _attr(get_provider_config(provider, 'user_name_from_token', self.IDTOKEN_USER_NAME),
                          'user_name')
        name = _attr(get_provider_config(provider, 'name_from_token', self.IDTOKEN_NAME), 'name')

        return user_name, name

    def _handle_token_body(self, user, provider, issuer, scopes, nonce, token_dict, act_hash=True):
        """
        scopes are the scope names (not Scope model instances)
        """
        logging.debug('handling token %s for user %s provider %s issuer %s scopes %s',
                      token_dict, user, provider, issuer, scopes)
        access_token = token_dict['access_token']
        expires_in = token_dict['expires_in']
        refresh_token = token_dict.get('refresh_token', None)

        # convert expires_in to timestamp
        n = now()
        iat_local = timegm(n.timetuple())

        expire_time = n + datetime.timedelta(seconds=expires_in)
        exp_local = timegm(expire_time.timetuple())
        logging.debug("token expire_time %s (expires_in %s local iat %s local exp %s)",
                      expire_time, expires_in, iat_local, exp_local)

        kwargs = {
            'user': user,
            'access_token': access_token,
            'refresh_token': refresh_token,  # TODO what if no refresh_token in response
            'expires': expire_time,
            'provider': provider,
            'issuer': issuer,
            'enabled': True,
        }

        if act_hash:
            kwargs['access_token_hash'] = sha256(access_token)

        token = models.Token(**kwargs)
        token.save()
        logging_sensitive('saved token: %s', vars(token))

        n, created = models.Nonce.objects.get_or_create(value=nonce)
        token.nonce.add(n)

        for scope in scopes:
            s, created = models.Scope.objects.get_or_create(name=scope)
            token.scopes.add(s)
        return (True, '', user, token, nonce)

    def _provider_sub_from_id_token(self, provider, id_token):
        return provider, id_token['sub']

    def _handle_token_response(self, w, response):
        '''
        Called upon successful exchange of an authorization code for an access token.
        Takes w a token_service.models.PendingCallback object and a requests.models.Response object
        Returns (bool, message, user_instance, token, nonce) or raises exception.
        '''
        body = json.loads(response.content)
        id_token = body['id_token']

        # expand the id_token to the encoded json object
        # TODO signature validation if signature provided
        id_token = jwt.decode(id_token, verify=False)
        logging.debug('id_token: %s', id_token)
        if 'iat' in id_token and 'exp' in id_token:
            # TODO: Why not use these?
            logging.debug("from token iat %s exp %s", id_token['iat'], id_token['exp'])

        provider, sub = self._provider_sub_from_id_token(w.provider, id_token)
        issuer = id_token['iss']

        nonce = id_token['nonce']
        if nonce != w.nonce:
            msg = 'login request malformed or expired'
            logging.warn("%s nonce form id_token %s from w %s", msg, nonce, w.nonce)
            return (False, msg, None, None, None)

        user_name, name = self.get_user_name_name(provider, id_token)
        user = get_user(provider, sub, user_name, name)
        
        # add email
        for email_key in self.IDTOKEN_EMAIL:
            if email_key in id_token:
                user.email = id_token[email_key]
                user.save()
                logging.debug('filled in email address [{}] for user [{}]'.format(
                        id_token[email_key], user.user_name))
                break

        scope_names = [s.name for s in w.scopes.all()]
        return self._handle_token_body(user, w.provider, issuer, scope_names, nonce, body)

    def validate_token(self, provider, access_token, scopes=None):
        logging.debug('validate_token: provider: %s, access_token: %s', provider, access_token)
        headers = {
            'Authorization': 'Bearer ' + str(access_token)
        }

        try:
            ept = get_provider_config(provider, 'introspection_endpoint')
            # TODO: why would the endpoint url support templating?
            endpoint = ept % access_token
            logging.debug("Got introspection endpoint %s (from config %s)", endpoint, ept)
        except KeyError:
            # non oidc providers must specify a userinfo_endpoint on the config file
            endpoint = get_provider_config(provider, 'userinfo_endpoint')
            logging.debug("No introspection endpoint, using userinfo endpoint %s", endpoint)

        response = requests.get(endpoint, headers=headers)
        content = response.content.decode('utf-8')
        if response.status_code != 200:
            return HttpResponse(status=401, content='Invalid token: ' + content)
        else:
            return JsonResponse(status=200, data=json.loads(content))

    def _token_request(self, token_endpoint, client_id, client_secret, code, redirect_uri):
        '''
        Performs the request to the token endpoint and returns a response object from the requests library

        Token endpoint MUST be TLS, because client secret is sent combined with client id in the authorization header.
        Client id is also sent as a parameter, because some APIs want that.
        '''
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'access_type': 'offline',
            'client_id': client_id
        }

        # set up headers and send request. Return raw requests response
        authorization = base64.b64encode((client_id + ':' + client_secret).encode('utf-8'))
        headers = {
            'Authorization': 'Basic ' + str(authorization.decode('utf-8')),
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = requests.post(token_endpoint, headers=headers, data=data)
        return response

    def _refresh_token(self, token_model):
        provider = token_model.provider
        token_endpoint = get_provider_config(provider, 'token_endpoint')

        data = {
            'grant_type': 'refresh_token',
            'refresh_token': token_model.refresh_token
        }
        provider_config = Config['providers'][provider]
        client_id = provider_config['client_id']
        client_secret = provider_config['client_secret']
        authorization = base64.b64encode((client_id + ':' + client_secret).encode('utf-8'))
        headers = {
            'Authorization': 'Basic ' + str(authorization.decode('utf-8')),
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = requests.post(token_endpoint, headers=headers, data=data)
        if response.status_code != 200:
            raise RuntimeError('could not refresh token, provider returned: {}\n{}'.format(
                response.status_code, response.content))
        else:
            content = response.content.decode('utf-8')
            obj = json.loads(content)
            if 'access_token' not in obj or 'expires_in' not in obj or 'token_type' not in obj:
                raise RuntimeError('refresh response missing required fields: {}\n{}'.format(
                    response.status, str(obj)))
            token_model.expires = now() + datetime.timedelta(seconds=int(obj['expires_in']))
            token_model.access_token = obj['access_token']
            if 'refresh_token' in obj:
                token_model.refresh_token = obj['refresh_token']
            token_model.save()
            return token_model

    def is_nonce_unique(self, nonce):
        # TODO update with https://github.com/heliumdatacommons/auth_microservice/issues/4 when resolved
        queryset = models.Nonce.objects.all()
        for n in queryset:
            if n.value == nonce:
                return False
        return True

    def _generate_authorization_url(self, state, nonce, scopes, provider_tag):
        '''
        Create a proper authorization url based on provided parameters
        '''
        authorization_endpoint = get_provider_config(provider_tag, 'authorization_endpoint')

        provider_config = Config['providers'][provider_tag]
        client_id = provider_config['client_id']
        redirect_uri = Config['redirect_uri']

        additional_params = '&' + provider_config.get('additional_params', '')

        # get auth endpoint
        if is_openid(provider_tag):
            scope = quote(' '.join(scopes))

            additional_params += '&scope=' + scope
            additional_params += '&response_type=code'
            additional_params += '&access_type=offline'
            if provider_config.get('prompt', True):
                additional_params += '&prompt=login%20consent'

        if additional_params == '&':
            additional_params = ''

        url = '{}?nonce={}&state={}&redirect_uri={}&client_id={}{}'.format(
            authorization_endpoint,
            nonce,
            state,
            redirect_uri,
            client_id,
            additional_params,
        )
        return url


class Auth0RedirectHandler(RedirectHandler):
    IDTOKEN_USER_NAME = ['preferred_username', 'email', 'nickname']

    def _generate_authorization_url(self, state, nonce, scopes, provider_tag):
        if provider_tag != PROVIDER_AUTH0:
            raise RuntimeError('incorrect provider_tag in Auth0RedirectHandler._generate_authorization_url')
        # This login field provides a Auth0 login UI and is specific to Auth0
        endpoint = Config['providers'][PROVIDER_AUTH0]['login_endpoint']
        redirect_uri = Config['redirect_uri']
        client_id = Config['providers'][PROVIDER_AUTH0]['client_id']

        scope = ' '.join(scopes)
        scope = quote(scope)
        additional_params = 'scope=' + scope
        additional_params += '&response_type=code'

        url = '{}?nonce={}&state={}&redirect_uri={}&client={}&{}'.format(
            endpoint,
            nonce,
            state,
            redirect_uri,
            client_id,
            additional_params
        )
        return url

    def accept(self, request):
        logging.debug("accept request %s", request)
        code = request.GET.get('code')
        state = request.GET.get('state')
        w = get_pending_by_state(state)
        if not w:
            return HttpResponseBadRequest('callback request from login is malformed, or authorization session expired')
        if now() > w.creation_time + datetime.timedelta(seconds=Config['url_expiration_timeout']):
                return HttpResponseBadRequest('This authorization url has expired, please retry')
        client_id = Config['providers'][PROVIDER_AUTH0]['client_id']
        client_secret = Config['providers'][PROVIDER_AUTH0]['client_secret']
        redirect_uri = Config['redirect_uri']
        token_endpoint = 'https://heliumdatacommons.auth0.com/oauth/token'
        token_response = self._token_request(
                    token_endpoint,
                    client_id,
                    client_secret,
                    code,
                    redirect_uri)
        (success, msg, user, token, nonce) = self._handle_token_response(w, token_response)

        if not success:
            return HttpResponseServerError(msg + ':' + token_response)

        if w.return_to:
            ret = HttpResponseRedirect(build_redirect_url(w.return_to, token))
        else:
            ret = HttpResponse('Successfully authenticated user')

        w.delete()
        return ret

    def _provider_sub_from_id_token(self, provider, id_token):
        # for some returns [[oauth2|]backend|]sub
        #   split it and reverse it
        s_parts = id_token['sub'].split('|')[::-1]

        sub = s_parts[0]

        p_parts = [provider]
        if len(s_parts) > 1:
            p_parts.append(s_parts[1])
        provider = '|'.join(p_parts)

        return provider, sub

    def _refresh_token(self, token_model):
        provider_config = Config['providers'][PROVIDER_AUTH0]
        if not token_model.refresh_token:
            # don't rely on exception for this
            raise RuntimeError('No refresh token available')

        data = {
            'grant_type': 'refresh_token',
            'refresh_token': token_model.refresh_token
        }
        client_id = provider_config['client_id']
        client_secret = provider_config['client_secret']
        authorization = base64.b64encode((client_id + ':' + client_secret).encode('utf-8'))
        headers = {
            'Authorization': 'Basic ' + str(authorization.decode('utf-8')),
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = requests.post(token_endpoint, headers=headers, data=data)
        if response.status_code != 200:
            raise RuntimeError('could not refresh token, provider returned: {}\n{}'.format(
                response.status_code, response.content))
        else:
            content = response.content.decode('utf-8')
            obj = json.loads(content)
            if 'access_token' not in obj or 'expires_in' not in obj or 'token_type' not in obj:
                raise RuntimeError('refresh response missing required fields: {}\n{}'.format(
                    response.status, str(obj)))
            token_model.expires = now() + datetime.timedelta(seconds=int(obj['expires_in']))
            token_model.access_token = obj['access_token']
            if 'refresh_token' in obj:
                token_model.refresh_token = obj['refresh_token']
            token_model.save()
            return token_model


class GlobusRedirectHandler(RedirectHandler):
    '''
    Almost everything is the same for Globus, except when user authorizes scopes which span
    resource servers, there is an access token returned per-server, instead of one which
    encompasses all of the scopes.
    '''

    def _handle_token_response(self, w, response):
        '''
        allow RedirectHandler to do everything except the parsing and handling of the token response
        this also differs from RedirectHandler._handle_token_response because there can be multiple
        tokens in the callback request. This method returns as the token return object, the top
        level token in the response, but also stores the 'other_tokens'
        '''
        body = json.loads(response.content)
        issuer = body['resource_server']
        scopes = []
        if is_str(body['scope']):
            scopes.append(body['scope'])

        tokens = []
        user = token = nonce = None

        def _htb(_user, _nonce, _dict):
            # TODO: act_hash False?
            return self._handle_token_body(_user, PROVIDER_GLOBUS, issuer, scopes, _nonce, _dict, act_hash=False)

        # check to see if top level token is for openid
        if 'openid' in body['scope'] and 'id_token' in body:
            success, msg, user, token, nonce = super()._handle_token_response(w, response)
            if not success:
                return (success, msg, user, token, nonce)
            tokens.append(token)
        else:
            # TODO: globus users are always created without a name attribute?
            user = get_user(PROVIDER_GLOBUS, w.uid, w.uid)

            # For globus, on a token callback it also puts the state value into the root level
            # json object. This is actually pretty nice and should be part of the OAuth2.0 spec.
            # However substituting the state value for the nonce (in OAuth2 callbacks, not OIDC)
            # will break our ability to let clients query based on the initial nonce parameter
            # sent in the original authorization url. Use the nonce in the PendingCallback object
            # and link the tokens to it, even if the nonce was not returned to us in the token
            # callback from globus.
            # This also impacts other OAuth2.0 apis which do not return nonce.
            # TODO It might be useful to switch over to linking tokens to the 'state' value
            # instead of 'nonce' since 'state' is used by both openid and oauth2.
            nonce = w.nonce

            success, msg, user, token, nonce = _htb(user, nonce, body)
            if not success:
                return (success, msg, user, token, nonce)
            tokens.append(token)

        # check if user exists
        # TODO: is this really necessary/possible?
        # TODO: explanation is wrong, this is the else block above?
        if not user:  # no openid token was in this response
            # TODO: globus users are always created without a name attribute?
            user = get_user(PROVIDER_GLOBUS, w.uid, w.uid)

        for other_token in body.get('other_tokens', []):
            success, msg, user, token, nonce = _htb(user, nonce, other_token)
            # TODO: why handle more than one, only first element of tokens is passed?
            # TODO: not success check?
            tokens.append(token)

        return (True, '', user, tokens[0], nonce)

"""
This is a reference implementation for OIDC IPDs which conform exactly to spec
"""
class Validator(object):
    def validate(self, token, provider=DEFAULT_PROVIDER):
        endpoint = get_provider_config(provider, 'introspection_endpoint')

        creds = base64.b64encode('{}:{}'.format(
            Config['providers'][provider]['client_id'],
            Config['providers'][provider]['client_secret']).encode('utf-8'))
        headers = {
            'Authorization': 'Basic ' + creds.decode('utf-8'),
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        body = {'token': token}
        # TODO: debug sensitive?
        logging.debug("validate endpoint %s headers %s body %s", endpoint, json.dumps(headers), json.dumps(body))

        response = requests.post(endpoint, headers=headers, data=body)
        content = response.content.decode('utf-8')
        if response.status_code > 400:
            logging.error('validate failed on %s. returned [%s] %s', endpoint, response.status_code, content)
            return {'active': False}
        else:
            try:
                body = json.loads(content)
                logging.debug('validate repsonse body from json %s', body)
            except json.JSONDecodeError:
                logging.error('could not decode validate response: %s', content)
                return {'active': False}
            if body.get('active', None):
                r = {'active': True}
                if body.get('sub', None):
                    r['sub'] = body['sub']
                if body.get('username', None):
                    r['username'] = body['username']
                elif 'sub' in r:
                    # see if we recognize the subject id
                    user = get_user(provider, r['sub'], warn=False)
                    if user:
                        r['username'] = user.user_name
                return r
        return {'active': False}

class GlobusValidator(Validator):
    def validate(self, token, provider=PROVIDER_GLOBUS):
        return Validator().validate(token, provider)

class Auth0Validator(Validator):
    def validate(self, token, provider=PROVIDER_AUTH0):
        endpoint = Config['providers'][PROVIDER_AUTH0]['userinfo_endpoint']
        endpoint += '?access_token={}'.format(token)
        response = requests.get(endpoint)
        if response.status_code < 300:
            try:
                body = json.loads(response.content.decode('utf-8'))
                logging.debug('userinfo response: ' + str(body))
            except json.JSONDecodeError:
                logging.error('could not decode response: {}\n{}'.format(response, response.content))
                return {'active': False}
            r = {'active': True}
            if body.get('sub', None):
                s_parts = body['sub'].split('|')
                if len(s_parts) == 3:
                    s_parts = s_parts[1:]
                if len(s_parts) == 2:
                    sub = s_parts[1]
                else:
                    sub = s_parts[0]
                r['sub'] = sub
            if body.get('preferred_username', None):
                r['username'] = body['preferred_username']
            elif body.get('username', None):
                r['username'] = body['username']
            elif body.get('email', None):
                r['username'] = body['email']
            else:
                # see if we recognize the sub
                try:
                    user = get_user(provider, r['sub'], warn=False)
                    if user:
                        r['username'] = user.user_name
                except ObjectDoesNotExist:
                    pass
            return r
        else:
            # token could not fetch userprofile from auth0
            # check whether the access token is for a backend instead
            for validator in [GlobusValidator, GoogleValidator]:
                logging.debug('trying to validate against {} with token {}'.format(validator, token))
                vresp = validator().validate(token)
                if vresp['active'] == True:
                    return vresp
            return {'active': False}


class GoogleValidator(Validator):
    def validate(self, token, provider=PROVIDER_GOOGLE):
        ept = get_provider_config(provider, 'introspection_endpoint')
        endpoint = '{}?access_token={}'.format(ept, token)

        response = requests.post(endpoint)
        content = response.content.decode('utf-8')
        if response.status_code > 400:
            logging.warn('validate failed on %s. returned [%s] %s',
                         endpoint, response.status_code, content)
            return {'active': False}
        else:
            try:
                body = json.loads(content)
            except json.JSONDecodeError:
                logging.warn('could not decode validate response: %s', content)
                return {'active': False}
            if int(body.get('expires_in', '0')) > 0:
                r = {'active': True}
                if body.get('user_id', None):
                    r['sub'] = body['user_id']
                return r
        return {'active': False}
