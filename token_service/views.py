import logging
import re
import time
from django.http import (
        HttpResponseBadRequest,
        JsonResponse,
        HttpResponseNotFound,
        HttpResponseForbidden,
        HttpResponseRedirect)
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils.timezone import now
from django.core.exceptions import (
        ObjectDoesNotExist)
from django.shortcuts import get_object_or_404
from . import models
from . import redirect_handler
from . import config
from . import util

Config = config.Config
access_token_validation_cache = {}


def _http_response(klass, msg):
    logging.debug("%s %s", klass.__name__, msg)
    return klass(msg)


@require_http_methods(['GET'])
def create_key(request):
    authorization = request.META.get('HTTP_AUTHORIZATION')
    # TODO: replace with sensitive logging?
    logging.debug('create_key authorization: %s', authorization)
    m = re.match(r'^Basic (\w{64})', authorization or '')
    if m:
        received_key = m.group(1)
        if received_key != config.admin_key:
            return _http_response(HttpResponseForbidden, 'must provide admin credentials')
    else:
        return _http_response(HttpResponseForbidden, 'must provide credentials')

    owner = request.GET.get('owner')
    if not owner:
        return _http_response(HttpResponseBadRequest, 'must provide owner string')
    key = util.generate_nonce(64)
    key_hash = util.sha256(key)
    logging.debug('new key: %s, hash: %s, owner: %s', key, key_hash, owner)
    db_entry = models.API_key(key_hash=key_hash, owner=owner)
    db_entry.save()
    return JsonResponse(status=200, data={'key': key})


def isint(s):
    try:
        int(s)
        return True
    except ValueError:
        return False


def _get_tokens(uid, scopes, provider, validate=False):
    '''
    This queries for tokens belonging to a given uid/subjectid, with a superset of the scopes, in a given provider.

    If validate is True, will additionally perform a validate_token operation on each token before returning it.
    Note that enabling validate will provide real-time token revocation checks with the provider, but this could
    have a serious performance impact.
    '''
    logging.debug('querying for tokens: uid %s, scopes %s, provider %s', uid, scopes, provider)
    # Django can do a filter using a subset operation for linked many-to-many, but not a filter using superset
    # we need to find tokens whose scopes are a superset of the scopes list being requested
    queryset = models.Token.objects.filter(
        user__sub=uid,
        # scopes__in=models.Scope.objects.filter(name__in=scopes),
        provider=provider
    ).order_by('expires')  # sort by expiration ascending (~oldest first~)
    tokens = []
    for t in queryset:
        token_scope_names = [s.name for s in t.scopes.all()]
        if util.list_subset(scopes, token_scope_names):
            tokens.append(t)

    if validate:
        tokens = prune_invalid(tokens)
    return tokens


def _get_first_valid_token(uid, scopes, provider):
    '''
    Returns the first token in the iterable which is still valid.
    More performant than _get_tokens with validate=True because it only
    prunes as needed.
    tokens: iterable of token_service.models.Token
    '''
    tokens = _get_tokens(uid, scopes, provider, validate=False)
    for t in tokens:
        ret = prune_invalid([t])
        if len(ret) > 0:
            return t
    return None


def prune_invalid(tokens):
    '''
    tokens: iterable of token_service.models.Token
    provider: str of provider key mapping to config values
    '''
    valid = []
    validators = {}
    cache_timeout = Config['real_time_validate_cache_retention_timeout']
    handler = redirect_handler.RedirectHandler()
    for t in tokens:
        if access_token_validation_cache.get((t.access_token, t.provider), None):
            cache_entry = access_token_validation_cache.get((t.access_token, t.provider))
            if time.time() <= cache_entry['ctime'] + cache_timeout:
                if cache_entry['val']:
                    valid.append(t)
                # within validation cache window for this token
                logging.debug('token validation cached for acces_token %s provider %s', t.access_token, t.provider)
                continue
        if len(t.access_token) and len(t.provider):
            if t.provider in validators:
                validator = validators[t.provider]
            else:
                validator = redirect_handler.get_validator(t.provider)
                validators[t.provider] = validator
            validation_resp = validator.validate(t.access_token, t.provider)
            active = validation_resp.get('active', False)
            # insert to worker cache
            access_token_validation_cache[(t.access_token, t.provider)] = {
                'ctime': time.time(),
                'val': active,
            }
            if active:
                logging.debug('token %s belonging to uid %s was valid', t.access_token, t.user.sub)
                valid.append(t)
            else:
                # try refresh
                try:
                    handler = redirect_handler.get_handler(token=t)
                    t = handler._refresh_token(t)
                    valid.append(t)
                except RuntimeError:
                    logging.debug('token %s belonging to uid %s was revoked', t.access_token, t.user.sub)
                    t.delete()
        else:
            logging.debug('token %s found with no access_token or provider field', t)
    return valid


def _get_first_valid_token_by_nonce(nonce):
    tokens = _get_tokens_by_nonce(nonce, validate=False)
    for t in tokens:
        ret = prune_invalid([t])
        if len(ret) > 0:
            return t
    return None


def _get_tokens_by_nonce(nonce, validate=False):
    logging.debug('querying for tokens nonce: %s', nonce)
    tokens = models.Token.objects.filter(nonce__value=nonce).order_by('expires')  # this nonce is not encrypted
    if validate:
        tokens = prune_invalid(tokens)
    return tokens


def require_valid_api_key_or_user_token(func):
    def wrapper(*args, **kwargs):
        if _valid_api_key(*args):
            return func(*args, **kwargs)
        t = _valid_user_token(*args)
        if t:
            kwargs['token'] = t
            return func(*args, **kwargs)
        return _http_response(HttpResponseForbidden, 'invalid authorization')
    return wrapper

# def require_valid_user_token(func):
#     def wrapper(*args, **kwargs):
#         if not _valid_user_token(*args):
#             return _http_response(HttpResponseForbidden, 'token was not valid')
#         return func(*args, **kwargs)
#     return wrapper


def require_valid_api_key(func):
    def wrapper(*args, **kwargs):
        if not _valid_api_key(*args):
            return _http_response(HttpResponseForbidden, 'must provide valid api key')
        return func(*args, **kwargs)
    return wrapper


def _valid_user_token(request):
    authorization = request.META.get('HTTP_AUTHORIZATION')
    if not authorization:
        logging.debug('No HTTP_AUTHORIZATION')
        return False
    m = re.match(r'^Bearer\W+(\w+)', authorization)
    if m:
        received_token = m.group(1)
        token_hash = util.sha256(received_token)

        tokens = models.Token.objects.filter(access_token_hash=token_hash)
        tokens = prune_invalid(tokens)
        if len(tokens) > 0:
            return tokens[0]
    else:
        logging.debug('malformed Authorization Bearer header: %s', authorization)
    return False


def _valid_api_key(request):
    authorization = request.META.get('HTTP_AUTHORIZATION')
    if not authorization:
        logging.debug('No HTTP_AUTHORIZATION')
        return False
    m = re.match(r'^Basic\W+(\w+)', authorization)
    if m:
        received_key = m.group(1)
        received_hash = util.sha256(received_key)
        util.logging_sensitive('_valid_api_key received key: ' + str(received_key))
        util.logging_sensitive('_valid_api_key received hash: ' + str(received_hash))
        # keys are unencrypted hashes
        keys = models.API_key.objects.filter(key_hash=received_hash)
        # for debugging purposes only, checking for multiple entries with same key hash
        if keys.count() > 1:
            logging.warn('found multiple matching key entries (will use first one)')
            for db_key in keys:
                logging.debug('found hash: %s owner: %s', db_key.key_hash, db_key.owner)
        if keys.count() > 0:
            logging.debug('_valid_api_key authenticated key for owner [%s] with hash [%s]',
                          keys[0].owner, received_hash)
            return True
        if keys.count() == 0:
            logging.debug('_valid_api_key received invalid api key: %s', received_key)
    else:
        logging.error('malformed Authorization Basic header: ', authorization)

    return False


@require_http_methods(['GET'])
def url(request):
    '''
    No authentication required, will just return a login url
    '''
    scope = request.GET.get('scope')
    provider = request.GET.get('provider')
    return_to = request.GET.get('return_to')
    if not scope:
        logging.debug('missing scope: %s', scope)
        return _http_response(HttpResponseBadRequest, 'missing scope')
    else:
        scopes = scope.split(' ')
        if len(scopes) == 0:
            return _http_response(HttpResponseBadRequest, 'no scopes provided')

    if not provider:
        return _http_response(HttpResponseBadRequest, 'missing provider')

    handler = redirect_handler.get_handler(request)
    if _valid_api_key(request) and return_to:
        url, nonce = handler.add(None, scopes, provider, return_to)
    else:
        if return_to:
            logging.debug('invalid api key, ignoring return_to param')
        url, nonce = handler.add(None, scopes, provider)
    return JsonResponse(status=200, data={'authorization_url': url, 'nonce': nonce})


@require_http_methods(['GET'])
def subject_by_nonce(request):
    nonce = request.GET.get('nonce')
    validate = request.GET.get('validate', str(Config['real_time_validate_default'])).lower() == 'true'

    tokens = _get_tokens_by_nonce(nonce, validate=validate)
    if len(tokens) == 0:
        return _http_response(HttpResponseNotFound, 'no token which meets required criteria')
    token = tokens[0]
    if now() >= token.expires:
        handler = redirect_handler.get_handler(token=token)
        token = handler._refresh_token(token)
    return JsonResponse(status=200, data={'uid': token.user.sub})


@require_http_methods(['GET'])
def token(request):
    nonce = request.GET.get('nonce')
    # api key authentication when no nonce provided
    if not nonce and not _valid_api_key(request):
        return _http_response(HttpResponseForbidden, 'must provide valid api key')

    uid = request.GET.get('uid')
    scope = request.GET.get('scope')
    provider = request.GET.get('provider')
    return_to = request.GET.get('return_to')
    handler = redirect_handler.get_handler()
    # validate
    # nonce takes precedence over (scope,provider,uid) combination
    if not nonce:
        if not scope:
            logging.debug('missing scope: %s', scope)
            return _http_response(HttpResponseBadRequest, 'missing scope')
        else:
            scopes = scope.split(' ')
            if len(scopes) == 0:
                return _http_response(HttpResponseBadRequest, 'no scopes provided')

        if not provider:
            return _http_response(HttpResponseBadRequest, 'missing provider')

        if not uid:
            logging.debug('request received with no uid specified, will only generate url')
            handler = redirect_handler.RedirectHandler()
            url, nonce = handler.add(uid, scopes, provider, return_to)
            return JsonResponse(status=401, data={'authorization_url': url, 'nonce': nonce})

    if nonce:
        token = _get_first_valid_token_by_nonce(nonce)
        if not token:
            return _http_response(HttpResponseNotFound, 'no token which meets required criteria')
    else:
        token = _get_first_valid_token(uid, scopes, provider)
        # only allow automatic flow start if queried by (uid,provider,scope), not nonce.
        if not token:
            url, nonce = handler.add(uid, scopes, provider, return_to)
            return JsonResponse(status=401, data={'authorization_url': url, 'nonce': nonce})

    #    token = prune_duplicate_tokens(tokens)

    if token.expires <= now():
        try:
            handler = redirect_handler.get_handler(token=token)
            token = handler._refresh_token(token)
        except RuntimeError as e:
            return JsonResponse(status=410, data={'msg': 'Token has expired'})

    # if return_to:
    #     return _http_response(HttpResponseRedirect, util.build_redirect_url(return_to, token))
    # else:
    return JsonResponse(status=200, data={
        'access_token': token.access_token,
        'uid': token.user.sub,
        'user_name': token.user.user_name
    })


# TODO
def prune_duplicate_tokens(tokens):
    if tokens:
        return tokens[0]
    else:
        return None


def authcallback(request):
    # check state against active list
    # get provider corresponding to the state
    # exchange code for token response via that provider's token endpoint
    handler = redirect_handler.get_handler(request)
    red_resp = handler.accept(request)

    # handler.accept returns a Django response or throws an exception
    return red_resp


@require_valid_api_key
def validate_token(request):
    if not _valid_api_key(request):
        return _http_response(HttpResponseForbidden, 'must provide valid api key')
    provider = request.GET.get('provider')
    access_token = request.GET.get('access_token')
    token_validator = redirect_handler.get_validator(provider)

    validate_response = token_validator.validate(access_token, provider)
    logging.debug('validate_response: %s', validate_response)
    return JsonResponse(status=200, data=validate_response)


####
# USER API KEY FUNCTIONALITY
####
#    path('apikey/<str:uid>/', views.list_user_keys),
#    path('apikey/<str:uid>/new', views.new_user_key),
#    path('apikey/<str:uid>/<str:key_id>', views.action_user_key),
#    path('apikey/verify', views.verify_user_key),

def _user_from_args(uid, kwargs):
    if kwargs.get('token', None):
        user = kwargs['token'].user
        logging.debug('got user (sub %s) from bearer token', user.sub)
        if str(user.sub) != str(uid):
            return None, _http_response(HttpResponseForbidden, 'Not authorized to create keys for this uid')
    else:
        try:
            user = models.User.objects.get(sub=uid)
            logging.debug('got user from uid %s', uid)
        except ObjectDoesNotExist:
            return None, _http_response(HttpResponseBadRequest, 'User does not exist')

    return user, None


@require_http_methods(['GET'])
@require_valid_api_key_or_user_token
def list_user_keys(request, uid, **kwargs):
    '''
    id = models.CharField(max_length=256)
    key_hash = models.CharField(max_length=256)
    label = models.CharField(max_length=256)
    creation_time = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey('User', on_delete=models.CASCADE)
    '''
    user, resp = _user_from_args(uid, kwargs)
    if resp:
        return resp

    # get keys for this uid
    ret_list = []
    keys = models.User_key.objects.filter(user__sub=uid)
    if len(keys) == 0:
        return JsonResponse(status=404, data={'message': 'No keys found for this user'})
    # non-paginated
    for k in keys:
        ret_list.append({
            "id": k.id,
            "creation_time": k.creation_time,
            "hash": k.key_hash,
            "label": k.label})
    return JsonResponse(status=200, data={'keys': ret_list})


@require_http_methods(['GET'])
@require_valid_api_key_or_user_token
def new_user_key(request, uid, **kwargs):
    user, resp = _user_from_args(uid, kwargs)
    if resp:
        return resp

    key_label = request.GET.get('label')
    key_val = util.generate_base64(64)
    key_val = util.sanitize_base64(key_val)
    key_hash = util.sha256(key_val)
    logging.debug('key_hash: %s', key_hash)
    key_id = util.generate_nonce(32)
    # ensure unique
    while len(models.User_key.objects.filter(id=key_id)) > 0:
        key_id = util.generate_nonce(32)

    models.User_key.objects.create(
        id=key_id,
        key_hash=key_hash,
        label=key_label,  # null if not provided in param
        user=user)
    return JsonResponse(status=200, data={'key': key_val})


@csrf_exempt
@require_http_methods(['GET', 'DELETE'])
@require_valid_api_key_or_user_token
def action_user_key(request, uid, key_id, **kwargs):
    user, resp = _user_from_args(uid, kwargs)
    if resp:
        return resp

    # do operation
    if request.method == 'GET':
        key = get_object_or_404(models.User_key, user__sub=uid, id=key_id)
        return JsonResponse(status=200, data={
            "id": key.id,
            "creation_time": key.creation_time,
            "hash": key.key_hash,
            "label": key.label})
    elif request.method == 'DELETE':
        try:
            key = models.User_key.objects.get(user__sub=uid, id=key_id)
            key.delete()
        except ObjectDoesNotExist:
            logging.debug('key did not exist, nothing to do')
        return JsonResponse(status=200, data={'message': 'Successfully deleted'})


@require_http_methods(['GET'])
@require_valid_api_key  # for this user key endpoint, only allow applications, not users
def verify_user_key(request, **kwargs):
    key_param = request.GET.get('key')
    if not key_param:
        return _http_response(HttpResponseBadRequest, 'Missing required key param')
    uid_param = request.GET.get('uid')
    user_param = request.GET.get('username')
    #    if not uid_param and not user_param:
    #        return _http_response(HttpResponseBadRequest, 'Missing required param, one of [uid, username]')
    # look up user
    # ret same err for all user lookup failures
    invalid_user = JsonResponse(status=400, data={'message': 'User not found which matches criteria'})
    user1 = user2 = None
    try:
        if uid_param:
            user1 = models.User.objects.get(sub=uid_param)
        if user_param:
            user2 = models.User.objects.get(user_name=user_param)
        if user1 and user2:
            if user1.sub != user2.sub:  # disallow mismatched uid and user_name
                return invalid_user
        user = user1 if user1 else user2
    except ObjectDoesNotExist as e:
        logging.debug("invalid user exception %s", repr(e))
        return invalid_user
    if user:
        logging.debug('verifying key for user: ' + user.user_name)
    # now lookup key
    try:
        key_hash = util.sha256(key_param)
        if user:  # user was specified so check it
            key = models.User_key.objects.get(user=user, key_hash=key_hash)
            return JsonResponse(status=200, data={'valid': True})
        else:  # don't check user
            key = models.User_key.objects.get(key_hash=key_hash)
            return JsonResponse(status=200, data={'valid': True, 'uid': key.user.sub, 'user_name': key.user.user_name})
    except ObjectDoesNotExist as e:
        return JsonResponse(status=401, data={'valid': False})


def index(request):
    handler = redirect_handler.Auth0RedirectHandler()
    scopes = ['openid', 'profile', 'email']
    provider = Config['root_default_provider']
    return_to = Config['root_return_to']
    url, nonce = handler.add(None, scopes, provider, return_to)
    logging.debug("index url %s", url)
    return HttpResponseRedirect(url)
