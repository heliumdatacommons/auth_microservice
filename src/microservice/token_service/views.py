import re
from django.http import (
        HttpResponseBadRequest,
        JsonResponse,
        HttpResponseNotFound,
        HttpResponseForbidden,
        HttpResponseRedirect)
from django.views.decorators.http import require_http_methods
from django.utils.timezone import now

from . import models
from . import redirect_handler
from . import config
from . import util

@require_http_methods(['GET'])
def create_key(request):
    authorization = request.META.get('HTTP_AUTHORIZATION')
    print('create_key authorization: ' + authorization)
    m = re.match(r'^Basic (\w{64})', authorization)
    if m:
        received_key = m.group(1)
        if received_key != config.admin_key:
            HttpResponseForbidden('must provide admin credentials')
    else:
        return HttpResponseForbidden('must provide credentials')
    
    owner = request.GET.get('owner')
    if not owner:
        return HttpResponseBadRequest('must provider owner string')
    key = util.generate_nonce(64)
    key_hash = util.sha256(key)
    print('new key: {}, hash: {}'.format(key, key_hash))
    db_entry = models.API_key(key_hash=key_hash, owner=owner)
    db_entry.save()
    return JsonResponse(status=200, data={'key': key})


def isint(s):
    try:
        i = int(s)
        return True
    except ValueError:
        return False


def _get_tokens(uid, scopes, provider):
    print('querying for tokens(uid,scopes,provider): ({},{},{})'.format(uid,scopes,provider))
    # Django can do a filter using a subset operation for linked many-to-many, but not a filter using superset
    # we need to find tokens whose scopes are a superset of the scopes list being requested
    queryset = models.Token.objects.filter(
        user__id=uid,
        #scopes__in=models.Scope.objects.filter(name__in=scopes),
        provider=provider
    )
    tokens = []
    for t in queryset:
        token_scope_names = [s.name for s in t.scopes.all()]
        if util.list_subset(scopes, token_scope_names):
            tokens.append(t)
    return tokens

def _get_tokens_by_nonce(nonce):
    print('querying for tokens(nonce): ({})'.format(nonce))
    return models.Token.objects.filter(nonce__value=nonce) # this nonce is not encrypted

def _valid_api_key(request):
    authorization = request.META.get('HTTP_AUTHORIZATION')
    if not authorization:
        print('NO HTTP_AUTHORIZATION')
        return False
    m = re.match(r'^Basic\W+(\w{64})', authorization)
    if m:
        received_key = m.group(1)
        received_hash = util.sha256(received_key)
        #print('_valid_api_key received_hash: ' + received_hash)
        # keys are unencrypted hashes
        keys = models.API_key.objects.filter(key_hash=received_hash)
        # for debugging purposes only, checking for multiple entries with same key hash
        if keys.count() > 1:
            print('FOUND MULTIPLE MATCHING KEY ENTRIES')
            for db_key in keys:
                print('found hash: ' + db_key.key_hash + ' owner: ' + db_key.owner)
        if keys.count() > 0:
            print('_valid_api_key authenticated key [{}] for owner [{}]'.format(received_key, keys[0].owner))
            return True
        if keys.count() == 0:
            print('_valid_api_key received invalid api key: ' + received_key)
    else:
        print('malformed Authorization Basic header: ' + str(authorization))
    return False

'''
No authentication required, will just return a login url
'''
@require_http_methods(['GET'])
def url(request):
    scope = request.GET.get('scope')
    provider = request.GET.get('provider')
    return_to = request.GET.get('return_to')
    if not scope:
        print('scope: ' + str(scope))
        return HttpResponseBadRequest('missing scope')
    else:
        scopes = scope.split(' ')
        if len(scopes) == 0:
            return HttpResponseBadRequest('no scopes provided')
    
    if not provider:
        return HttpResponseBadRequest('missing provider')

    handler = redirect_handler.RedirectHandler()
    if _valid_api_key(request) and return_to:
        url, nonce = handler.add(None, scopes, provider, return_to)
    else:
        if return_to: print('invalid api key, ignoring return_to param')
        url, nonce = handler.add(None, scopes, provider)
    return JsonResponse(status=200, data={'authorization_url': url, 'nonce': nonce})


@require_http_methods(['GET'])
def subject_by_nonce(request):
    nonce = request.GET.get('nonce')

    handler = redirect_handler.RedirectHandler()
    tokens = _get_tokens_by_nonce(nonce)
    if len(tokens) == 0:
        return HttpResponseNotFound('no token which meets required criteria')
    token = tokens[0]
    if now() >= token.expires:
        token = handler._refresh_token(token)
    return JsonResponse(status=200, data={'uid':token.user.id})

@require_http_methods(['GET'])
def token(request):
    # api key authentication
    if not _valid_api_key(request):
        return HttpResponseForbidden('must provide valid api key')

    uid = request.GET.get('uid')
    scope = request.GET.get('scope')
    provider = request.GET.get('provider')
    nonce = request.GET.get('nonce')
    return_to = request.GET.get('return_to')

    handler = redirect_handler.RedirectHandler()
    # validate
    # nonce takes precedence over (scope,provider,uid) combination
    if not nonce:
        if not scope:
            print('scope: ' + str(scope))
            return HttpResponseBadRequest('missing scope')
        else:
            scopes = scope.split(' ')
            if len(scopes) == 0:
                return HttpResponseBadRequest('no scopes provided')
    
        if not provider:
            return HttpResponseBadRequest('missing provider')
    
        if not uid:
            print('request received with no uid specified, will only generate url')
            handler = redirect_handler.RedirectHandler()
            url,nonce = handler.add(uid, scopes, provider, return_to)
            return JsonResponse(status=401, data={'authorization_url': url, 'nonce': nonce})

    if nonce:
        tokens = _get_tokens_by_nonce(nonce)
        if len(tokens) == 0:
            return HttpResponseNotFound('no token which meets required criteria')
    else:
        tokens = _get_tokens(uid, scopes, provider)
        # only allow automatic flow start if queried by (uid,provider,scope), not nonce.
        if len(tokens) == 0:
            url,nonce = handler.add(uid, scopes, provider, return_to)
            return JsonResponse(status=401, data={'authorization_url': url, 'nonce': nonce})

    token = prune_duplicate_tokens(tokens)
    
    if token.expires <= now():
        token = handler._refresh_token(token)

    #if return_to:
    #    return HttpResponseRedirect(util.build_redirect_url(return_to, token))
    #else:
    return JsonResponse(status=200, data={'access_token': token.access_token, 'uid':token.user.id})

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
    handler = redirect_handler.RedirectHandler()
    red_resp = handler.accept(request)
    
    # handler.accept returns a Django response or throws an exception
    return red_resp

def validate_token(request):
    if not _valid_api_key(request):
        return HttpResponseForbidden('must provide valid api key')
    provider = request.GET.get('provider')
    access_token = request.GET.get('access_token')
    validation_url = request.GET.get('validation_url') # None if not present
    
    if provider == 'google':
        token_validator = redirect_handler.GoogleValidator()
    else:
        token_validator = redirect_handler.Validator()
    
    isvalid = token_validator.validate(access_token, provider)

    return JsonResponse(status=200, data= {'active': isvalid})

