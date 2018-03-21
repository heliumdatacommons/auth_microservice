from django.http import HttpResponseNotAllowed
from django.views.decorators.http import require_http_methods
from . import models

def isint(s):
    try:
        i = int(s)
        return True
    except ValueError:
        return False

@require_http_methods(['GET'])
def token(request):
    # api key authentication
    uid = request.GET.get('uid')
    scope = request.GET.get('scope')
    provider = request.GET.get('provider')
    block = request.GET.get('block')
    
    # validate
    if block:
        if isint(block):
            block = int(block)
        elif block.lower() == 'false':
            block = False
        else:
            return HttpResponseBadRequest('if block param included, must be false or an integer')
    
    if not uid:
        return HttpResponseBadRequest('missing uid')

    if scope:
        scope = scope.split(',')
    else:
        return HttpResponseBadRequest('missing scope')

    if not provider:
        return HttpResponseBadRequest('missing scope')

    return HttpResponseServerError('unimplemented') 



def authcallback(request):
    authorization_code = request.GET.get('code')
    state = request.GET.get('state')
    # check state against active list
    # get provider corresponding to the state
    # exchange code for token response via that provider's token endpoint
