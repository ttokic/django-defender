from django.shortcuts import render_to_response
from django.template import RequestContext
from django.http import HttpResponseRedirect,HttpResponse
from django.core.urlresolvers import reverse
from django.utils.functional import lazy
from bcore.apps.administrator.views import AUTH_FAILED_URL
from django.contrib.auth.decorators import login_required, user_passes_test
from bcore.apps.authorization.models import in_supportuser_or_programmanager_group
from bcore.apps.common.utils import create_custom_JSON_error_response
from bcore.apps.audit.hbx_signals import log_user_unlock
from bcore.apps.authorization.models import HBXUser as User
import json

from .utils import (
    get_blocked_ips, get_blocked_usernames, unblock_ip, unblock_username)


# Enable reverse function for url namespace:name in the user_passes_test decorator
# (standard reverse function can NOT be used outside view functions
reverse_lazy = lambda name = None, *args: lazy(reverse, str)(name, args=args)

@login_required
@user_passes_test(in_supportuser_or_programmanager_group, login_url=reverse_lazy(AUTH_FAILED_URL), redirect_field_name='')
def block_view(request):
    """ List the blocked IP and Usernames """
    blocked_ip_list = get_blocked_ips()
    blocked_username_list = get_blocked_usernames()

    context = {'blocked_ip_list': blocked_ip_list,
               'blocked_username_list': blocked_username_list}
    return render_to_response(
        'defender/admin/blocks.html',
        context, context_instance=RequestContext(request))


@login_required
@user_passes_test(in_supportuser_or_programmanager_group, login_url=reverse_lazy(AUTH_FAILED_URL), redirect_field_name='')
def unblock_ip_view(request, ip):
    """ unblock the given ip """
    if request.method == 'POST':
        unblock_ip(ip)
    return HttpResponseRedirect(reverse("defender_blocks_view"))


@login_required
@user_passes_test(in_supportuser_or_programmanager_group, login_url=reverse_lazy(AUTH_FAILED_URL), redirect_field_name='')
def unblock_username_view(request, user_id):
    """ unblock he given username """
    if request.method == 'POST':
        username = User.objects.get(id=user_id).username
        unblock_username(username)
        log_user_unlock.send(sender=unblock_username_view, request=request, username=username)
        return HttpResponse(json.dumps({"status": "unlocked"}), content_type='application/json')
    else:
        return create_custom_JSON_error_response(422, "Wrong request method")
