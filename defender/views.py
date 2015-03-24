from django.shortcuts import render_to_response
from django.template import RequestContext
from django.http import HttpResponseRedirect,HttpResponse
from django.core.urlresolvers import reverse
from django.contrib.admin.views.decorators import staff_member_required
import json

from .utils import (
    get_blocked_ips, get_blocked_usernames, unblock_ip, unblock_username)


@staff_member_required
def block_view(request):
    """ List the blocked IP and Usernames """
    blocked_ip_list = get_blocked_ips()
    blocked_username_list = get_blocked_usernames()

    context = {'blocked_ip_list': blocked_ip_list,
               'blocked_username_list': blocked_username_list}
    return render_to_response(
        'defender/admin/blocks.html',
        context, context_instance=RequestContext(request))


@staff_member_required
def unblock_ip_view(request, ip):
    """ upblock the given ip """
    if request.method == 'POST':
        unblock_ip(ip)
    return HttpResponseRedirect(reverse("defender_blocks_view"))


@staff_member_required
def unblock_username_view(request, username):
    """ unblockt he given username """
    if request.method == 'POST':
        unblock_username(username)
        return HttpResponse(json.dumps({"status": "unlocked"}), content_type='application/json')
    else:
        return HttpResponse(json.dumps({"status": "wrong request method"}), content_type='application/json')
