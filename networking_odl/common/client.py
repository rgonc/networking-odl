# Copyright (c) 2014 Red Hat Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_log import log as logging
from oslo_serialization import jsonutils
import requests

from networking_odl.openstack.common._i18n import _LE
from networking_odl.openstack.common._i18n import _LI


LOG = logging.getLogger(__name__)


class OpenDaylightRestClient(object):

    def __init__(self, url, username, password, timeout):
        self.url = url
        self.timeout = timeout
        self.auth = (username, password)

    def sendjson(self, method, urlpath, obj):
        """Send json to the OpenDaylight controller."""

        headers = {'Content-Type': 'application/json'}
        data = jsonutils.dumps(obj, indent=2) if obj else None
        url = '/'.join([self.url, urlpath])
        LOG.debug("Sending METHOD (%(method)s) URL (%(url)s) JSON (%(obj)s)",
                  {'method': method, 'url': url, 'obj': obj})
        r = requests.request(method, url=url,
                             headers=headers, data=data,
                             auth=self.auth, timeout=self.timeout)
        r.raise_for_status()
        new_obj = None
        try:
            new_obj = r.json()
        except Exception:
            LOG.debug("requests result is not json")
        LOG.debug("%(result)s", {'result': new_obj})
        return new_obj

    def try_delete(self, urlpath):
        try:
            self.sendjson('delete', urlpath, None)
        except requests.HTTPError as e:
            # The resource is already removed. ignore 404 gracefully
            if e.response.status_code != 404:
                raise
            LOG.debug("%(urlpath)s doesn't exist", {'urlpath': urlpath})
            return False
        return True
