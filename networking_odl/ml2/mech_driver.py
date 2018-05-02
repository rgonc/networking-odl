# Copyright (c) 2013-2014 OpenStack Foundation
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

import abc
import six

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
import requests

from neutron.common import exceptions as n_exc
from neutron.common import utils
from neutron import context
from neutron.db import api as db_api
from neutron.extensions import securitygroup as sg
from neutron.extensions import providernet as provider
from neutron.plugins.common import utils as plugin_utils
from neutron.plugins.ml2 import driver_context
from neutron.plugins.ml2 import db
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.drivers import type_vlan
from neutron.plugins.ml2.drivers import type_vxlan

from networking_odl.common import callback as odl_call
from networking_odl.common import client as odl_client
from networking_odl.common import constants as odl_const
from networking_odl.common import utils as odl_utils
from networking_odl.openstack.common._i18n import _LE
from networking_odl.openstack.common._i18n import _LI

LOG = logging.getLogger(__name__)

not_found_exception_map = {odl_const.ODL_NETWORKS: n_exc.NetworkNotFound,
                           odl_const.ODL_SUBNETS: n_exc.SubnetNotFound,
                           odl_const.ODL_PORTS: n_exc.PortNotFound,
                           odl_const.ODL_SGS: sg.SecurityGroupNotFound,
                           odl_const.ODL_SG_RULES:
                               sg.SecurityGroupRuleNotFound}


@six.add_metaclass(abc.ABCMeta)
class ResourceFilterBase(object):
    @staticmethod
    @abc.abstractmethod
    def filter_create_attributes(resource, context):
        pass

    @staticmethod
    @abc.abstractmethod
    def filter_update_attributes(resource, context):
        pass

    @staticmethod
    @abc.abstractmethod
    def filter_create_attributes_with_plugin(resource, plugin, dbcontext):
        pass


class NetworkFilter(ResourceFilterBase):
    @staticmethod
    def filter_create_attributes(network, context):
        """Filter out network attributes not required for a create."""
        odl_utils.try_del(network, ['status', 'subnets'])

    @staticmethod
    def filter_update_attributes(network, context):
        """Filter out network attributes for an update operation."""
        odl_utils.try_del(network, ['id', 'status', 'subnets', 'tenant_id'])

    @classmethod
    def filter_create_attributes_with_plugin(cls, network, plugin, dbcontext):
        context = driver_context.NetworkContext(plugin, dbcontext, network)
        cls.filter_create_attributes(network, context)


class SubnetFilter(ResourceFilterBase):
    @staticmethod
    def filter_create_attributes(subnet, context):
        """Filter out subnet attributes not required for a create."""
        pass

    @staticmethod
    def filter_update_attributes(subnet, context):
        """Filter out subnet attributes for an update operation."""
        odl_utils.try_del(subnet, ['id', 'network_id', 'ip_version', 'cidr',
                          'allocation_pools', 'tenant_id'])

    @classmethod
    def filter_create_attributes_with_plugin(cls, subnet, plugin, dbcontext):
        context = driver_context.SubnetContext(subnet, plugin, dbcontext)
        cls.filter_create_attributes(subnet, context)


class PortFilter(ResourceFilterBase):
    @staticmethod
    def _add_security_groups(port, context):
        """Populate the 'security_groups' field with entire records."""
        dbcontext = context._plugin_context
        groups = [context._plugin.get_security_group(dbcontext, sg)
                  for sg in port['security_groups']]
        port['security_groups'] = groups

    @classmethod
    def filter_create_attributes(cls, port, context):
        """Filter out port attributes not required for a create."""
        cls._add_security_groups(port, context)
        # TODO(kmestery): Converting to uppercase due to ODL bug
        # https://bugs.opendaylight.org/show_bug.cgi?id=477
        port['mac_address'] = port['mac_address'].upper()
        odl_utils.try_del(port, ['status'])

        # NOTE(yamahata): work around for port creation for router
        # tenant_id=''(empty string) is passed when port is created
        # by l3 plugin internally for router.
        # On the other hand, ODL doesn't accept empty string for tenant_id.
        # In that case, deduce tenant_id from network_id for now.
        # Right fix: modify Neutron so that don't allow empty string
        # for tenant_id even for port for internal use.
        # TODO(yamahata): eliminate this work around when neutron side
        # is fixed
        # assert port['tenant_id'] != ''
        if port['tenant_id'] == '':
            LOG.debug('empty string was passed for tenant_id: %s(port)', port)
            port['tenant_id'] = context._network_context._network['tenant_id']

    @classmethod
    def filter_update_attributes(cls, port, context):
        """Filter out port attributes for an update operation."""
        cls._add_security_groups(port, context)
        odl_utils.try_del(port, ['network_id', 'id', 'status', 'mac_address',
                          'tenant_id'])

    @classmethod
    def filter_create_attributes_with_plugin(cls, port, plugin, dbcontext):
        network = plugin.get_network(dbcontext, port['network_id'])
        # TODO(yamahata): port binding
        binding = {}
        context = driver_context.PortContext(
            plugin, dbcontext, port, network, binding, None)
        cls.filter_create_attributes(port, context)


class SecurityGroupFilter(ResourceFilterBase):
    @staticmethod
    def filter_create_attributes(sg, context):
        """Filter out security-group attributes not required for a create."""
        pass

    @staticmethod
    def filter_update_attributes(sg, context):
        """Filter out security-group attributes for an update operation."""
        pass

    @staticmethod
    def filter_create_attributes_with_plugin(sg, plugin, dbcontext):
        pass


class SecurityGroupRuleFilter(ResourceFilterBase):
    @staticmethod
    def filter_create_attributes(sg_rule, context):
        """Filter out sg-rule attributes not required for a create."""
        pass

    @staticmethod
    def filter_update_attributes(sg_rule, context):
        """Filter out sg-rule attributes for an update operation."""
        pass

    @staticmethod
    def filter_create_attributes_with_plugin(sg_rule, plugin, dbcontext):
        pass


class OpenDaylightDriver(object):

    """OpenDaylight Python Driver for Neutron.

    This code is the backend implementation for the OpenDaylight ML2
    MechanismDriver for OpenStack Neutron.
    """
    FILTER_MAP = {
        odl_const.ODL_NETWORKS: NetworkFilter,
        odl_const.ODL_SUBNETS: SubnetFilter,
        odl_const.ODL_PORTS: PortFilter,
        odl_const.ODL_SGS: SecurityGroupFilter,
        odl_const.ODL_SG_RULES: SecurityGroupRuleFilter,
    }
    out_of_sync = True

    def __init__(self):
        LOG.debug("Initializing OpenDaylight ML2 driver")
        self.client = odl_client.OpenDaylightRestClient(
            cfg.CONF.ml2_odl.url,
            cfg.CONF.ml2_odl.username,
            cfg.CONF.ml2_odl.password,
            cfg.CONF.ml2_odl.timeout
        )
        self.sec_handler = odl_call.OdlSecurityGroupsHandler(self)

        #add by hqf: get provider network
        self.network_vlan_ranges = plugin_utils.parse_network_vlan_ranges(
                cfg.CONF.ml2_type_vlan.network_vlan_ranges)
        self.physical_network = self.get_physical_network()

    def synchronize(self, operation, object_type, context):
        """Synchronize ODL with Neutron following a configuration change."""
        LOG.debug("synchronize 1 out_of_sync is %(out_of_sync)s",
            {'out_of_sync': self.out_of_sync})
        if self.out_of_sync:
            self.sync_full(context._plugin)
            LOG.info("afred sync_full")            
            if operation in [odl_const.ODL_UPDATE, odl_const.ODL_DELETE]:                
                # NOTE: work around that sync_full doesn't know                
                # how to handle UPDATE and DELETE at the moment.                
                # TODO: implement TODOs in sync_full and remove this                
                # work around                
                self.sync_single_resource(operation, object_type, context)                
                LOG.info("afred sync_full Delete or Update")
        else:
            self.sync_single_resource(operation, object_type, context)
        LOG.debug("synchronize 2 out_of_sync is %(out_of_sync)s",
            {'out_of_sync': self.out_of_sync})

    def sync_resources(self, plugin, dbcontext, collection_name):
        """Sync objects from Neutron over to OpenDaylight.

        This will handle syncing networks, subnets, and ports from Neutron to
        OpenDaylight. It also filters out the requisite items which are not
        valid for create API operations.
        """
        filter_cls = self.FILTER_MAP[collection_name]
        to_be_synced = []
        obj_getter = getattr(plugin, 'get_%s' % collection_name)
        if collection_name == odl_const.ODL_SGS:
            resources = obj_getter(dbcontext, default_sg=True)
        else:
            resources = obj_getter(dbcontext)
        for resource in resources:
            try:
                # Convert underscores to dashes in the URL for ODL
                collection_name_url = collection_name.replace('_', '-')
                urlpath = collection_name_url + '/' + resource['id']
                self.client.sendjson('get', urlpath, None)
            except requests.exceptions.HTTPError as e:
                with excutils.save_and_reraise_exception() as ctx:
                    if e.response.status_code == requests.codes.not_found:
                        filter_cls.filter_create_attributes_with_plugin(
                            resource, plugin, dbcontext)
                        to_be_synced.append(resource)
                        ctx.reraise = False
            else:
                # TODO(yamahata): compare result with resource.
                # If they don't match, update it below
                pass

        key = collection_name[:-1] if len(to_be_synced) == 1 else (
            collection_name)
        # Convert underscores to dashes in the URL for ODL
        collection_name_url = collection_name.replace('_', '-')
        new_objs_obj = self.client.sendjson('post', collection_name_url, {key: to_be_synced})
        
        # add by hqf
        if collection_name == odl_const.ODL_NETWORKS:
            new_objs = new_objs_obj.get(key)
            if key == collection_name:
                for new_obj in new_objs:
                    LOG.info(_LI("new_obj %(new_obj)s"),
                        {'new_obj': new_obj})
                    self.update_network_segments(new_obj)
            else:
                self.update_network_segments(new_objs)
        # add by hqf end
        
        # https://bugs.launchpad.net/networking-odl/+bug/1371115
        # TODO(yamahata): update resources with unsyned attributes
        # TODO(yamahata): find dangling ODL resouce that was deleted in
        # neutron db

    @utils.synchronized('odl-sync-full')
    def sync_full(self, plugin):
        """Resync the entire database to ODL.

        Transition to the in-sync state on success.
        Note: we only allow a single thread in here at a time.
        """
        LOG.debug("sync_full 1 out_of_sync is %(out_of_sync)s",
            {'out_of_sync': self.out_of_sync})
        if not self.out_of_sync:
            return
        dbcontext = context.get_admin_context()
        for collection_name in [odl_const.ODL_NETWORKS,
                                odl_const.ODL_SUBNETS,
                                odl_const.ODL_PORTS,
                                odl_const.ODL_SGS,
                                odl_const.ODL_SG_RULES]:
            self.sync_resources(plugin, dbcontext, collection_name)
        self.out_of_sync = False
        LOG.debug("sync_full 2 out_of_sync is %(out_of_sync)s",
            {'out_of_sync': self.out_of_sync})

    def update_network_segments(self, new_obj):
        obj_id = new_obj.get('id')
        LOG.debug("update network segments for %(obj_id)s",
                {'obj_id': obj_id})
        try:
            new_segments = new_obj.get('segments')
            if new_segments == None:
                return
            LOG.debug("new_segments %(new_segments)s",
                {'new_segments': new_segments})
            session = db_api.get_session()
            with session.begin(subtransactions=True):
                segments=db.get_network_segments(session, obj_id)
                LOG.debug("update network segments when old segments %(segments)s",
                    {'segments': segments})
                phy_network = self.physical_network
                for segment in segments:
                    db.delete_network_segment(session, segment.get(api.ID))
                for new_segment in new_segments:
                    network_type = new_segment.get(provider.NETWORK_TYPE)
                    model = None
                    filters = {}
                    segmentation_id = new_segment.get(provider.SEGMENTATION_ID)
                    new_segment_db = {api.NETWORK_TYPE: network_type,
                                      api.PHYSICAL_NETWORK: new_segment.get(provider.PHYSICAL_NETWORK),
                                      api.SEGMENTATION_ID: segmentation_id}
                    if new_segment.get(provider.NETWORK_TYPE) == 'vlan':
                        segment_index = 0                        
                        new_segment_db = {api.NETWORK_TYPE: network_type,
                                      api.PHYSICAL_NETWORK: phy_network,
                                      api.SEGMENTATION_ID: segmentation_id}
                        model = type_vlan.VlanAllocation
                        filters['physical_network'] = phy_network
                        filters['vlan_id'] = segmentation_id
                    else:
                        segment_index = 1
                        model = type_vxlan.VxlanAllocation
                        filters['vxlan_vni'] = segmentation_id
                    LOG.debug("update network segments when new segment %(new_segment)s",
                        {'new_segment': new_segment_db})
                    self.allocate_fully_specified_segment(session, network_type, model, **filters)
                    db.add_network_segment(session, obj_id, new_segment_db, segment_index)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("update network segments error on "
                              "%(object_id)s"),
                          {'object_id': obj_id})

    def get_physical_network(self):
        if self.network_vlan_ranges == None:
            return
        for physical_network in self.network_vlan_ranges:
            LOG.info(_LI("physical network is %(physical_network)s"),
                        {'physical_network': physical_network})
            return physical_network
            
    def allocate_fully_specified_segment(self, session, network_type, model, **raw_segment):
        """Allocate segment fully specified by raw_segment.

        If segment exists, then try to allocate it and return db object
        If segment does not exists, then try to create it and return db object
        If allocation/creation failed, then return None
        """

        try:
            with session.begin(subtransactions=True):
                alloc = (session.query(model).filter_by(**raw_segment).
                         first())
                if alloc:
                    if alloc.allocated:
                        # Segment already allocated
                        return
                    else:
                        # Segment not allocated
                        LOG.debug("%(type)s segment %(segment)s allocate "
                                  "started ",
                                  {"type": network_type,
                                   "segment": raw_segment})
                        count = (session.query(model).
                                 filter_by(allocated=False, **raw_segment).
                                 update({"allocated": True}))
                        if count:
                            LOG.debug("%(type)s segment %(segment)s allocate "
                                      "done ",
                                  {"type": network_type,
                                   "segment": raw_segment})
                            return alloc

                        # Segment allocated or deleted since select
                        LOG.debug("%(type)s segment %(segment)s allocate "
                                  "failed: segment has been allocated or "
                                  "deleted",
                                  {"type": network_type,
                                   "segment": raw_segment})

                # Segment to create or already allocated
                LOG.debug("%(type)s segment %(segment)s create started",
                          {"type": network_type, "segment": raw_segment})
                alloc = model(allocated=True, **raw_segment)
                alloc.save(session)
                LOG.debug("%(type)s segment %(segment)s create done",
                          {"type": network_type, "segment": raw_segment})

        except db_exc.DBDuplicateEntry:
            # Segment already allocated (insert failure)
            alloc = None
            LOG.debug("%(type)s segment %(segment)s create failed",
                      {"type": network_type, "segment": raw_segment})

        return alloc

    def sync_single_resource(self, operation, object_type, context):
        """Sync over a single resource from Neutron to OpenDaylight.

        Handle syncing a single operation over to OpenDaylight, and correctly
        filter attributes out which are not required for the requisite
        operation (create or update) being handled.
        """
        # Convert underscores to dashes in the URL for ODL
        object_type_url = object_type.replace('_', '-')
        try:
            obj_id = context.current['id']
            if operation == odl_const.ODL_DELETE:
                self.out_of_sync |= not self.client.try_delete(
                    object_type_url + '/' + obj_id)
                LOG.debug("sync_single_resource 1 out_of_sync is %(out_of_sync)s",
                   {'out_of_sync': self.out_of_sync})
            else:
                filter_cls = self.FILTER_MAP[object_type]
                if operation == odl_const.ODL_CREATE:
                    urlpath = object_type_url
                    method = 'post'
                    attr_filter = filter_cls.filter_create_attributes
                elif operation == odl_const.ODL_UPDATE:
                    urlpath = object_type_url + '/' + obj_id
                    method = 'put'
                    attr_filter = filter_cls.filter_update_attributes
                resource = context.current.copy()
                attr_filter(resource, context)
                new_obj_obj = self.client.sendjson(method, urlpath,
                                     {object_type_url[:-1]: resource})
                
                # byhqf
                if operation == odl_const.ODL_CREATE:
                    if object_type == odl_const.ODL_NETWORKS:
                        self.update_network_segments(new_obj_obj.get('network'))
                # byhqf end
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to perform %(operation)s on "
                              "%(object_type)s %(object_id)s"),
                          {'operation': operation,
                           'object_type': object_type,
                           'object_id': obj_id})
                self.out_of_sync = True
                LOG.debug("sync_single_resource 2 out_of_sync is %(out_of_sync)s",
                   {'out_of_sync': self.out_of_sync})

    def sync_from_callback(self, operation, object_type, res_id,
                           resource_dict):
        try:
            if operation == odl_const.ODL_DELETE:
                self.out_of_sync |= not self.client.try_delete(
                    object_type + '/' + res_id)
                LOG.debug("sync_from_callback 1 out_of_sync is %(out_of_sync)s",
                   {'out_of_sync': self.out_of_sync})
            else:
                if operation == odl_const.ODL_CREATE:
                    urlpath = object_type
                    method = 'post'
                elif operation == odl_const.ODL_UPDATE:
                    urlpath = object_type + '/' + res_id
                    method = 'put'
                self.client.sendjson(method, urlpath, resource_dict)
        except Exception:
            with excutils.save_and_reraise_exception():
                LOG.error(_LE("Unable to perform %(operation)s on "
                              "%(object_type)s %(res_id)s %(resource_dict)s"),
                          {'operation': operation,
                           'object_type': object_type,
                           'res_id': res_id,
                           'resource_dict': resource_dict})
                self.out_of_sync = True
                LOG.debug("sync_from_callback 2 out_of_sync is %(out_of_sync)s",
                   {'out_of_sync': self.out_of_sync})