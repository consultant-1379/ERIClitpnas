##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import os
import sys
import netaddr
import time
from collections import defaultdict
from decimal import Decimal, ROUND_CEILING
import traceback

from litp.core.execution_manager import ConfigTask, CallbackTask, \
                                        CallbackExecutionException,\
                                        PluginError
from litp.core.future_property_value import FuturePropertyValue
from litp.core.litp_logging import LitpLogger
from litp.core.node_utils import wait_for_node, wait_for_node_down, \
                                 wait_for_node_timestamp
from litp.core.plugin import Plugin
from litp.core.rpc_commands import BaseRpcCommandProcessor, \
        RpcExecutionException, PuppetMcoProcessor
from litp.core.validators import ValidationError
from litp.plan_types.create_snapshot import create_snapshot_tags
from litp.plan_types.remove_snapshot import remove_snapshot_tags
from litp.plan_types.restore_snapshot import restore_snapshot_tags
from naslib.connection import NasConnection
from naslib.log import NasLogger
from naslib.nasexceptions import (NasException,
                                  NasConnectionException,
                                  UnableToDiscoverDriver)
from naslib.objects import FileSystem, Share, Cache, Snapshot
from naslib.objects import NasServer  # pylint: disable=E0611,W0611
from naslib.resourceprops import Size
from naslib.ssh import SSHClient
from nas_extension.nas_extension import ips_overlap

from .nas_cmd_api import NasCmdApi, NasCmdApiException

import itertools as it
import inspect
from litp.core.constants import UPGRADE_SNAPSHOT_NAME

log = LitpLogger()

NasLogger.set(log)


def build_nas_callback_task(model_item, description, callback,
                            sfs_service_vpath, *args, **kwargs):
    """ All the arguments are used to generate a normal CallbackTask but this
    function requires the "sfs_service_vpath" attribute. The task will have
    a new attribute "is_nas_callback_task" set to True. So the tasks can be
    easily identified to generate host keys tasks.
    """
    kwargs['sfs_service_vpath'] = sfs_service_vpath
    task = CallbackTask(model_item, description, callback, *args, **kwargs)
    task.is_nas_callback_task = True
    return task


class NasConnectionCallback(NasConnection):
    """ Based on NasConnection Context Manager, this class has some particular
    behavior for callback tasks.
    """

    def __init__(self, callback_api, host, username, password=None, port=22,
            nas_type='veritas'):
        """ At first it decrypts the password through the callback API.
        """
        password = callback_api.get_password(password, username)
        super(NasConnectionCallback, self).__init__(host, username,
                password, port, nas_type=nas_type)
        self.get_decrypted_password = callback_api.get_password

    def __enter__(self):
        """ When entering the "with" statement it raise the properly
        CallbackExecutionException after trying a SSH connection.
        """
        try:
            return super(NasConnectionCallback, self).__enter__()
        except NasConnectionException, err:
            exc = sys.exc_info()
            raise CallbackExecutionException(
                "Error while trying to connect "
                "to NFS server: %s" % str(err)), None, exc[2]
        except UnableToDiscoverDriver, err:
            exc = sys.exc_info()
            raise CallbackExecutionException(err)

    def __exit__(self, *args):
        """ When exiting from the "with" statement it raise the properly
        CallbackExecutionException in case of NasException errors.

        """
        try:
            super(NasConnectionCallback, self).__exit__(*args)
        except (NasException, NasConnectionException) as err:
            raise CallbackExecutionException(err), None, args[2]


class OptionsParser(dict):
    """This is a comma delimited options parser for mount options
    """
    def __init__(self, raw_options):
        """Parses the options and adds to a dictionary and a list
        because we don't have an ordered dict in python 2.6.6

        >>> o = OptionsParser("rw,no_root_squash,hede=hodo")

        >>> str(o)
        'rw,no_root_squash,hede=hodo'
        >>> o['attr'] = 'value'
        >>> str(o)
        'rw,no_root_squash,hede=hodo,attr=value'
        >>> o['attr'] = 'value1'
        >>> str(o)
        'rw,no_root_squash,hede=hodo,attr=value1'
        >>> del o['attr']
        >>> str(o)
        'rw,no_root_squash,hede=hodo'
        >>> o['rw']
        >>> o['absent']
        Traceback (most recent call last):
        ...
        KeyError: 'absent'
        """
        super(OptionsParser, self).__init__()
        self._option_names = []
        raw_options_list = raw_options.split(",")
        for raw_option in raw_options_list:
            option = raw_option.split("=")
            self[option[0]] = option[1] if len(option) > 1 else None

    def __str__(self):
        pairs = []
        for key in self._option_names:
            val = self[key]
            item_str = "=".join(
                (key, val)) if val else key
            pairs.append(item_str)
        return ",".join(pairs)

    def __setitem__(self, key, value):
        if key not in self._option_names:
            self._option_names.append(key)
        super(OptionsParser, self).__setitem__(key, value)

    def __delitem__(self, key):
        self._option_names.remove(key)
        super(OptionsParser, self).__delitem__(key)


def in_ip(ip, client):
    # if subnet
    if '/' in client:
        client_ip = netaddr.IPAddress(ip)
        subnet = netaddr.IPNetwork(client)
        return client_ip in subnet
    else:
        return ip == client


def has_property(model, prop):
    return hasattr(model, prop) and getattr(model, prop) is not None


class PuppetMountStatus(object):
    MOUNT = "mounted"
    UMOUNT = "absent"
    REMOUNT = "remount"


class NasPlugin(Plugin):
    """ Use the LITP NAS plugin to create file systems, exports and caches
        on NAS servers and mount exports from NAS and non-NAS
        servers. It can also be used to create, delete and restore snapshots
        of file systems

        Update and remove reconfiguration actions are supported for this plugin
        (with some exceptions - see the Validation section).
    """
    DEFAULT_SNAP_NAME = 'snapshot'

    def __init__(self):
        """ constructor for the NasPlugin.
        """
        self.nfs_connection_class = NasConnectionCallback

    def validate_model(self, plugin_api_context):
        """


        Validates NAS model integrity. Validation rules enforced by this
        plugin are:

        - Rules common to the Management Server and peer nodes:

          - The item of type ``sfs-service`` must be defined with \
            a value for the ``name`` property that is unique in \
            the model.

          - The item of type ``sfs-service`` must be defined with \
            a unique value for the ``management_ipv4`` property.

          - The item of type ``sfs-service`` should be defined \
            with values for the ``name``, ``user_name``, \
            ``password_key``, ``management_ipv4`` \
            properties if it has underlying  children of item type \
            ``sfs-pool``.

          - The item of type ``sfs-pool`` must be defined with a \
            unique value for the ``name`` property for a given parent \
            ``sfs-service`` item type.

          - If a single item of type ``sfs-pool`` is defined it must \
            contain a minimum of one child ``sfs-filesystem`` item type.

          - If multiple items of type ``sfs-pool`` are defined they must \
            conatin a minimum of one child ``sfs-filesystem`` or \
            ``sfs-cache`` item types.

          - The item of type ``sfs-filesystem`` must be defined with \
            a unique value for property type ``path`` for a given parent \
            ``sfs-service`` item type.

          - The item of type ``sfs-export`` must be unique for a given \
            parent ``sfs-filesystem``.
            Two items of type ``sfs-export`` are deemed to be duplicates \
            if they have at least one host in common or one host is \
            contained in a subnet or subnets overlap \
            from their respective ``ipv4allowed_clients`` property.

          - The item of type ``sfs-virtual-server`` must be defined with \
            a value for the ``name`` property that is unique in the model.

          - The item of type ``sfs-virtual-server`` must be defined with \
            a value for the ``ipv4address`` property that is unique in \
            the model.

          - The item of type ``nfs-service`` may be defined with \
            either ``ipv4address`` or ``ipv6address`` or both. These \
            addresses must be unique in the model.

          - If the item of type ``nfs-service`` is defined with \
            both ``ipv4address`` and ``ipv6address``, the \
            ``ipv4address`` will be chosen when mounting an export \
            from the server.

          - If the item  of type ``nfs-service`` is defined with \
            only one property, either ``ipv4address`` or ``ipv6address``, \
            then for a given ``nfs-mount`` that resolves to that \
            ``nfs-service`` the ``network_name`` property must relate to an \
            interface that supports  the same IP address version.

          - The item of type ``nfs-service`` must be defined with \
            a unique value for the ``name`` property.

          - The ``name`` property values of all ``nfs-service`` and \
            ``sfs-virtual-server`` items must be collectively unique.

          - The ``provider`` property value of the ``nfs-mount`` \
            item type should reference a provider defined amongst \
            ``nfs-service`` or ``sfs-virtual-server`` items. If the \
            ``nfs-mount`` item contains an ``export_path`` value \
            that indicates we are trying to mount a managed
            ``sfs-export`` defined in the model, then the provider \
            should be a defined ``sfs-virtual-server`` item.

          - The ``provider`` property value of the ``nfs-mount`` \
            item type can only be updated to a different \
            ``sfs-virtual-server`` item type ``name`` property.

          - If the ``provider`` property value of an ``nfs-mount`` item type \
            resolves to an ``nfs-service`` \
            item type ``name`` property then it cannot be updated.

          - Under any given ``sfs-service`` item, only one ``sfs-cache`` \
            item can be defined.

          - If an ``sfs-cache`` item is defined, it requires a minimum \
            of one ``sfs-filesystem`` to be defined, whose ``cache_name`` \
            property value matches the ``name`` property value of the \
            ``sfs-cache`` item.

          - If the ``cache_name`` property of an ``sfs-filesystem`` item is \
            specified, there must be a corresponding ``sfs-cache`` item \
            defined whose ``name`` property matches the ``cache_name`` \
            property of such ``sfs-filesystem`` item.

          - The ``cache_name`` property of all ``sfs-filesystem`` items must \
            point to the same ``name`` property of an ``sfs-cache`` item.

          - For the ``sfs-filesystem`` item, either both ``snap_size`` and \
            ``cache_name`` properties must be present or neither must be \
            present. This only applies to veritas sfs-services

          - For the ``sfs-filesystem`` item under unityxt sfs-services, \
            the ``provider`` property value of the ``sfs-filesystem`` \
            item type is required and must reference a \
            ``sfs-virtual-server`` item

          - For the ``sfs-filesystem`` item under unityxt sfs-services, \
            the minimum value of ``size`` is 3G

          - For the ``sfs-filesystem`` item, the ``size`` property may be \
            increased but not decreased.

          - For the ``sfs-filesystem`` item, the ``size`` property may not be \
            increased while a snapshot is present.

          - If an ``sfs-cache`` item, whose state is applied, is still \
            referenced by an ``sfs-filesystem`` via the cache name, it is \
            not allowed to delete such ``sfs-cache`` item.
        """
        errors = []

        managed_nodes = [n for n in plugin_api_context.query('node')
                         if not n.is_for_removal()]
        mses = [ms for ms in plugin_api_context.query('ms')
                if not ms.is_for_removal()]
        all_nodes = mses + managed_nodes
        for node in all_nodes:
            errors += self._validate_mount_point_in_model(node)
            errors += self._validate_mounts(plugin_api_context, node)
            errors += self._validate_correct_interfaces_defined(
                plugin_api_context, node)
            errors += self._validate_nested_mount_points(
                plugin_api_context, node)
            errors += self._validate_nfs_mount_network_names(node)
            errors += self._validate_sfs_mount_interface_has_ipv4_address(
                        plugin_api_context, node)

        errors += self._validate_service_dependencies(plugin_api_context)
        errors += self._validate_provider_names(plugin_api_context)
        errors += self._validate_no_duplicate_exports(plugin_api_context)

        sfs_services = plugin_api_context.query('sfs-service')
        errors += self._validate_only_one_cache_per_sfs(sfs_services)
        errors += self._validate_filesystem_size(sfs_services,
                                                 plugin_api_context)
        errors += self._validate_sfs_properties(sfs_services)
        errors += self._validate_service_name_is_unique(sfs_services)
        errors += self._validate_unique_sfs_mgmt_ipv4(sfs_services)
        errors += self._validate_no_duplicate_filesystems_per_service(
            sfs_services)
        errors += self._validate_virt_server_ipv4_is_unique(sfs_services)
        errors += self._validate_no_duplicate_pool_names_in_service(
            sfs_services)
        errors += self._validate_sfs_filesystem_cachename(sfs_services)
        errors += self._validate_unique_sfs_cache_name(sfs_services)
        errors += self._validate_sfs_cache_dependencies(sfs_services)
        nfs_services = plugin_api_context.query('nfs-service')
        errors += self._validate_unique_nfs_ipv4address(nfs_services)
        errors += self._validate_unique_nfs_ipv6address(nfs_services)
        errors += self._validate_no_empty_pools(sfs_services)

        errors += self._validate_filesystem_provider(
            sfs_services
        )
        errors += self._validate_sfs_cache_snapsize(sfs_services)

        nfs_mounts = plugin_api_context.query('nfs-mount')
        if nfs_mounts:
            errors += self._validate_nfs_mount_valid_providers(all_nodes,
                    nfs_mounts, sfs_services, nfs_services)
            for node in all_nodes:
                mounts = node.query('nfs-mount')
                nfs_mounts.extend(mounts)
            errors += self._validate_nfs_mount_providers_updated(
                    nfs_mounts, sfs_services, nfs_services, plugin_api_context)
        return errors

    def validate_model_snapshot(self, plugin_api_context):
        """


        Validates snapshot actions passed to the model.
        Validation rules enforced are:

        - A snapshot may not be created while an ``sfs-filesystem`` \
          ``size`` property update is pending.

        - A ``create`` snapshot action requires that all ``sfs-filesystem`` \
          items with defined ``cache_name`` property must \
          point to the same ``name`` property of an ``sfs-cache`` item.

        - Rules pertaining to the snapshot name:

          - The maximum length of the name of a backup snapshot \
            is 7 characters.

          - Underscore characters must not be used in the snapshot name.
        """

        errors = []
        try:
            action = plugin_api_context.snapshot_action()
        except Exception as e:
            raise PluginError(e)
        snapshot_name = self._get_snapshot_tag(plugin_api_context)
        sfs_services = plugin_api_context.query('sfs-service')

        if action == 'create':
            if any(self._get_snappable_filesystems(s) for s in sfs_services):
                errors += self._validate_sfs_filesystem_cachename(
                    sfs_services,
                    model_validation=False)
                if snapshot_name:
                    errors += self._validate_snapshot_name(snapshot_name)

            for sfs in sfs_services:
                for pool in sfs.pools:
                    for fs in pool.file_systems:
                        if fs.is_updated():
                            previous_size = Size(
                                       fs.applied_properties.get('size'))
                            if Size(fs.size) != previous_size:
                                msg = 'A snapshot may not be created while ' \
                                      'an sfs-filesystem "size" property ' \
                                      'update is pending.'
                                errors.append(ValidationError(
                                              item_path=fs.get_vpath(),
                                              error_message=msg))

        return errors

    def _get_snapshot_tag(self, context):
        """ Get the snapshot tag from the plugin context API, return
        empty str if no snapshot tag is given.
        """
        if context.snapshot_name() != UPGRADE_SNAPSHOT_NAME:
            return context.snapshot_name()
        return ''

    @classmethod
    def _validate_filesystem_size(cls, sfs_services, context):
        """
        Validates that for every sfs-filesystem that has an updated
        size, the target size must not be less than the current size. If
        a snapshot item exists in the model, file system expansion is not
        supported.
        """
        errors = []

        ss_objects = context.query('snapshot-base')

        for sfs in sfs_services:
            sfs_nas_type = NasPlugin._get_sfs_nas_type(sfs)
            for pool in sfs.pools:
                for fs in [f for f in pool.file_systems if f.is_updated()]:
                    previous_size = Size(fs.applied_properties.get('size'))
                    if Size(fs.size) < previous_size:
                        msg = 'Decreasing the "size" property of ' \
                                  'an sfs-filesystem is not supported.'
                        cls.debug(msg)
                        errors += cls._add_error(fs, msg)
                    if ss_objects:
                        if Size(fs.size) != previous_size:
                            msg = 'Changing the "size" ' \
                                  'property of any sfs-filesystem ' \
                                  'while a snapshot exists ' \
                                  'is not supported.'
                            cls.debug(msg)
                            errors += cls._add_error(fs, msg)
                # For UnityXT, minimum size is 3G
                if sfs_nas_type == "unityxt":
                    for fs in pool.file_systems:
                        if not fs.is_for_removal() and \
                            Size(fs.size) < Size("3G"):
                            msg = "Minimum FS size for UnityXT is 3G"
                            cls.debug(msg)
                            errors += cls._add_error(fs, msg)

        return errors

    @classmethod
    def _validate_filesystem_provider(cls, sfs_services):
        """
        Validates that for every sfs-filesystem for unityxt sfs-service
        """
        errors = []

        for service in sfs_services:
            if NasPlugin._get_sfs_nas_type(service) != "unityxt":
                continue

            vservers = []
            for vserver in service.virtual_servers:
                vservers.append(vserver.name)

            for pool in [p for p in service.pools if not p.is_for_removal()]:
                cls._validate_filesystem_provider_pool(pool, vservers, errors)

        return errors

    @classmethod
    def _validate_filesystem_provider_pool(cls, pool, vservers, errors):
        """
        Validates that every sfs-filesystem in the pool references a server
        in vservers
        """
        log.trace.debug(
            "_validate_filesystem_provider_pool: vservers=%s",
            vservers
        )

        for fs in pool.file_systems:
            log.trace.debug(
                "_validate_filesystem_provider: fs=%s",
                fs
            )
            if not fs.is_for_removal():
                if not hasattr(fs, 'provider') or \
                    getattr(fs, 'provider') is None:
                    msg = "provider is required for UnityXT filesystem"
                    errors.append(cls._add_error(fs, msg))
                elif fs.provider not in vservers:
                    msg = "provider {0} is not valid".format(fs.provider)
                    errors.append(cls._add_error(fs, msg))

    @classmethod
    def _validate_nfs_mount_network_names(cls, node):
        """
        Method validates that nfs mounts
        that share a common value for their "provider" property,
        on a per node basis, should have the same "network_name"
        property value too
        """
        errors = []

        providers = {}

        for mount in [m for m in node.query('nfs-mount')
                        if not m.is_for_removal()]:
            if (mount.provider in providers and
                mount.network_name != providers[mount.provider][0]):
                msg = ('The value for property "network_name" on path "%s"'
                      ' must be identical to the "network_name" value on'
                      ' path "%s" as they share a common value for the'
                      ' "provider" property.' % (
                      mount.get_vpath(),
                      providers[mount.provider][1]))
                errors += cls._add_error(mount, msg)
            else:
                providers[mount.provider] = [mount.network_name,
                                             mount.get_vpath()]
        return errors

    @classmethod
    def _validate_mount_point_in_model(cls, node):
        """
        Method validates that the mount point used by nfs-mount
        is unique in the model
        """
        mount_points = {}
        errors = []

        for profile in node.query('storage-profile'):
            if not profile.is_for_removal():
                for vg in profile.volume_groups:
                    if not vg.is_for_removal():
                        for fs in vg.file_systems:
                            if not fs.is_for_removal():
                                mount_points[fs.mount_point] = fs.get_vpath()

        for_removal = dict([(m.mount_point, m) for m in node.query('nfs-mount')
                                               if m.is_for_removal()])
        for mount in node.query('nfs-mount'):
            if (mount.is_initial() or mount.is_updated()) and \
                mount.mount_point in for_removal:
                msg = 'Value "%s" for property "mount_point" is already ' \
                      'defined on path "%s" and it is marked for removal.' % \
                      (mount.mount_point,
                       for_removal[mount.mount_point].get_vpath())
                errors += cls._add_error(mount, msg)
            if not mount.is_for_removal():
                if mount.mount_point in mount_points:
                    msg = 'Value "%s" for property "mount_point"' \
                          ' is already defined on path "%s"' % (
                            mount.mount_point, mount_points[mount.mount_point])
                    errors += cls._add_error(mount, msg)
                else:
                    mount_points[mount.mount_point] = mount.get_vpath()
        return errors

    @classmethod
    def _add_error(cls, item, msg):
        return [ValidationError(item_path=item.get_vpath(),
                                error_message=msg)]

    @staticmethod
    def debug(msg):
        """debugging level message, which takes the name of the previous method
        in the call stack as the preamble, plus the message.
        """
        try:
            method_name = ".%s: " % inspect.stack()[0][3]
        except IndexError:
            method_name = ""
        log.trace.debug("%s%s" % (method_name, msg))

    @staticmethod
    def warn(msg, preamble=False):
        """ By default, warning message does not need a preamble in the output
        """
        try:
            method_name = ".%s: " % inspect.stack()[0][3]
        except IndexError:
            method_name = ""
        output = "%s%s" % (method_name, msg) if preamble else msg
        log.event.warn(output)

    @classmethod
    def _validate_unique_sfs_mgmt_ipv4(cls, sfs_services):
        """
        Method validates that the management_ipv4 address is unique
        amongst sfs-service items
        """
        sfs_mgmt_ips = {}
        errors = []

        for sfs in sfs_services:
            if hasattr(sfs, 'management_ipv4') \
                    and sfs.management_ipv4 is not None:
                if sfs.management_ipv4 in sfs_mgmt_ips:
                    msg = 'Value "%s" for property ' \
                          '"management_ipv4" is already defined' \
                          ' on sfs-service path "%s"' % (
                          sfs.management_ipv4,
                          sfs_mgmt_ips[sfs.management_ipv4])
                    cls.debug(msg)
                    errors += cls._add_error(sfs, msg)
                else:
                    sfs_mgmt_ips[sfs.management_ipv4] = sfs.get_vpath()
        return errors

    # TODO: REALLY NEED TO FIX THIS
    @classmethod
    def _validate_sfs_properties(cls, sfs_services):
        """
        Method validates that an sfs-service is either managed
        or unmanaged
        """
        errors = []

        for sfs in sfs_services:
            pools = [p for p in sfs.pools]
            b = lambda x: not hasattr(sfs, x) or (hasattr(sfs, x)
                                                  and getattr(sfs, x) is None)
            if pools:
                if all([b(i) for i in ['user_name', "management_ipv4",
                                       'password_key']]):
                    msg = 'An sfs-service with only property "name" '\
                          'defined should have no related ' \
                          'sfs-pool items defined.'
                    cls.debug(msg)
                    errors += cls._add_error(sfs, msg)
        return errors

    @staticmethod
    def _is_sfs_managed(sfs):
        """
        If an sfs-service item is managed, it will have at least one export and
        it will contain the following properties: management_ipv4, user_name,
        password_key.
        """
        properties = ['user_name', 'password_key', 'management_ipv4']
        a = lambda x: hasattr(sfs, x) and getattr(sfs, x) is not None
        return any([a(i) for i in properties])

    @classmethod
    def _validate_unique_nfs_ipv4address(cls, nfs_services):
        """
        Method validates that the ipv4address is unique
        amongst nfs-service items
        """
        nfs_ips = {}
        errors = []

        for n in nfs_services:
            if hasattr(n, 'ipv4address')\
                 and n.ipv4address is not None:
                if n.ipv4address in nfs_ips:
                    msg = 'Value "%s" for property "ipv4address"' \
                          ' is already defined on nfs-service path "%s"' % (
                        n.ipv4address, nfs_ips[n.ipv4address])
                    cls.debug(msg)
                    errors += cls._add_error(n, msg)
                else:
                    nfs_ips[n.ipv4address] = n.get_vpath()

        return errors

    @classmethod
    def _validate_unique_nfs_ipv6address(cls, nfs_services):
        """
        Method validates that the ipv6address is unique
        amongst nfs-service items
        """
        nfs_ips = {}
        errors = []

        for n in nfs_services:
            if hasattr(n, 'ipv6address') \
                   and n.ipv6address is not None:
                if n.ipv6address in nfs_ips:
                    msg = 'Value "%s" for property "ipv6address" ' \
                          ' is already defined on nfs-service path "%s" ' % (
                        n.ipv6address, nfs_ips[n.ipv6address])
                    cls.debug(msg)
                    errors += cls._add_error(n, msg)
                else:
                    nfs_ips[n.ipv6address] = n.get_vpath()
        return errors

    @classmethod
    def _validate_no_empty_pools(cls, sfs_services):
        """
        Method to ensure pool contains at least one instance of
        either 'file system' or 'cache'.  Else generate error if
        the pool is empty.
        """

        errors = []
        for service in [s for s in sfs_services if not s.is_for_removal()]:
            pools = [p for p in service.pools if not p.is_for_removal()]
            caches_per_serv = []
            fss_per_service = []
            for pool in pools:
                caches = [cache for cache in pool.cache_objects if not
                                                cache.is_for_removal()]
                if caches:
                    caches_per_serv.extend(caches)
                file_systems = [fs for fs in pool.file_systems if not
                                                fs.is_for_removal()]
                if file_systems:
                    fss_per_service.extend(file_systems)

            if len(pools) == 1 and not fss_per_service:
                msg = 'The sfs-pool with a property "name" ' \
                      'value of "%s" ' \
                      'must contain a minimum of one ' \
                      'sfs-filesystem.' % pools[0].name
                cls.debug(msg)
                errors += cls._add_error(pools[0], msg)
            else:
                for pool in pools:
                    description = ''
                    caches = [cache for cache in pool.cache_objects if not
                            cache.is_for_removal()]
                    file_systems = [fs for fs in pool.file_systems if not
                            fs.is_for_removal()]
                    # Check if fs's and cache across all pools
                    if not caches_per_serv and not fss_per_service:
                        description = "sfs-cache or sfs-filesystem."
                    else:
                        # Check if fs's and cache in this pool
                        empty_pool = not file_systems and not caches
                        if empty_pool:
                            description = "sfs-cache or sfs-filesystem."
                            if caches_per_serv:
                                description = "sfs-filesystem."
                    if description:
                        msg = 'The sfs-pool with a property "name" ' \
                              'value of "%s" ' \
                              'must contain a minimum of one %s' \
                               % (pool.name, description)
                        cls.debug(msg)
                        errors += cls._add_error(pool, msg)
        return errors

    @classmethod
    def _validate_virt_server_ipv4_is_unique(cls, sfs_services):
        """
        Method validates that the ipv4address is unique
        amongst sfs-virtual-server items
        """
        servers = {}
        errors = []

        for sfs in sfs_services:
            msg = 'Querying for sfs model items "%s" ' % sfs.get_vpath()
            cls.debug(msg)
            for v in sfs.virtual_servers:
                if hasattr(v, 'ipv4address') \
                        and v.ipv4address is not None:
                    if v.ipv4address in servers:
                        msg = 'Value "%s" for property "ipv4address"' \
                        ' is already defined on sfs-virtual-server path' \
                        ' "%s"' % (v.ipv4address, servers[v.ipv4address])
                        errors += cls._add_error(v, msg)
                    else:
                        servers[v.ipv4address] = v.get_vpath()
        return errors

    @classmethod
    def _validate_service_name_is_unique(cls, services):
        """
        Method validates that all sfs-service items have unique
        values for their name property
        """
        names = {}
        errors = []

        for s in services:
            if s.name in names:
                msg = 'Value "%s" for property "name"' \
                      ' is already defined on sfs-service path "%s"' % (
                    s.name, names[s.name])
                cls.debug(msg)
                errors += cls._add_error(s, msg)
            else:
                names[s.name] = s.get_vpath()

        return errors

    @classmethod
    def _check_required_mounts(cls, errors, service, api,
                               providers, service_type):
        if service.is_for_removal():
            for mount in api.query('nfs-mount'):
                if not mount.is_for_removal() and mount.provider in providers:
                    msg = '%s "%s" is required by the nfs-mount '\
                        '"%s" and cannot be removed.' % \
                        (service_type, service.name, mount.get_vpath())
                    errors.extend(cls._add_error(service, msg))

    @classmethod
    def _validate_service_dependencies(cls, plugin_api_context):
        """ Before removing a sfs-service or nfs-service, validate that no
        nfs-mount items are depending on the service based on the provider.
        If the item for removal is an sfs-service, we also validate that
        the sfs-virtual-server must have no other dependencies.
        """
        nfs_srv_name, sfs_srv_name, sfs_virsrv_name = \
            "nfs-service", "sfs-service", "sfs-virtual-server"
        nfs_srvs, sfs_srvs, sfs_virsrvs = [plugin_api_context.query(i) \
                    for i in [nfs_srv_name, sfs_srv_name, sfs_virsrv_name]]

        errors = []
        for service in nfs_srvs:
            cls._check_required_mounts(errors, service, plugin_api_context,
                                       [service.name], nfs_srv_name)
        for service in sfs_srvs:
            cls._check_required_mounts(errors, service, plugin_api_context,
                [vs.name for vs in service.virtual_servers], sfs_srv_name)
        for service in sfs_virsrvs:
            cls._check_required_mounts(errors, service, plugin_api_context,
                                       [service.name], sfs_virsrv_name)
        return errors

    @classmethod
    def _validate_provider_names(cls, api):
        """
        Method validates that nfs-service and sfs-virtual-server
        names are collectively unique
        """
        nfs_services = [
            s for s in api.query('nfs-service') if not s.is_for_removal()]
        sfs_services = [
            s for s in api.query('sfs-service') if not s.is_for_removal()]
        server_names = {}
        errors = []

        for s in nfs_services:
            if s.name in server_names:
                msg = 'Value "%s" for property "name" is already defined' \
                      ' on path "%s"' % (s.name, server_names[s.name])
                cls.debug(msg)
                errors += cls._add_error(s, msg)
            else:
                server_names[s.name] = s.get_vpath()

        for sfs in sfs_services:
            msg = 'Querying for sfs-service items "%s"' % sfs.get_vpath()
            cls.debug(msg)
            for v in [vs for vs in sfs.virtual_servers
                      if not vs.is_for_removal()]:
                if v.name in server_names:
                    msg = 'Value "%s" for property "name" is already defined' \
                          ' on path "%s"' % (v.name, server_names[v.name])
                    errors += cls._add_error(v, msg)
                else:
                    server_names[v.name] = v.get_vpath()
        return errors

    @classmethod
    def _get_nfs_mount_provider(
            cls, sfs_services, nfs_services, mount):
        """
        Method validates that the provider is defined in nfs-service
        or sfs-virtual-server items. If the nfs-mount item contains
        an export_path that indicates we are trying to mount a managed
        export in the model, then we should only search for the provider
        in defined sfs-virtual-server items
        returns the provider that is associated with the mount
        """
        errors = []
        managed_vservers = {}
        for s in sfs_services:
            managed_vservers.update(
                dict((v.name, v)
                     for v in s.virtual_servers
                     if s.user_name and not v.is_for_removal()))
        umanaged_vservers = {}
        for s in sfs_services:
            umanaged_vservers.update(
                dict((v.name, v)
                     for v in s.virtual_servers
                     if not s.user_name and not v.is_for_removal()))
        nfs_services = dict((
            (ns.name, ns) for ns in nfs_services if not ns.is_for_removal()))
        if mount.provider not in\
                managed_vservers.keys() + umanaged_vservers.keys()\
                + nfs_services.keys():
            msg = 'Value "%s" for property "provider"' \
                  ' does not reference' \
                  ' any defined sfs-virtual-server or' \
                  ' nfs-service items.' \
                   % (mount.provider,)
            cls.debug(msg)
            errors += cls._add_error(mount, msg)
        return (
            managed_vservers.get(mount.provider, None),
            umanaged_vservers.get(mount.provider, None),
            nfs_services.get(mount.provider, None),
            errors
        )

    @classmethod
    def _validate_nested_mount_points(cls, _, node):
        """
        Validates nested mount points in the whole model.
        """
        errors = []
        ab = lambda x: "%s/" % os.path.abspath(x)

        def check_nested(m1, m2):
            if m1.mount_point == m2.mount_point or \
               not ab(m1.mount_point).startswith(ab(m2.mount_point)):
                return []
            msg = 'Nested mount points are not allowed: "%s". The ' \
                  'mount point "%s" is defined on "%s".' % \
                  (m1.mount_point, m2.mount_point, m2.get_vpath())
            cls.debug(msg)
            return cls._add_error(m1, msg)

        for mount1 in node.query('nfs-mount'):
            for mount2 in node.query('nfs-mount'):
                if mount1 == mount2:
                    continue
                errors += check_nested(mount1, mount2)

        return errors

    @classmethod
    def _validate_no_duplicate_filesystems_per_service(cls, services):
        """
        Method validates that there is no duplicate sfs-filesystem
        in an sfs-service
        """
        errors = []
        for service in services:
            all_fs_in_service = []
            unique_filesystems = []
            for pool in [p for p in service.pools if not p.is_for_removal()]:
                all_fs_in_service.extend([f for f in pool.file_systems
                                          if not f.is_for_removal()])
            for filesystem in all_fs_in_service:
                if not unique_filesystems:
                    unique_filesystems.append(filesystem)
                else:
                    for other_filesystem in unique_filesystems:
                        if other_filesystem.path == filesystem.path:
                            msg = 'Value "%s" for property "path" is '\
                                  'already defined on path: "%s"' % (
                                    filesystem.path,
                                    other_filesystem.get_vpath())
                            cls.debug(msg)
                            errors += cls._add_error(filesystem, msg)
                    if not errors:
                        unique_filesystems.append(filesystem)
        return errors

    @classmethod
    def _validate_no_duplicate_pool_names_in_service(cls, sfs_services):
        """
        Method validates that there are no duplicate pool names in an
        sfs-service
        """
        errors = []
        for service in [s for s in sfs_services if not s.is_for_removal()]:
            pools = [p for p in service.pools if not p.is_for_removal()]
            for index, left_pool in enumerate(pools):
                for right_pool in pools[index + 1:len(pools)]:
                    if left_pool.name == right_pool.name:
                        msg = 'Value "%s" for property "name" is ' \
                              'already defined on path: "%s"' % (
                              left_pool.name, left_pool.get_vpath())
                        cls.debug(msg)
                        errors += cls._add_error(right_pool, msg)
        return errors

    @classmethod
    def _validate_no_duplicate_exports(cls, plugin_api_context):
        """
        Method validates that there are no duplicate
        sfs-exports in the model. A duplicate is defined
        as an sfs-export with one or more identical allowed clients
        under the same file system for a given pool
        """
        pools = plugin_api_context.query('sfs-pool')
        errors = []

        def get_clients(props):
            clients = props.get("ipv4allowed_clients")
            return clients.split(',') if clients else []

        def generate_error_message(c, ip, e, other_export):
            c_ip_type = 'Subnet' \
                if '/' in c else 'IP address'
            if '/' in ip:
                second_ip_type = 'subnet'
            else:
                second_ip_type = 'IP address'
            if ip == c:
                if second_ip_type == 'subnet':
                    second_ip_type = 'a subnet'
                else:
                    second_ip_type = 'an IP address'
                msg = ('{first_type} "{first_ip}" in value'
            ' "{property_value}" for '
            'property "ipv4allowed_clients"'
            ' is a duplicate of {second_type}'
            ' on path: "{other_export_vpath}"').format(
                   first_type=c_ip_type,
                   first_ip=c,
                   property_value=e.ipv4allowed_clients,
                   second_type=second_ip_type,
                   other_export_vpath=other_export.get_vpath())
            else:
                msg = ('{first_type} "{first_ip}" in value'
            ' "{property_value}" for '
            'property "ipv4allowed_clients"'
            ' overlaps with {second_type} "{second_ip}"'
            ' on path: "{other_export_vpath}"').format(
                   first_type=c_ip_type,
                   first_ip=c,
                   property_value=e.ipv4allowed_clients,
                   second_type=second_ip_type,
                   second_ip=ip,
                   other_export_vpath=other_export.get_vpath())

            cls.debug(msg)
            return cls._add_error(e, msg)

        for pool in [p for p in pools if not p.is_for_removal()]:
            for filesystem in [
                    f for f in pool.file_systems if not f.is_for_removal()]:
                ip_to_exports = []
                for e in [
                        e for e in filesystem.exports
                        if not e.is_for_removal()]:
                    clients = get_clients(e.properties)
                    for c in clients:
                        ip_to_exports.append((c, e))
                # first ips, then subnets
                _ips = [pair for pair in ip_to_exports if '/' not in pair[0]]
                subnets = [pair for pair in ip_to_exports if '/' in pair[0]]
                ip_to_exports = _ips + subnets
                for index, pair in enumerate(ip_to_exports):
                    ip, export = pair
                    for pair in ip_to_exports[index + 1:]:
                        other_ip, other_export = pair
                        if ips_overlap(ip, other_ip):
                            errors += generate_error_message(
                                ip, other_ip, export, other_export)
        return errors

    @classmethod
    def _validate_clientaddr_is_valid(cls, interface, nfs_mount):
        """
        Method validates that an nfs-mount clientaddr mount option is
        assigned to an ip address that an interface on a node has on the same
        network
        """
        errors = []

        if not nfs_mount.is_initial():
            return errors

        if has_property(nfs_mount, "mount_options"):
            options = OptionsParser(nfs_mount.mount_options)
            clientaddr = options.get("clientaddr", None)
            if clientaddr and not (interface.ipaddress == clientaddr
            or interface.ipv6address == clientaddr):
                msg = 'The "clientaddr" value "%s" in the property ' \
                      '"mount_options" must be an ' \
                      'IP address on the network named "%s" ' \
                      'and that IP address must be defined ' \
                      'on an interface on the node.' % \
                      (clientaddr, nfs_mount.network_name)
                cls.debug(msg)
                errors += cls._add_error(nfs_mount, msg)
        return errors

    @classmethod
    def _get_mount_interface(
            cls, mount, node):
        """
        Method validates that the network_name for the mount checks with
        at least one of the interfaces that are defined inside the node
        infrastructure
        """
        interface = next(
            (i for i in node.network_interfaces
             if mount.network_name == i.network_name
             and not i.is_for_removal()), None)
        errors = []
        if not interface:
            msg = 'Value "%s" for property "network_name"' \
                  ' must match the network_name for one interface' \
                  ' defined on node "%s".' % (
                mount.network_name, node.hostname)
            cls.debug(msg)
            errors += cls._add_error(mount, msg)
        return interface, errors

    @classmethod
    def _is_managed_mount(cls, nfs_mount, plugin_api_context):
        """
        Checks if an nfs-mount is a managed export, a managed export is one
        that has an sfs-filesystem path that matches the export_path on the
        nfs-mount
        """
        filesystems = [
            fs for fs in plugin_api_context.query("sfs-filesystem")
            if not fs.is_for_removal()]
        for filesystem in filesystems:
            if nfs_mount.export_path == filesystem.path:
                return True
        return False

    @classmethod
    def _validate_mounts(cls, api, node):
        """
        Method validates that:
        - The ip address of an interface on a node that
        has a managed mount is on the allowed clients list of an
        export being referenced by export path
        - Checks if the node that the mount is mounted to has an interface
        that has the same network_name with the mount
        - Checks if the clientaddr inside mount_options is pointing to the
        interface of the node
        - If the file system is managed, checks if the allowedclients points
        to interface of the node
        """
        errors = []
        nfs_services = [
            s for s in api.query('nfs-service') if not s.is_for_removal()]
        sfs_services = [
            s for s in api.query('sfs-service') if not s.is_for_removal()]

        def ipaddress_in_allowed_clients(ipaddress, file_system):
            if file_system and ipaddress is not None:
                for e in [e for e in file_system.exports
                          if not e.is_for_removal()]:
                    if e.ipv4allowed_clients:
                        clients4 = [
                            x.strip() for x in e.ipv4allowed_clients.split(',')
                            if x.strip()]
                        if any((in_ip(
                                ipaddress, client) for client in clients4)):
                            return True
            return False
        for m in [
                m for m in node.query('nfs-mount') if not m.is_for_removal()]:
            interface, err = cls._get_mount_interface(m, node)
            if err:
                errors += err
                continue
            # This doesn't prevent other validations to work, so just extending
            # errors
            errors += cls._validate_clientaddr_is_valid(interface, m)
            # actually we should also check the interfaces for nfs provider,
            # but we don't do that since there is another function for that
            # so much refactoring for remodel branch
            mvprovider, _, _, err = cls._get_nfs_mount_provider(
                sfs_services, nfs_services, m)

            errors += err
            if mvprovider:
                sfs_service = mvprovider.parent.parent
                file_system = next(
                        (fs for fs in sfs_service.query(
                                "sfs-filesystem")
                         if fs.path == m.export_path
                         and not fs.is_for_removal()), None)
                if not file_system:
                    continue
                if not ipaddress_in_allowed_clients(
                        interface.ipaddress, file_system):
                    msg = 'The IP address for the network "%s" must be ' \
                          'included in the property "ipv4allowed_clients" '\
                          'of an sfs-export which is defined under an ' \
                          'sfs-filesystem which has a property "path" ' \
                          'defined as "%s".' % (m.network_name, m.export_path)
                    errors += cls._add_error(m, msg)
                    cls.debug(msg)
        return errors

    @classmethod
    def _is_dual_stack(cls, plugin_api_context, node, nfs):
        services = [
            s for s in plugin_api_context.query('nfs-service')
            if not s.is_for_removal()]
        mount_interface = next(
            (i for i in node.network_interfaces
                if nfs.network_name == i.network_name
                and not i.is_for_removal()), None)
        if not mount_interface:
            return False
        for service in services:
            if nfs.provider == service.name and (hasattr(service,
                'ipv4address')\
                        and service.ipv4address is not None)\
            and (hasattr(service, 'ipv6address') and \
            service.ipv6address is not None) and \
            (hasattr(mount_interface, 'ipaddress')\
            and mount_interface.ipaddress is not None) and \
            (hasattr(mount_interface, 'ipv6address')\
            and mount_interface.ipv6address is not None):
                return True
        return False

    @classmethod
    def _validate_correct_interfaces_defined(cls, api, node):
        """
        Validate that:
        If you are allowed client via an ipv4 address, you must specify an
        ipv4 address on the nfs-service and your network_name related
        interface must support ipv4.

        If you are allowed client via an ipv6 address, you must specify an ipv6
        address on the nfs-service and your network_name related interface
        must support ipv6.
        """
        errors = []
        nfs_mounts = [i for i in node.query('nfs-mount')
                      if not i.is_for_removal()]

        for mount in nfs_mounts:
            # network interface device on the node using same network as mount
            device = [dev for dev in node.network_interfaces if
                      dev.network_name == mount.network_name
                      and not dev.is_for_removal()]
            nfs_services = [
                s for s in api.query('nfs-service') if not s.is_for_removal()]
            provider = [
                prov for prov in nfs_services
                if prov.name == mount.provider]

            if provider and device:
                # check if ip of the interface is version 4 or 6
                if getattr(device[0], 'ipaddress', None) is not None:
                    ip_version = 'ipv4'
                elif getattr(device[0], 'ipv6address', None) is not None:
                    ip_version = 'ipv6'
                # error when there is no ipaddress assigned to the interface
                else:
                    msg = 'The network "%s" does not have an ip address '\
                          'defined so it cannot be used to mount network '\
                          'file systems.' % \
                          device[0].network_name
                    errors += cls._add_error(mount, msg)
                    cls.debug(msg)
                    continue

                if provider and (ip_version == 'ipv4' and \
                getattr(provider[0], 'ipv4address', None) is None) or \
                        (ip_version == 'ipv6' and getattr(
                                provider[0], 'ipv6address', None) is None):
                    msg = 'The nfs-service "%s" and network_name ' \
                          '"%s" are not compatible as they use ' \
                          'different IP protocols.' \
                          % (provider[0].name, device[0].network_name)
                    errors += cls._add_error(mount, msg)
                    cls.debug(msg)

        return errors

    @classmethod
    def _validate_sfs_mount_interface_has_ipv4_address(cls, api, node):
        """
        Validate that for an sfs related nfs-mount that the property
        network_name relates to an interface with property name that
        has a valid IP address
        """
        errors = []
        nfs_mounts = [m for m in node.query('nfs-mount')
                      if not m.is_for_removal()]

        for mount in nfs_mounts:
            device = [dev for dev in node.network_interfaces if
                      dev.network_name == mount.network_name
                      and not dev.is_for_removal()]
            provider = [prov for prov in api.query('sfs-virtual-server') if
                        prov.name == mount.provider
                        and not prov.is_for_removal()]
            if provider and device:
                if getattr(device[0], 'ipaddress') is None:
                    msg = 'The network "%s" does not have an IPv4 address '\
                          'defined so it cannot be used to mount network ' \
                          'file systems.' % \
                          device[0].network_name
                    errors += cls._add_error(mount, msg)
                    cls.debug(msg)
        return errors

    @staticmethod
    def _validate_nfs_mount_valid_providers(nodes, mounts, sfs_srvs, nfs_srvs):
        errors = []
        node_mounts = list(
            it.chain(*[
                [m for m in i.query('nfs-mount') if not m.is_for_removal]
                for i in nodes]))
        node_mounts_src = dict([(i.get_source().get_vpath(), i.get_source())
                                for i in node_mounts])
        nfs_mounts_orphans = [i for i in mounts if i.get_vpath()
                              not in node_mounts_src.keys() and
                              not i.is_for_removal()]
        for orphan in nfs_mounts_orphans:
            msg = "Checking orphan nfs-mount item '%s', ensuring it needs to "\
                "have a valid provider" % orphan.get_vpath()
            NasPlugin.debug(msg)
            errors += NasPlugin._get_nfs_mount_provider(sfs_srvs,
                                                        nfs_srvs, orphan)[-1]
        return errors

    @classmethod
    def _validate_nfs_mount_providers_updated(cls, mounts, sfs_srvs,
            nfs_srvs, plugin_api_context):
        '''Method validates that you cannot update the provider of an
           nfs-mount from an sfs-virtual-server to an nfs-service or vice
           versa and you cannot update from one nfs-service to another.
        '''
        errors = []
        for mount in mounts:
            if not mount.is_updated():
                continue
            old_provider = None
            new_provider = None
            current_provider = mount.provider
            applied_provider = \
                    mount.applied_properties.get('provider')
            virt_servers = \
                    plugin_api_context.query('sfs-virtual-server')
            was_virt_applied = False
            for virt in virt_servers:
                if applied_provider == virt.name:
                    was_virt_applied = True
                    break
            if current_provider is not None \
                    and applied_provider is not None \
                    and current_provider != applied_provider:
                for nfs in nfs_srvs:
                    if mount.provider == \
                            nfs.name and not was_virt_applied:
                        msg = 'The "provider" property of an "nfs-mount"' \
                                ' cannot be updated from an "%s"' \
                                ' to an "%s".'\
                                % (str(nfs.item_type_id),
                                        str(nfs.item_type_id))
                        errors += cls._add_error(mount, msg)
                        cls.debug(msg)
                    if nfs.applied_properties.get('name') \
                            == applied_provider:
                        old_provider = nfs
                    if mount.provider == nfs.name:
                        new_provider = nfs

                for sfs in sfs_srvs:
                    for sfs_virt in sfs.virtual_servers:
                        if sfs_virt.applied_properties.get('name') ==\
                                applied_provider:
                            old_provider = sfs_virt
                        if mount.provider == sfs_virt.name:
                            new_provider = sfs_virt

            if old_provider is not None and new_provider is not None \
                and old_provider.item_type != new_provider.item_type:
                msg = 'The "provider" property of an "nfs-mount"' \
                          ' cannot be updated from an "%s"' \
                          ' to an "%s".'\
                            % (str(old_provider.item_type_id),
                                    str(new_provider.item_type_id))
                errors += cls._add_error(mount, msg)
                cls.debug(msg)

        return errors

    @classmethod
    def _pool_not_relevant(cls, pool, model_validation):
        if model_validation:
            if pool.is_for_removal():
                return True
        else:
            #Snapshot validation
            if not pool.cache_objects:
                snap_fss = cls._get_snappable_filesystems(pool)
                if not snap_fss:
                    return True
        return False

    @classmethod
    def _validate_sfs_filesystem_cachename(cls, sfs_services,
                                           model_validation=True):
        """
        Validate that:
        1) Every snap file system's cache_name value references a cache
           in the model with the same value for its name property
        2) If a cache exists for an sfs-service, it must
           be referenced by at least one file system in that sfs-service.
        3) Every snap file system should reference one and only one cache
           item in the model.
        model_validation is True when we are validating model.
        - When validating model, a service or a pool is not relevant if they
          are marked for removal.
        model_validation is False when we are validating model_snapshot.
        - When validating model_snapshot, a pool is not relevant if it has
          no snap fss and no cache items.
        """
        errors = []

        for service in sfs_services:
            if model_validation and service.is_for_removal():
                continue

            file_systems, cache_objects, co_used = [], [], set()

            for pool in service.pools:
                if cls._pool_not_relevant(pool, model_validation):
                    continue

                fss_in_pool = [f for f in pool.file_systems
                               if f.cache_name is not None]

                if model_validation:
                    file_systems.extend([f for f in fss_in_pool
                                         if not f.is_for_removal()])
                    cache_objects.extend([c for c in pool.cache_objects
                                          if not c.is_for_removal()])
                else:
                    #Snapshot validation - include fss and cache objects
                    #that are for removal
                    file_systems.extend(fss_in_pool)
                    cache_objects.extend(pool.cache_objects)

            for f in file_systems:
                cache_object = next((c for c in cache_objects
                                     if c.name == f.cache_name), None)
                if cache_object:
                    co_used.add(cache_object.name)
                elif not model_validation and f.is_initial():
                    continue
                else:
                    msg = ('The "cache_name" property with value "%s" '
                           'does not reference '
                           'a defined sfs-cache item under any '
                           'sfs-pool for the sfs-service on path "%s".'
                           % (f.cache_name, service.get_vpath()))
                    cls.debug(msg)
                    errors += cls._add_error(f, msg)

            errors += cls._cache_used_by_one_filesystem(cache_objects,
                                                        co_used,
                                                        model_validation)
            errors += cls._all_snap_fss_reference_same_cache(cache_objects,
                                                             file_systems,
                                                             service,
                                                             model_validation)
        return errors

    @classmethod
    def _all_snap_fss_reference_same_cache(cls, cache_objects,
                                      file_systems, service, model_validation):
        errors = []
        if not model_validation:
            # it means snapshot_validation, so we only use applied or updated
            # file_systems to be checked on this validation, that's why the
            # filter below.
            file_systems = [f for f in file_systems if f.is_applied() or
                                                       f.is_updated()]
            if not file_systems:
                # if no file_systems after the filter above, the
                # create_snapshot shouldn't be prevented.
                return []
        if len(cache_objects) > 1:
            fss_with_diff_cache_name = [f for f in file_systems if
                            f.cache_name != file_systems[0].cache_name]
            if fss_with_diff_cache_name:
                msg = ('All file systems under every sfs-pool for '
                       'the sfs-service item '
                       'on path "%s" must have the same "cache_name" '
                       'property value.' % service.get_vpath())
                cls.debug(msg)
                errors += cls._add_error(service.pools, msg)
        return errors

    @classmethod
    def _cache_used_by_one_filesystem(cls, cache_objects,
                                      co_used,
                                      model_validation):
        errors = []

        if len(cache_objects) == 1:
            cache_not_used = cache_objects[0].name not in co_used
            if model_validation and cache_not_used:
                msg = 'The sfs-cache item requires a minimum of 1 '\
                      'sfs-filesystem item with a property ' \
                      '"cache_name" value "%s".' % cache_objects[0].name
                cls.debug(msg)
                errors += cls._add_error(cache_objects[0], msg)
        return errors

    @classmethod
    def _validate_only_one_cache_per_sfs(cls, sfs_services):
        """ Validate that not more than one cache exists per
            sfs-service
        """
        errors = []
        for service in [s for s in sfs_services if not s.is_for_removal()]:
            cache_objects = []
            reference_cache = None
            for pool in [p for p in service.pools if not p.is_for_removal()]:
                for co in pool.cache_objects:
                    if co.is_for_removal():
                        continue
                    if co.is_applied():
                        reference_cache = co
                    else:
                        cache_objects.append(co)
            # We need to make sure that cache that we will refer to is either
            # an existing one (applied) or if all caches are Initial state then
            # there is no difference which one we will refer in error.
            if not reference_cache and len(cache_objects) > 0:
                reference_cache = cache_objects.pop()
            for co in cache_objects:
                msg = 'Only one sfs-cache is allowed per sfs-service. ' \
                      'An sfs-cache with a "name" property value of "%s" ' \
                      'is already defined for the sfs-service on path "%s".'\
                      % (reference_cache.name, reference_cache.get_vpath())
                cls.debug(msg)
                errors += cls._add_error(co, msg)
        return errors

    @classmethod
    def _validate_unique_sfs_cache_name(cls, sfs_services):
        """ Validate that the sfs-cache name property must be unique
        across any given sfs-service item.
        NOTE: this is an implicit validation rule currently enforced by
        only one sfs-cache item is allowed per sfs-service. We included
        this validation here in the case we will remove the one sfs-cache
        object item restriction in the future.
        """
        errors, unique_sfsco_name = [], {}
        for service in [s for s in sfs_services if not s.is_for_removal()]:
            for pool in [p for p in service.pools if not p.is_for_removal()]:
                if not pool.cache_objects:
                    continue
                cache_objects = [co for co in pool.cache_objects
                                    if not co.is_for_removal()]
                for co in cache_objects:
                    if not unique_sfsco_name:
                        unique_sfsco_name[co.name] = co.get_vpath()
                    else:
                        if co.name in unique_sfsco_name:
                            msg = 'Value "%s" for property "name" is '\
                                  'already defined on sfs-cache item path: '\
                                  '"%s".' % (co.name,
                                             unique_sfsco_name[co.name])
                            cls.debug(msg)
                            errors += cls._add_error(co, msg)
                        else:
                            unique_sfsco_name[co.name] = co.get_vpath()
            unique_sfsco_name.clear()
        return errors

    @classmethod
    def _validate_sfs_cache_dependencies(cls, sfs_services):
        """ Validate that sfs-cache cannot be deleted if it is still used
        and referenced by any sfs-filesystem.
        """
        errors = []
        for service in [s for s in sfs_services if not s.is_for_removal()]:
            # retrieve the only sfs-cache object if it is defined
            # and marked for removal
            co_for_removal = None
            for pool in [p for p in service.pools if not p.is_for_removal()]:
                if not pool.cache_objects:
                    continue
                cache_objects = [co for co in pool.cache_objects
                                    if co.is_for_removal()]
                if cache_objects:
                    co_for_removal = cache_objects[0]
                    break

            # check any dependent file systems on the cache object
            if co_for_removal:
                for pool in [p for p in service.pools
                                if not p.is_for_removal()]:
                    file_systems = [fs for fs in pool.file_systems
                                        if not fs.is_for_removal()]
                    for fs in file_systems:
                        if has_property(fs, "cache_name") and\
                                (fs.cache_name == co_for_removal.name):
                            msg = 'sfs-cache with name "%s" is required by '\
                                  'the sfs-filesystem item on path "%s" to '\
                                  'create a snapshot and cannot be removed.' %\
                                  (co_for_removal.name, fs.get_vpath())
                            cls.debug(msg)
                            errors += cls._add_error(co_for_removal, msg)
        return errors

    MAX_SNAPSHOT_NAME_LENGTH = 7

    def _validate_snapshot_name(self, snapshot_name):
        """ Validate the maximum length of the snapshot name (tag), if
        specified, must be 7 characters.
        The rationale for this rule is described as follows:
        - The maximum length for the sfs file system name is 21
        - The maximum length for snapshot name is 31 in sfs
        - 3 characters taken as overload (L__)
        The snapshot name comprises of the above prefix, sfs file system name,
        MAX_SNAPSHOT_NAME_LENGTH + 3 + 21 = 31, therefore
        MAX_SNAPSHOT_NAME_LENGTH = 7
        - Also validate that underscore "_" is not a valid character.
        """
        errors = []
        # TODO: currently we hard code maximum length to be 7 characters,
        # we should really externalize into a variable or something.

        if len(snapshot_name) > self.MAX_SNAPSHOT_NAME_LENGTH:
            msg = 'Snapshot name tag cannot exceed %s characters '\
                            'which is the maximum available length '\
                            'for a NAS file system.'\
                             % self.MAX_SNAPSHOT_NAME_LENGTH

            error = ValidationError(error_message=msg)
            errors.append(error)
        if '_' in snapshot_name:
            msg = 'The snapshot "name" cannot include underscores.'
            error = ValidationError(error_message=msg)
            errors.append(error)
        return errors

    @classmethod
    def _validate_sfs_cache_snapsize(cls, sfs_services):
        """ Validate that for veritas sfs_services, snap_size and cache_name
        for sfs-filesystem

        Ensures that both 'snap_size' and 'cache_name' properties
        must be present or neither, when creating an 'sfs-filesystem' item.
        """
        errors = []
        xor = lambda a, b: bool(a) ^ bool(b)
        msg = 'Either both "snap_size" and "cache_name" '\
            'properties or neither must be defined when creating '\
            'an "sfs-filesystem" item.'
        for service in [s for s in sfs_services if not s.is_for_removal()]:
            if NasPlugin._get_sfs_nas_type(service) == "unityxt":
                continue
            # retrieve the only sfs-cache object if it is defined
            # and marked for removal
            for pool in [p for p in service.pools if not p.is_for_removal()]:
                file_systems = [fs for fs in pool.file_systems
                                    if not fs.is_for_removal()]
                for fs in file_systems:
                    has_cache_name = has_property(fs, "cache_name")
                    has_snap_size = has_property(fs, "snap_size")
                    if xor(has_cache_name, has_snap_size):
                        errors += cls._add_error(fs, msg)

        return errors

    def create_configuration(self, plugin_api_context):
        """
        The NAS plugin can be used for the following tasks:

        - Create file systems on NAS servers.

        - Create exports on NAS servers.

        - Mount and unmount exports from NAS and non-NAS servers.



        *Example CLI for mounting a NAS unmanaged export:*

        .. code-block:: bash

            litp create -t sfs-service -p /infrastructure/storage\
/storage_providers/sp1 -o name='sfs1'
            litp create -t sfs-virtual-server -p /infrastructure/storage\
/storage_providers/sp1/virtual_servers/vs1 -o name='vsvr1' \
ipv4address='10.44.86.242'
            litp create -t nfs-mount -p /infrastructure/storage/nfs_mounts/\
nm1 -o export_path='/vx/abcde-fs1' provider='vsvr1' \
network_name='storage' mount_point='/cluster' mount_options='soft'
            litp inherit -p /deployments/local/clusters/\
cluster1/nodes/node1/file_systems/nm1 -s /infrastructure/storage/\
nfs_mounts/nm1


        *Example CLI for mounting a non-NAS unmanaged export:*

        .. code-block:: bash

            litp create -t nfs-service -p /infrastructure/storage\
/storage_providers/sp2 -o name='nfs1' ipv4address='10.44.86.242' \
ipv6address="aa:bb:01::"
            litp create -t nfs-mount -p /infrastructure/storage/nfs_mounts/\
nm2 -o export_path='/abc' provider='nfs1' network_name='storage' \
mount_point='/cluster' mount_options="soft"
            litp inherit -p /deployments/local/clusters/\
cluster1/nodes/node1/file_systems/nm2 -s /infrastructure/storage/\
nfs_mounts/nm2


        *Example CLI for creating a file system, managed export \
                and mounting:*

        .. code-block:: bash

            litpcrypt set key-for-sfs support mypasswd
            litp create -t sfs-service -p /infrastructure/storage\
/storage_providers/sfs_service -o name='sfs1' user_name='support' \
password_key='key-for-sfs' management_ipv4='10.44.86.236'
            litp create -t sfs-virtual-server -p /infrastructure/storage\
/storage_providers/sp1/virtual_servers/vs1 -o name='vsvr1' \
ipv4address='10.44.86.242'
            litp create -t sfs-pool -p /infrastructure/storage\
/storage_providers/sfs_service/pools/pool1 -o name='pool1'
            litp create -t sfs-filesystem -p /infrastructure/storage\
/storage_providers/sfs_service/pools/pool1/file_systems/fs1 -o \
path='/vx/foobar' size='1G'
            litp create -t sfs-export -p /infrastructure/storage/\
storage_providers/sfs_service/pools/pool1/file_systems/fs1/exports/ex1 -o \
ipv4allowed_clients='10.44.86.122' export_options='rw,no_root_squash'
            litp create -t nfs-mount -p /infrastructure/storage/nfs_mounts/\
nm1 -o export_path='/vx/foobar' provider='vsvr1' network_name='storage' \
mount_point='/cluster' mount_options='soft'
            litp inherit -p /deployments/local/clusters/\
cluster1/nodes/node1/file_systems/nm1 -s /infrastructure/storage/\
nfs_mounts/nm1

        *Example CLI for updating an export:*

        .. code-block:: bash

            litp update -p /infrastructure/storage/\
storage_providers/sfs_service/pools/pool1/file_systems/fs1/exports/ex1 -o \
ipv4allowed_clients='10.44.86.122,10.44.86.123'

        *Example CLI for creating an export with subnet and ip address:*

        .. code-block:: bash

            litp create -t sfs-export -p /infrastructure/storage/\
storage_providers/sfs_service/pools/pool1/file_systems/fs1/exports/ex2 -o \
ipv4allowed_clients='10.44.86.0/24,10.10.10.10' \
export_options='rw,no_root_squash'


        *Example CLI for creating a file system of which \
snapshots can be taken. Note cache is configured during snapshot plan:*

        .. code-block:: bash

            litpcrypt set key-for-sfs support mypasswd
            litp create -t sfs-service -p /infrastructure/storage\
/storage_providers/sfs_service -o name='sfs1' user_name='support' \
password_key='key-for-sfs' management_ipv4='10.44.86.236'
            litp create -t sfs-pool -p /infrastructure/storage\
/storage_providers/sfs_service/pools/pool1 -o name='pool1'
            litp create -t sfs-cache -p /infrastructure/storage/\
storage_providers/sfs_service/pools/pool1/cache_objects/cache1\
 -o name='mycache'
            litp create -t sfs-filesystem -p /infrastructure/storage\
/storage_providers/sfs_service/pools/pool1/file_systems/fs1 -o \
path='/vx/foobar' size='1G' cache_name='mycache' snap_size=20


        *Example CLI for creating a file system of which \
snapshots can be taken where the file system and cache reside in \
different pools. Note cache is configured during snapshot plan:*

        .. code-block:: bash

            litpcrypt set key-for-sfs support mypasswd
            litp create -t sfs-service -p /infrastructure/storage\
/storage_providers/sfs_service -o name='sfs1' user_name='support' \
password_key='key-for-sfs' management_ipv4='10.44.86.236'
            litp create -t sfs-pool -p /infrastructure/storage\
/storage_providers/sfs_service/pools/pool1 -o name='pool1'
            litp create -t sfs-pool -p /infrastructure/storage\
/storage_providers/sfs_service/pools/pool2 -o name='pool2'
            litp create -t sfs-cache -p /infrastructure/storage/\
storage_providers/sfs_service/pools/pool1/cache_objects/cache1\
 -o name='mycache'
            litp create -t sfs-filesystem -p /infrastructure/storage\
/storage_providers/sfs_service/pools/pool2/file_systems/fs1 -o \
path='/vx/foobar' size='1G' cache_name='mycache' snap_size=20


        *Example CLI for increasing the size of the space allocated \
in a cache for a file system from 20 to 30 percent. Note cache resize \
occurs during a snapshot plan:*

        .. code-block:: bash

            litp update -p /infrastructure/storage\
/storage_providers/sfs_service/pools/pool1/file_systems/fs1 -o \
snap_size=30


        *Example of XML for mounting two exports. One \
from a NAS server and the other from a non-NAS server:*

        .. code-block:: xml

            <?xml version='1.0' encoding='utf-8'?>
            <litp:root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" \
xmlns:litp="http://www.ericsson.com/litp" \
xsi:schemaLocation="http://www.ericsson.com/litp litp-xml-schema/litp.xsd" \
id="root">
                <litp:storage-storage_providers-collection \
id="storage_providers">
                  <litp:sfs-service id="sp1">
                    <name>sfs1</name>
                    <litp:sfs-service-exports-collection id="exports"/>
                    <litp:sfs-service-virtual_servers-collection \
id="virtual_servers">
                      <litp:sfs-virtual-server id="vs1">
                        <ipv4address>10.10.10.10</ipv4address>
                        <name>vsvr1</name>
                      </litp:sfs-virtual-server>
                    </litp:sfs-service-virtual_servers-collection>
                   </litp:sfs-service>
                   <litp:nfs-service id="sp2">
                     <ipv4address>10.10.10.11</ipv4address>
                     <name>nfs1</name>
                   </litp:nfs-service>
                 </litp:storage-storage_providers-collection>
                 <litp:storage-nfs_mounts-collection id="nfs_mounts">
                   <litp:nfs-mount id="nm1">
                     <export_path>/vx/abcde-fs1</export_path>
                     <mount_options>soft</mount_options>
                     <mount_point>/tmp1</mount_point>
                     <network_name>storage</network_name>
                     <provider>vsvr1</provider>
                   </litp:nfs-mount>
                   <litp:nfs-mount id="nm2">
                     <export_path>/exports/xyz-fs1</export_path>
                     <mount_options>soft</mount_options>
                     <mount_point>/cluster</mount_point>
                     <network_name>storage</network_name>
                     <provider>nfs1</provider>
                   </litp:nfs-mount>
                 </litp:storage-nfs_mounts-collection>
                 <litp:node id="node1">
                   <hostname>node1</hostname>
                   <node_id>1</node_id>
                   <litp:node-file_systems-collection id="file_systems">
                     <litp:nfs-mount-inherit source_path="/infrastructure/\
storage/nfs_mounts/nm1" id="nm1"/>
                   </litp:node-file_systems-collection>
                 </litp:node>
                 <litp:node id="node2">
                   <hostname>node2</hostname>
                   <node_id>2</node_id>
                   <litp:node-file_systems-collection id="file_systems">
                     <litp:nfs-mount-inherit source_path="/infrastructure/\
storage/nfs_mounts/nm2" id="nm1"/>
                   </litp:node-file_systems-collection>
                 </litp:node>
            </litp:root>


        *An example of XML for creating two file systems both with\
        one export on a NAS server:*

        .. code-block:: xml

            <?xml version='1.0' encoding='utf-8'?>
             <litp:sfs-service xmlns:xsi="http://www.w3.org/2001/\
XMLSchema-instance" xmlns:litp="http://www.ericsson.com/litp"\
xsi:schemaLocation="http://www.ericsson.com/litp litp-xml-schema/\
litp.xsd" id="sfs1">
              <management_ipv4>172.16.30.17<!--note: this\
property is not updatable--></management_ipv4>
              <password_key>key-for-sfs</password_key>
              <user_name>support</user_name>
              <litp:sfs-service-pools-collection id="pools">
                <litp:sfs-pool id="pool1">
                  <name>litp2<!--note: this property is not updatable \
--></name>
                  <litp:sfs-pool-file_systems-collection id=\
"file_systems">
                    <litp:sfs-filesystem id="fs1">
                      <path>/vx/fooBar<!--note: this property is not\
updatable--></path>
                      <size>10M</size>
                      <litp:sfs-filesystem-exports-collection id=\
"exports">
                        <litp:sfs-export id="ex1">
                          <ipv4allowed_clients>192.168.0.42,\
192.168.0.43,192.168.0.44,192.168.0.45,192.168.0.46</ipv4allowed_clients>
                          <options>rw,no_root_squash</options>
                        </litp:sfs-export>
                      </litp:sfs-filesystem-exports-collection>
                    </litp:sfs-filesystem>
                    <litp:sfs-filesystem id="fs2">
                      <path>/vx/Barfoo<!--note: this property is not \
updatable--></path>
                      <size>10M</size>
                      <litp:sfs-filesystem-exports-collection \
id="exports">
                        <litp:sfs-export id="ex1">
                          <ipv4allowed_clients>192.168.0.42,\
192.168.0.43,192.168.0.44,192.168.0.45,192.168.0.46</ipv4allowed_clients>
                          <options>rw,no_root_squash</options>
                        </litp:sfs-export>
                      </litp:sfs-filesystem-exports-collection>
                    </litp:sfs-filesystem>
                  </litp:sfs-pool-file_systems-collection>
                </litp:sfs-pool>
              </litp:sfs-service-pools-collection>
              <litp:sfs-service-virtual_servers-collection \
id="virtual_servers">
                <litp:sfs-virtual-server id="vs1">
                  <ipv4address>172.16.30.17<!--note: this \
property is not updatable--></ipv4address>
                  <name>vs1<!--note: this property is not \
updatable--></name>
                </litp:sfs-virtual-server>
              </litp:sfs-service-virtual_servers-collection>
             </litp:sfs-service>


        *An example of XML for two file systems
        that have snapshot related properties defined:*

        .. code-block:: xml

            <?xml version='1.0' encoding='utf-8'?>
            <litp:sfs-service xmlns:xsi="http://www.w3.org/2001\
/XMLSchema-instance" xmlns:litp="http://www.ericsson.com/litp" \
xsi:schemaLocation="http://www.ericsson.com/litp \
litp-xml-schema/litp.xsd" id="sfs1">"
              <management_ipv4>172.16.30.17<!--note: this\
 property is not updatable--></management_ipv4>
              <name>sfs1<!--note: this property is not \
updatable--></name>
              <password_key>key-for-sfs</password_key>
              <user_name>support</user_name>
              <litp:sfs-service-pools-collection id="pools">
                <litp:sfs-pool id="pool1">
                  <name>litp2<!--note: this property is not \
updatable--></name>
                  <litp:sfs-pool-cache_objects-collection \
id="cache_objects">
                    <litp:sfs-cache id="cache1">
                      <name>mycache<!--note: this property \
is not updatable--></name>
                    </litp:sfs-cache>
                  </litp:sfs-pool-cache_objects-collection>
                  <litp:sfs-pool-file_systems-collection id=\
"file_systems">
                    <litp:sfs-filesystem id="fs1">
                      <cache_name>mycache</cache_name>
                      <path>/vx/fooBar<!--note: this property \
is not updatable--></path>
                      <size>10M</size>
                      <snap_size>30</snap_size>
                      <litp:sfs-filesystem-exports-collection \
id="exports"/>
                    </litp:sfs-filesystem>
                    <litp:sfs-filesystem id="fs2">
                      <cache_name>mycache</cache_name>
                      <path>/vx/Barfoo<!--note: this property is \
not updatable--></path>
                      <size>10M</size>
                      <snap_size>30</snap_size>
                      <litp:sfs-filesystem-exports-collection \
id="exports"/>
                    </litp:sfs-filesystem>
                  </litp:sfs-pool-file_systems-collection>
                </litp:sfs-pool>
              </litp:sfs-service-pools-collection>
            </litp:sfs-service>


        *An example of XML for two pools that have file systems
        that have snapshot related properties defined:*

        .. code-block:: xml

            <?xml version='1.0' encoding='utf-8'?>
            <litp:sfs-service xmlns:xsi="http://www.w3.org/2001\
/XMLSchema-instance" xmlns:litp="http://www.ericsson.com/litp" \
xsi:schemaLocation="http://www.ericsson.com/litp \
litp-xml-schema/litp.xsd" id="sfs1">
             <management_ipv4>172.16.30.17<!--note: this \
property is not updatable--></management_ipv4>
             <name>sfs1<!--note: this property is not \
updatable--></name>
             <password_key>key-for-sfs</password_key>
             <user_name>support</user_name>
             <litp:sfs-service-pools-collection id="pools">
               <litp:sfs-pool id="sfs_pool1">
                 <name>SFS_Pool<!--note: this property is not \
updatable--></name>
                 <litp:sfs-pool-cache_objects-collection \
id="cache_objects">
                   <litp:sfs-cache id="pl1_cache1">
                      <name>pl1_cache1<!--note: this property \
is not updatable--></name>
                   </litp:sfs-cache>
                 </litp:sfs-pool-cache_objects-collection>
                 <litp:sfs-pool-file_systems-collection id=\
"file_systems">
                   <litp:sfs-filesystem id="pl1_fs1">
                     <cache_name>pl1_cache1</cache_name>
                     <path>/vx/pl1_fs1<!--note: this property \
is not updatable--></path>
                     <size>1G</size>
                     <snap_size>40</snap_size>
                     <litp:sfs-filesystem-exports-collection \
id="exports"/>
                   </litp:sfs-filesystem>
                 </litp:sfs-pool-file_systems-collection>
               </litp:sfs-pool>
               <litp:sfs-pool id="sfs_pool2">
                 <name>SFS_Pool2<!--note: this property is \
not updatable--></name>
                 <litp:sfs-pool-cache_objects-collection \
id="cache_objects"/>
                  <litp:sfs-pool-file_systems-collection id=\
"file_systems">
                    <litp:sfs-filesystem id="pl2_fs2">
                      <cache_name>pl1_cache1</cache_name>
                      <path>/vx/pl2_fs2<!--note: this property \
is not updatable--></path>
                      <size>1G</size>
                      <snap_size>40</snap_size>
                      <litp:sfs-filesystem-exports-collection \
id="exports"/>
                    </litp:sfs-filesystem>
                  </litp:sfs-pool-file_systems-collection>
                </litp:sfs-pool>
              </litp:sfs-service-pools-collection>
            </litp:sfs-service>



        For more information, see `NAS Storage Management \
<https://arm1s11-eiffel004.eiffel.gic.ericsson.se:8443/nexus/\
content/sites/litp2/ERIClitpdocs/latest/\
litp_references.html#litp-references>`_ |external|.
        """
        # return []
        # create_server_tasks means actually just for managed NFS
        api = plugin_api_context
        # below will generate NAS server tasks
        tasks = self.generate_nasserver_tasks(api)
        tasks += self.create_server_tasks(api, 'sfs-service')
        # below will do the mounts for either managed or unmanaged NFS
        tasks += self.create_client_tasks(api, tasks)
        # below will generate the prior tasks to get and save host keys
        tasks += self.generate_get_and_save_remote_host_key_tasks(api, tasks)
        return tasks

    def generate_get_and_save_remote_host_key_tasks(self, api, tasks,
                                                    tag=None):
        """ Returns a list of tasks per sfs-service to collect the remote
        host key from the NAS heads VIPs and save to the ~/.ssh/known_hosts
        file for the service management ipv4.
        """
        description = 'Checking remote host keys exist for sfs-service "%s"'
        callback = self.get_and_save_remote_host_key_callback
        nas_cb_tasks = [t for t in tasks
                          if getattr(t, 'is_nas_callback_task', False)]
        if not nas_cb_tasks:
            return []
        remote_host_key_tasks = []
        cb_tasks_per_service = defaultdict(list)
        for nas_cb_task in nas_cb_tasks:
            key = nas_cb_task.kwargs['sfs_service_vpath']
            cb_tasks_per_service[key].append(nas_cb_task)
        for sfs_service_vpath, tasks in cb_tasks_per_service.items():
            sfs_service = api.query_by_vpath(sfs_service_vpath)

            if NasPlugin._get_sfs_nas_type(sfs_service) == 'veritas':
                desc = description % sfs_service.name
                check_host_key = CallbackTask(
                    sfs_service, desc, callback,
                    sfs_service_vpath=sfs_service_vpath,
                    tag_name=tag
                )
                for task in tasks:
                    task.requires.add(check_host_key)
                remote_host_key_tasks.append(check_host_key)
        return remote_host_key_tasks

    def get_and_save_remote_host_key_callback(self, api, sfs_service_vpath):
        """ Uses naslib.ssh.SSHClient to get the remote host key from the
        NAS heads VIPs and save them locally in MS in the ~/.ssh/known_hosts
        file for the service management ipv4.
        """
        service = api.query_by_vpath(sfs_service_vpath)
        mgmt_ipv4 = service.management_ipv4
        try:
            local_keys = SSHClient.get_known_hosts_keys().get(mgmt_ipv4, {})
        except IOError:
            local_keys = {}
        for virtual_server in service.virtual_servers:
            vip = virtual_server.ipv4address
            try:
                remote_key = SSHClient.get_remote_host_key(vip)
            except NasException as err:
                exc = sys.exc_info()
                raise CallbackExecutionException(str(err)), None, exc[2]
            already_in = False
            for key_set in local_keys.values():
                base_64_keys = [k.get_base64() for k in key_set]
                if remote_key.get_base64() in base_64_keys:
                    already_in = True
                    break
            if not already_in:
                # ** saves the key for the service management_ipv4 **
                SSHClient.save_host_key(mgmt_ipv4, remote_key)

    def remount(self, context, interface,
                nfs_mount, node, cb_dict):
        node_desc = '"%s" on node "%s"' % (
                                         nfs_mount.export_path, node.hostname)
        description = 'Remount ' + node_desc
        mount_options = OptionsParser(nfs_mount.mount_options)
        client_option = "clientaddr"
        update_ip_task = None
        if (client_option in mount_options
                and mount_options[client_option] is not None):
            if netaddr.valid_ipv4(
                    mount_options[client_option],
                    netaddr.INET_PTON):
                new_address = interface.ipaddress
            else:
                new_address = interface.ipv6address
            if mount_options[client_option] != new_address:
                mount_options[client_option] = new_address
                update_ip_task = CallbackTask(
                    nfs_mount,
                    'Update "%s" option to "%s"' %
                    (client_option, new_address),
                    self.update_clientaddr_option_callback,
                    node_vpath=node.get_vpath(),
                    nfs_vpath=nfs_mount.get_vpath(),
                    new_options=str(mount_options))
        remount_task = self.generate_nfs_task(
                                              context, description,
                                              PuppetMountStatus.REMOUNT,
                                              str(mount_options),
                                              cb_dict, nfs_mount, node)
        remount_task.model_items.add(interface)
        return update_ip_task, remount_task

    def generate_nfs_task(self, context, desc,
                          mount_status, mount_options,
                          cb_dict, nfs_mount, node):
        ipv4, ipv6 = self._find_provider_ip(nfs_mount, context)
        ip_address = ipv4 or ipv6
        task = ConfigTask(node, nfs_mount, desc,
                          call_type='nas::config',
                          call_id=nfs_mount.get_vpath(),
                          mount_point=nfs_mount.mount_point,
                          mount_status=mount_status,
                          path=ip_address + ':' + nfs_mount.export_path,
                          mount_options=mount_options)
        if task.node.is_ms():
            path = task.model_item.export_path
            provider = task.model_item.provider
            cb_task = cb_dict.get(provider, {}).get(path)
            if cb_task:
                task.requires.add(cb_task)
        return task

    def _generate_nfs_tasks(
                            self, context, cb_dict, nfs_mount, node):
        nfs_tasks = []
        self.debug('Query node "%s" for nfs-mount items' %
                    nfs_mount.get_vpath())
        node_desc = '"%s" on node "%s"' % (
            nfs_mount.export_path, node.hostname)

        reboot_node = False
        if nfs_mount.is_initial():
            if not self._is_dual_stack(context, node, nfs_mount):
                desc = 'Mount share ' + node_desc
                mount_task = self.generate_nfs_task(
                                                   context, desc,
                                                   PuppetMountStatus.MOUNT,
                                                   nfs_mount.mount_options,
                                                   cb_dict, nfs_mount, node)
                nfs_tasks.append(mount_task)
            else:
                desc = 'Mount share ' + node_desc
                dual_mount_task = self._dual_mount_callback(
                        context, nfs_mount, node)
                nfs_tasks.append(dual_mount_task)

                path = FuturePropertyValue(nfs_mount, "device_path")
                mount_task = ConfigTask(
                    node, nfs_mount, desc,
                    call_type='nas::config', call_id=nfs_mount.get_vpath(),
                    mount_point=nfs_mount.mount_point,
                    mount_status=PuppetMountStatus.MOUNT,
                    path=path,
                    mount_options=nfs_mount.mount_options,
                )
                if dual_mount_task:
                    mount_task.requires = set([dual_mount_task])
                    nfs_tasks.append(mount_task)
        elif nfs_mount.is_for_removal():
            desc = 'Unmount ' + node_desc
            unmount_task = self.generate_nfs_task(
                                                 context, desc,
                                                 PuppetMountStatus.UMOUNT,
                                                 nfs_mount.mount_options,
                                                 cb_dict, nfs_mount, node)
            nfs_tasks.append(unmount_task)
        elif nfs_mount.is_updated():
            remount_task = None
            update_ip_task = None
            # can only have at max 1 interface per network_name
            mounted_interfaces = [i for i in node.network_interfaces
                                  if i.network_name == nfs_mount.network_name]

            networking_change = nfs_mount.applied_properties['network_name'] \
            != nfs_mount.properties['network_name'] or \
                self.interface_ip_changed(node, nfs_mount)
            if networking_change and mounted_interfaces:
                interface = mounted_interfaces[0]
                update_ip_task, remount_task = self.remount(
                                               context,
                                               interface, nfs_mount,
                                               node, cb_dict)
                # don't create reboot task for MS
                if not node.is_ms() and self.interface_ip_changed(
                        node, nfs_mount):
                    reboot_node = True
                elif not node.is_ms():
                    source = nfs_mount._model_item.source
                    appl = source.get_applied_properties().get('network_name')
                    source_network_name = source.properties['network_name']
                    if appl is not None and appl != source_network_name:
                        reboot_node = True
                    item = nfs_mount._model_item
                    appl = item.get_applied_properties().get('network_name')
                    item_network_name = item.properties.get('network_name')
                    if appl is not None and appl != item_network_name:
                        reboot_node = True

            # Updated provider on mount, sfs-virtual-server only
            nfs_mount_item = nfs_mount._model_item
            applied_provider = \
                    nfs_mount_item.get_applied_properties().get('provider')
            updated_provider = nfs_mount.provider
            if applied_provider is not None and \
                    updated_provider is not None and \
                applied_provider != updated_provider:

                mount_options = None
                # if IP is updated then we need the new clientaddr value
                # needs to be refactored.
                if remount_task:
                    mount_options = remount_task.kwargs['mount_options']
                else:
                    mount_options = nfs_mount.mount_options
                remount_task_prov = self.generate_nfs_task_provider_updated(
                        node, node_desc, nfs_mount, mount_options,
                        context)
                path = remount_task_prov.model_item.export_path
                provider = remount_task_prov.model_item.provider
                cb_task = cb_dict.get(provider, {}).get(path)
                if cb_task and node.is_ms():
                    remount_task_prov.requires.add(cb_task)
                nfs_tasks.append(remount_task_prov)
                if update_ip_task:
                    nfs_tasks.append(update_ip_task)
                    update_ip_task.requires.add(remount_task_prov)
            elif update_ip_task and remount_task:
                nfs_tasks.append(remount_task)
                nfs_tasks.append(update_ip_task)
                update_ip_task.requires.add(remount_task)

        elif nfs_mount.is_applied():
            if node.is_ms():
                path = nfs_mount.export_path
                provider = nfs_mount.provider
                cb_task = cb_dict.get(provider, {}).get(path)
                # If prepare_restore sets cb_tasks back to initial
                # on MS nfs-mounts will still be applied we must
                # recreate the mount task and add the dependency of the
                # callback task to it.
                if cb_task:
                    reboot_node = False
                    desc = 'Mount share ' + node_desc
                    mount_task = self.generate_nfs_task(
                                                   context, desc,
                                                   PuppetMountStatus.MOUNT,
                                                   nfs_mount.mount_options,
                                                   cb_dict, nfs_mount, node)
                    nfs_tasks.append(mount_task)
            else:
                for interface in node.network_interfaces:
                    if (interface.network_name == nfs_mount.network_name and
                        self.interface_ip_changed(node, nfs_mount)
                        # LITPCDS-9806
                            and (not node.get_cluster().is_initial())):
                        reboot_node = True
                        update_ip_task, remount_task = self.remount(
                                                      context,
                                                      interface, nfs_mount,
                                                       node, cb_dict)
                        if update_ip_task:
                            nfs_tasks.append(update_ip_task)
                            update_ip_task.requires.add(remount_task)
                        if 'clientaddr' in \
                                remount_task.kwargs['mount_options']:
                            nfs_tasks.append(remount_task)

        return nfs_tasks, reboot_node

    # LITPCDS-9665
    # LITPCDS-10588
    def interface_ip_changed(self, node, mount):
        network_name = mount.network_name
        interfaces = node.query(
            'network-interface', network_name=network_name)
        interface = next(
            (i for i in interfaces if i.network_name == network_name),
            None)
        ipv6 = False
        if (interface.ipaddress is not None
            and interface.ipv6address is not None):
            if mount.device_path is not None:
                ipaddress = mount.device_path.split(":")[0]
                if not netaddr.valid_ipv4(
                        ipaddress,
                        netaddr.INET_PTON):
                    ipv6 = True
        else:
            ipv6 = interface.ipv6address is not None

        def get_ip_field(interface):
            return getattr(
                interface, 'ipv6address' if ipv6 else 'ipaddress')

        def get_applied_ip_field(interface):
            return interface.applied_properties.get(
                'ipv6address' if ipv6 else 'ipaddress')

        old_interface = next(
            (i for i in node.query('network-interface')
             if not i.is_initial()
             and i.applied_properties.get('network_name') == network_name),
            None)

        if old_interface is None:
            return False
        return get_ip_field(interface) != get_applied_ip_field(
            old_interface)

    def generate_nfs_task_provider_updated(self, node, node_desc,
            nfs_mount, mount_options, plugin_api_context):
        updated_provider_ip = self._find_provider_updated_ip(nfs_mount,
                plugin_api_context)
        mount_status = PuppetMountStatus.REMOUNT
        description = 'Remount ' + node_desc
        task = ConfigTask(node, nfs_mount, description,
                      call_type='nas::config',
                      call_id=nfs_mount.get_vpath(),
                      mount_point=nfs_mount.mount_point,
                      mount_status=mount_status,
                      path=updated_provider_ip + ':' + \
                              nfs_mount.export_path,
                      mount_options=mount_options)
        return task

    def _gen_reboot_task(self, node):
        return CallbackTask(
                node,
                'Reboot node "%s"' % node.hostname,
                self._reboot_node_and_wait,
                hostname=node.hostname,
                )

    def _reboot_node_and_wait(self, callback_api, hostname):
        self._execute_rpc_in_callback_task(
                callback_api, [hostname], "core", "reboot")
        time_at_reboot = time.time()
        wait_for_node_down(callback_api, [hostname], True)
        wait_for_node_timestamp(callback_api, [hostname], time_at_reboot, True)
        PuppetMcoProcessor().enable_puppet([hostname])
        wait_for_node(callback_api, [hostname], True)

    def _execute_rpc_in_callback_task(self, cb_api, nodes, agent, action,
            action_kwargs=None, timeout=30):
        try:
            # LITPCDS-11664 must retry as intermittently mco call
            # is not received by node following IP update, seen
            # more frequent on bridged interfaces.
            bcp = BaseRpcCommandProcessor()
            _, errors = bcp.execute_rpc_and_process_result(
                    cb_api, nodes, agent, action,
                    action_kwargs, timeout, retries=5)
        except RpcExecutionException as e:
            raise CallbackExecutionException(e)
        if errors:
            raise CallbackExecutionException(','.join(errors))

    def _dual_mount_callback(self, plugin_api_context, nfs_mount, node):
        ipv4, ipv6 = self._find_provider_ip(nfs_mount,
                plugin_api_context)

        dual_mount_attempt_task = CallbackTask(
                    nfs_mount,
                    'Verify ipv4/ipv6 interface to mount "%s"' % \
                    nfs_mount.export_path,
                    self.attempt_dual_stack_mount,
                    node_hostname=node.hostname,
                    ipv4=ipv4,
                    ipv6=ipv6,
                    export_path=nfs_mount.export_path,
                    mount_point=nfs_mount.mount_point,
                    node_vpath=node.get_vpath(),
                    nfs_vpath=nfs_mount.get_vpath(),
                    )
        return dual_mount_attempt_task

    def attempt_dual_stack_mount(self, callback_api, node_hostname,
                                                ipv4, ipv6, export_path,
                                                mount_point, node_vpath,
                                                nfs_vpath):
        # core rpc command expects a list of nodes
        # we only want to execute on one
        nodes = []
        nodes.append(node_hostname)
        mcoll = NasCmdApi(nodes)
        kwargs = mcoll.get_kwargs(ipv4, ipv6, export_path, mount_point)
        device_path = None
        try:
            mcoll.mount_ipv4(kwargs)
            device_path = ipv4 + ':' + export_path
        except NasCmdApiException, err:
            self.debug(str(err))
            try:
                mcoll.mount_ipv6(kwargs)
                device_path = ipv6 + ':' + export_path
            except NasCmdApiException, err:
                self.debug(str(err))
                raise CallbackExecutionException("Unable to mount: %s" % err)
        try:
            mcoll.unmount(kwargs)
        except NasCmdApiException, err:
            self.debug(str(err))
        ms = callback_api.query('ms')
        nodes = callback_api.query('node')
        all_nodes = ms + nodes
        node = next(node for node in all_nodes
                    if node.get_vpath() == node_vpath)
        nfs_mounts = node.query('nfs-mount')
        nfs_mount = next(mount for mount in nfs_mounts
                         if mount.get_vpath() == nfs_vpath)
        if device_path is not None:
            self.debug('Updating device_path of %s to "%s"' %
                       (nfs_mount.get_vpath(), device_path))
            nfs_mount.device_path = device_path

    def callback_tasks_by_export_path(self, cb_tasks):
        cb_dict = dict()
        for cb_task in cb_tasks:
            # gets only share callback tasks.
            if cb_task.callback != self.nfs_shares_creation_callback:
                continue
            file_system = cb_task.model_item.parent.parent
            service = file_system.parent.parent.parent.parent
            for virtual_server in service.virtual_servers:
                cb_dict.setdefault(virtual_server.name, {})
                cb_dict[virtual_server.name][file_system.path] = cb_task
        return cb_dict

    def create_client_tasks(self, plugin_api_context, cb_tasks):
        """ This method builds a list of ConfigTasks related to the mounts in
        the clients for either managed or unmanaged NFS.
        """
        tasks = []
        cb_dict = self.callback_tasks_by_export_path(cb_tasks)
        ms = plugin_api_context.query('ms')
        nodes = plugin_api_context.query('node')
        all_nodes = ms + nodes
        for node in all_nodes:
            node_tasks = []
            msg = 'Examining Node "%s"' % node.get_vpath()
            self.debug(msg)
            reboot_node = False
            for nfs in node.query('nfs-mount'):
                nfs_tasks, reboot_for_node = self._generate_nfs_tasks(
                    plugin_api_context, cb_dict, nfs, node)
                reboot_node = reboot_for_node or reboot_node
                node_tasks.extend(nfs_tasks)

            if reboot_node:
                reboot_task = self._gen_reboot_task(node)
                for task in node_tasks:
                    task.requires.add(reboot_task)
                node_tasks.append(reboot_task)
            tasks.extend(node_tasks)
        return tasks

    def update_clientaddr_option_callback(self, callback_api,
                                          node_vpath, nfs_vpath, new_options):
        ms = callback_api.query('ms')
        nodes = callback_api.query('node')
        all_nodes = ms + nodes
        node = next(node for node in all_nodes
                    if node.get_vpath() == node_vpath)
        nfs_mounts = node.query('nfs-mount')
        nfs_mount = next(mount for mount in nfs_mounts
                         if mount.get_vpath() == nfs_vpath)
        nfs_mount.mount_options = new_options

    @classmethod
    def _find_provider_ip(cls, nfs_mount, plugin_api_context):
        """
        Utility method returns tuple of ipaddress and ipv6address of
        the nfs-service if the mount interface is dual stack
        """
        virtual_servers = plugin_api_context.query('sfs-virtual-server')
        nfs_services = plugin_api_context.query('nfs-service')
        all_providers = virtual_servers + nfs_services
        ipv6_address = [s.ipv6address for s in all_providers
                if hasattr(s, 'ipv6address') and \
                        s.ipv6address and s.name == nfs_mount.provider]

        msg = 'Searching for ipv6address for nfs-mount "%s"' \
                ' amongst providers ' % nfs_mount.get_vpath()
        cls.debug(msg)
        if ipv6_address:
            ipv6 = ipv6_address[0]
        else:
            ipv6 = None

        ipv4_address = [s.ipv4address for s in all_providers
                if hasattr(s, 'ipv4address') and \
                        s.ipv4address and s.name == nfs_mount.provider]
        msg = 'Searching for ipv4address for nfs-mount' \
                ' "%s" amongst providers ' % nfs_mount.get_vpath()
        cls.debug(msg)
        if ipv4_address:
            ipv4 = ipv4_address[0]
        else:
            ipv4 = None
        return ipv4, "[%s]" % ipv6

    @classmethod
    def _find_provider_updated_ip(cls, nfs_mount, plugin_api_context):
        """
        Utility method returns ip of the ipv4address of the new
        sfs-virtual-server ipv4address that the sfs-mount has been
        updated to.
        """
        # Validation enforces that only an sfs-virtual-server can be updated
        virtual_servers = plugin_api_context.query('sfs-virtual-server')
        msg = 'Searching for ipv4address for nfs-mount' \
                ' "%s" amongst updated providers ' % nfs_mount.get_vpath()
        cls.debug(msg)
        updated_prov_ip = None
        for prov in virtual_servers:
            if nfs_mount.provider == prov.name:
                updated_prov_ip = prov.ipv4address
        return updated_prov_ip

    def create_server_tasks(self, context, nfs_type):
        """ It creates all CallbackTasks needed in order to create file systems
        and its correspond shares for managed NFS.
        """
        logger = log.trace
        logger.info("create_server_tasks nfs_type=%s", nfs_type)

        parse_fs = lambda path: path.split('/')[-1]
        tasks = []

        split_ips = lambda ips: set(x.strip() for x in ips.split(',')
                                                    if x.strip())
        split_options = lambda options: set(x.strip() \
                                            for x in options.split(',')
                                            if x.strip())

        def allowed_clients_updated(export):
            old_ips = export.applied_properties.get('ipv4allowed_clients', '')
            old_clients = split_ips(old_ips)
            clients = split_ips(export.ipv4allowed_clients or '')
            return export.is_updated() and old_clients != clients

        def options_updated(export):
            applied_options = export.applied_properties.get('options', '')
            old_options = split_options(applied_options)
            options = split_options(export.options or '')
            return export.is_updated() and old_options != options

        def create_share_task(action, info, service,
                              callback_function, file_system):
            share = info["shares"]
            pool = file_system.parent.parent
            export_path = file_system.path
            description = '%s exports for ' \
                          '"%s" in pool "%s" on NAS server "%s"' % \
                (action, export_path, pool.name,
                 service.properties["management_ipv4"])

            logger = log.trace
            for line in traceback.format_stack():
                logger.debug("create_share_task %s", line)

            return build_nas_callback_task(
                            info["export"], description,
                            callback_function,
                            sfs_service_vpath=service.get_vpath(),
                            shares=[dict(
                                path=export_path,
                                clients=share['clients'],
                                options=share['options']
                            )]
            )

        def get_clients(props):
            clients = props.get("ipv4allowed_clients")
            return set(clients.split(',')) if clients else set()

        for service in context.query(nfs_type):
            logger.debug("create_server_tasks service=%s", service)
            if not (service.is_initial() or service.is_applied() or
                    service.is_updated()):
                continue
            if not self._is_sfs_managed(service):
                # that means that we don't need to create fs or shares for
                # un-managed services.
                continue
            sfs_nas_type = NasPlugin._get_sfs_nas_type(service)
            for pool in service.pools:
                logger.debug("create_server_tasks pool=%s", pool)
                for file_system in pool.file_systems:
                    logger.debug(
                        "create_server_tasks file_system=%s",
                        file_system
                    )
                    exp_task = None
                    fs = parse_fs(file_system.path)
                    if file_system.is_initial():
                        description = 'Create file system "%s" in pool "%s"' \
                                      ' on NAS server "%s"' % (fs, pool.name,
                                      service.properties["management_ipv4"])
                        # Hack here. For UnityXT we need specify which
                        # nasserver to create the filesystem on. To
                        # maintain the existing API, we'll pass this in
                        # the layout arg
                        layout = 'simple'
                        data_reduction = 'true'
                        if sfs_nas_type == 'unityxt':
                            layout = file_system.provider
                            if file_system.data_reduction:
                                data_reduction = file_system.data_reduction
                        exp_task = build_nas_callback_task(file_system,
                            description,
                            self.nfs_fs_creation_callback,
                            sfs_service_vpath=service.get_vpath(),
                            name=fs,
                            size=file_system.size,
                            pool=pool.name,
                            layout=layout,
                            data_reduction=data_reduction
                            )
                        tasks.append(exp_task)
                    elif file_system.is_updated():
                        old_size = file_system.applied_properties.get("size")
                        if Size(file_system.size) > Size(old_size):
                            description = 'Increase size of file system' \
                                          ' "%s" in pool "%s" on NAS' \
                                          ' "%s" from "%s" to "%s"' % \
                                          (fs, pool.name,
                             service.properties["management_ipv4"],
                             Size(old_size), Size(file_system.size))
                            exp_task = build_nas_callback_task(file_system,
                                description,
                                self.nfs_fs_resize_callback,
                                sfs_service_vpath=service.get_vpath(),
                                name=fs,
                                size=file_system.size,
                                pool_name=pool.name)
                            tasks.append(exp_task)
                        if sfs_nas_type == 'unityxt':
                            if not file_system.data_reduction:
                                data_reduction = 'true'
                            else:
                                data_reduction = file_system.data_reduction
                            old_dr = file_system.applied_properties.get(
                                    "data_reduction")
                            if old_dr != data_reduction:
                                description = 'change data reduction' \
                                              ' setting from "%s"' \
                                              ' to "%s"' % (old_dr,
                                                            data_reduction)
                                change_dr = build_nas_callback_task(
                                    file_system,
                                    description,
                                    self.nfs_fs_change_dr_callback,
                                    sfs_service_vpath=service.get_vpath(),
                                    name=fs,
                                    data_reduction=data_reduction)
                                tasks.append(change_dr)

                    ip_to_shares = {}
                    for export in file_system.exports:
                        logger.debug(
                            "create_server_tasks export=%s",
                            export
                        )
                        applied_props = export.applied_properties
                        old_options = applied_props.get("options", "")
                        clients = get_clients(export.properties)
                        logger.debug(
                            "create_server_tasks clients=%s is_for_removal=%s",
                            clients,
                            export.is_for_removal()
                        )
                        if not export.is_initial():
                            old_clients = get_clients(applied_props)
                        else:
                            old_clients = set()
                        removed_shares = {}
                        if export.is_for_removal():
                            for ip in clients:
                                removed_shares[ip] = old_options
                        logger.debug(
                            "create_server_tasks removed_shares=%s",
                            removed_shares
                        )
                        logger.debug(
                            "create_server_tasks ii=%s acu=%s ou=%s",
                            export.is_initial(),
                            allowed_clients_updated(export),
                            options_updated(export)
                        )

                        if not export.is_initial() and \
                           not allowed_clients_updated(export) and \
                           not options_updated(export):
                            continue
                        logger.debug("create_server_tasks for ip in clients")
                        for ip in clients:
                            if ip not in ip_to_shares:
                                ip_to_shares[ip] = dict(
                                    old_export=None,
                                    export=export,
                                    old_options='',
                                    options=export.options
                                )
                            else:
                                ip_to_shares[ip]["export"] = export
                                if not ip_to_shares[ip]["options"]:
                                    ip_to_shares[ip]["options"] = \
                                                                 export.options
                        for ip in old_clients:
                            if ip not in ip_to_shares:
                                ip_to_shares[ip] = dict(
                                    old_export=export,
                                    export=None,
                                    old_options=old_options,
                                    options=''
                                )
                            else:
                                ip_to_shares[ip]["old_export"] = export
                                if not ip_to_shares[ip]["old_options"]:
                                    ip_to_shares[ip][
                                        "old_options"] = old_options
                    logger.debug(
                        "create_server_tasks: ip_to_shares=%s",
                        ip_to_shares
                    )
                    remove_shares = {}
                    create_shares = {}
                    update_shares = {}
                    for ip, share in ip_to_shares.items():
                        if share["export"] is None:
                            export = share["old_export"]
                            options = share["old_options"]
                            remove_shares.setdefault(
                                export.get_vpath(),
                                dict(
                                    export=export,
                                    shares=dict(
                                        path=file_system.path,
                                        clients=[],
                                        options=options
                                    )
                                )
                            )["shares"]["clients"].append(ip)
                        if share["old_export"] is None\
                                and not ip in removed_shares:
                            export = share["export"]
                            options = share["options"]
                            create_shares.setdefault(
                                export.get_vpath(),
                                dict(
                                    export=export,
                                    shares=dict(
                                        path=file_system.path,
                                        clients=[],
                                        options=options
                                    )
                                )
                            )["shares"]["clients"].append(ip)
                        if share["export"] is not None \
                            and (share["old_export"] is not None \
                                 and share[
                                "old_options"] != share["options"])\
                            or (ip in removed_shares \
                                and removed_shares[ip] != share["options"]):
                            export = share["export"]
                            options = share["options"]
                            update_shares.setdefault(
                                export.get_vpath(),
                                dict(
                                    export=export,
                                    shares=dict(
                                        path=file_system.path,
                                        clients=[],
                                        options=options
                                    )
                                )
                            )["shares"]["clients"].append(ip)

                    for info in remove_shares.values():
                        share_remove_task = create_share_task(
                            "Remove", info,
                            service, self.nfs_shares_removal_callback,
                            file_system)
                        tasks.append(share_remove_task)
                    for info in create_shares.values():
                        share_create_task = create_share_task(
                            "Create", info,
                            service, self.nfs_shares_creation_callback,
                            file_system)
                        tasks.append(share_create_task)
                        # share creation depends on the fs,
                        # case it's not applied
                        if exp_task is not None:
                            share_create_task.requires.add(exp_task)
                    for info in update_shares.values():
                        share_update_task = create_share_task(
                            "Update", info,
                            service, self.nfs_shares_update_callback,
                            file_system)
                        tasks.append(share_update_task)
        return tasks

    def nfs_shares_creation_callback(self, api, sfs_service_vpath,
                                     shares):
        """ This callback task creates shares for a file system.
        """
        conn = self.get_conn_dict(api, sfs_service_vpath)
        self.debug("Starting callback task to create shares")
        with self.nfs_connection_class(api, **conn) as nfs:
            for share_dict in shares:
                for client in share_dict['clients']:
                    path, options = share_dict['path'], share_dict['options']
                    share_id = "%s (%s)" % (path, client)
                    exist_share = None
                    self.debug("%s: checking if the share '%s' already "
                               "exists" % (str(nfs), share_id))
                    try:
                        exist_share = nfs.share.get(path, client)
                    except Share.DoesNotExist:
                        self.debug('Share "%s" does not exist' % share_id)
                    if exist_share is not None:
                        new_share = Share(nfs.share, path, client, options)
                        self.debug("%s: the share '%s' already exists. "
                                   "Checking if it's faulted" % (str(nfs),
                                                                  share_id))
                        if exist_share.faulted:
                            raise Share.CreationException('The share "%s" '
                                'already exists in NAS but is in a faulted '
                                'state.' % share_id)
                        self.debug("%s: now checking whether the share "
                                   "%s has same options or not" %
                                   (str(nfs), share_id))
                        self.debug("%s: existing share options: %s" %
                                   (str(nfs), exist_share.options))
                        self.debug("%s: new share options: %s" %
                                   (str(nfs), new_share.options))

                        if nfs.name == 'VA':
                            # TORF-183610 - VA driver adds the nordirplus
                            # hardcoded. Here this option is removed in order
                            # to not consider this option in the comparison.
                            self.debug('Excluding the "nordirplus" option for '
                                       'the shares comparison. Current '
                                       'options of %s: %s' % (exist_share,
                                                          exist_share.options))
                            filtered = ','.join([i for i in
                                                 exist_share.options.list
                                                 if i != 'nordirplus'])
                            exist_share.options._options_str = filtered
                            self.debug('Filtered options of %s: %s' %
                                       (exist_share, exist_share.options))

                        if exist_share != new_share:
                            msg = 'The share "%s" already exists in NAS ' \
                                  'but it\'s options do not match: "%s" != ' \
                                  '"%s"' % (path, exist_share.options,
                                            new_share.options)
                            self.debug("%s: %s" % (str(nfs), msg))
                            raise Share.CreationException(msg)
                        self.warn('The share "%s" already exists on NAS' %
                                  share_id)
                    else:
                        self.debug('Creating share "%s"' % share_id)
                        try:
                            nfs.share.create(path, client, options)
                        except Share.AlreadyExists:
                            self.warn('The share "%s" already exists on NAS' %
                                  share_id)

    def nfs_shares_update_callback(self, api, sfs_service_vpath,
                                   shares):
        """ This callback task updates shares for a file system.
        """
        conn = self.get_conn_dict(api, sfs_service_vpath)
        self.debug("Starting callback task to update shares")
        with self.nfs_connection_class(
                api, **conn) as nfs:
            for share_dict in shares:
                for client in share_dict['clients']:
                    path, options = share_dict['path'], share_dict['options']
                    share_id = "%s (%s)" % (path, client)
                    try:
                        nfs.share.create(path, client, options)
                        self.warn('The share "%s" does not exist on NAS' %
                                  share_id)
                    except Share.AlreadyExists:
                        pass

    def nfs_shares_removal_callback(self, api, sfs_service_vpath,
                                    shares):
        """ This callback task removes shares for a file system.
        """
        conn = self.get_conn_dict(api, sfs_service_vpath)
        self.debug("Starting callback task to remove shares")
        with self.nfs_connection_class(
                api, **conn) as nfs:
            for share_dict in shares:
                for client in share_dict['clients']:
                    path = share_dict['path']
                    share_id = "%s (%s)" % (path, client)
                    self.debug("%s: checking if the share '%s' exists" %
                               (str(nfs), share_id))
                    if nfs.share.exists(path, client):
                        nfs.share.delete(path, client)
                    else:
                        self.debug("%s: share '%s' does not exist, doing "
                                   "nothing" % (str(nfs), share_id))

    # TODO temporary solution, plugin api doesn't have this
    def sanitize(self, raw_string):
        """
        Sanitizes a string by inserting escape characters to make it
        shell-safe.

        :param raw_string: The string to sanitise
        :type raw_string: string

        :returns: The escaped string
        :rtype: string
        """
        spec_chars = '''"`$'(\\)!~#<>&*;| '''
        escaped = ''.join([c if c not in spec_chars else '\\' + c
                           for c in raw_string])
        return escaped

    def get_conn_dict(self, api, sfs_service_vpath):
        """ Get all connection details for given service_vpath then return is
        as dictionary with keys: host, username, password
        """
        service = api.query_by_vpath(sfs_service_vpath)
        ipv4 = service.properties.get("management_ipv4")
        ipv6 = service.properties.get("management_ipv6")
        host = ipv4 or ipv6
        username = service.properties["user_name"]
        password = service.properties.get("password_key")

        nas_type = service.properties.get("nas_type")
        if not nas_type:
            nas_type = 'veritas'

        return {
            'host': host,
            'username': username,
            'password': password,
            'nas_type': nas_type
        }

    def nfs_fs_creation_callback(self, api, sfs_service_vpath,
                                 name, size, pool, layout,
                                 data_reduction):
        """ This callback task creates a single file system.
        """
        conn = self.get_conn_dict(api, sfs_service_vpath)
        self.debug('Starting a callback task to create the "%s" file system' %
                   name)
        conn["username"] = api.sanitize(conn["username"])
        with self.nfs_connection_class(
                api, **conn) as nfs:
            service = api.query_by_vpath(sfs_service_vpath)
            nas_type = service.properties.get("nas_type")
            try:
                if nas_type == 'unityxt':
                    nfs.filesystem.create(name, size, pool, layout,
                                          data_reduction)
                else:
                    nfs.filesystem.create(name, size, pool, layout)
                    self.debug('%s: file system "%s" has been created '
                               'successfully' % (str(nfs), name))
            except FileSystem.AlreadyExists, err:
                self.warn('The file system "%s" already exists on NAS.' % name)
                self.debug("%s: %s" % (str(nfs), str(err)))
                fs = nfs.filesystem.get(name)
                other = FileSystem(nfs.filesystem, name, size, layout, pool)
                if fs == other:
                    self.debug('%s: the file system "%s" is exactly the same'
                               ', so continue.' % (str(nfs), name))
                    # before: if fs is offline, fail the plan (LITPCDS-7278)
                    # now: try to bring the fs online (LITPCDS-10248)
                    if not fs.online:
                        msg = 'The file system "%s" already exists in NAS ' \
                              'but it is set to offline. Attempting to ' \
                              'online it.' % name
                        self.debug("%s: %s" % (str(nfs), msg))
                        nfs.filesystem.online(name)
                    return
                msg = 'The file system "%s" already exists on NAS but its ' \
                      'attributes don\'t match: %s' % (name,
                                                        fs.diff_display(other))
                raise FileSystem.CreationException(msg)

    def nfs_fs_change_dr_callback(self, api, sfs_service_vpath, name,
                                  data_reduction):
        """ This callback task enables or disables data
        reduction on an existing filesystem.
        """
        conn = self.get_conn_dict(api, sfs_service_vpath)
        self.debug('Starting a callback task to resize the "%s" file system' %
                   name)
        conn["username"] = api.sanitize(conn["username"])
        service = api.query_by_vpath(sfs_service_vpath)
        nas_type = service.properties.get("nas_type")
        if nas_type == 'unityxt':
            with self.nfs_connection_class(api, **conn) as nfs:
                try:
                    nfs.filesystem.change_data_reduction(name,
                                                         data_reduction)
                    log.trace.info('File system "%s" has had data'
                                   ' reduction set to'
                                   ' "%s" successfully' % (name,
                                                           data_reduction))
                except CallbackExecutionException:
                    self.warn('Data reduction on file system "%s" could '
                              'not be set to "%s"' % (name,
                                                      data_reduction))

    def nfs_fs_resize_callback(self, api, sfs_service_vpath, name,
                                 size, pool_name):
        """ This callback task resizes a single file system.
        """
        conn = self.get_conn_dict(api, sfs_service_vpath)
        self.debug('Starting a callback task to resize the "%s" file system' %
                   name)
        conn["username"] = api.sanitize(conn["username"])
        with self.nfs_connection_class(
                api, **conn) as nfs:
            try:
                nfs.filesystem.resize(name, size, pool=pool_name)
                log.trace.info('File system "%s" has been resized to'
                           ' "%s" successfully' % (name, size))
            except FileSystem.SameSizeException:
                self.warn('File system "%s" is already same '
                          'size as the target size "%s"' % (name, size))

    def get_security_credentials(self, plugin_api_context):
        """ Registers pairs of credentials for NFS user_name and password_key.

        :param plugin_api_context: PluginApiContext instance to access Model
        :type plugin_api_context: litp.core.plugin_context_api.PluginApiContext

        :returns: A list of credentials pairs (user_name, password_key)
        :rtype: list
        """
        c = lambda s: (s.properties.get('user_name'),
                       s.properties.get('password_key'))
        credentials = [c(s) for s in plugin_api_context.query('sfs-service')
                       if self._is_sfs_managed(s)]
        return credentials

    def _get_caches_pools(self, sfs_service):
        """ Return a list of pairs of cache and the correspond pool.
        """
        caches_pools = {}
        for file_system in self._get_snappable_filesystems(sfs_service):
            caches = sfs_service.query("sfs-cache",
                                       name=file_system.cache_name)
            for cache in caches:
                pool = cache.parent.parent
                caches_pools[cache.name] = (cache, pool)
        return caches_pools.values()

    def _configure_cache_object_tasks(self, snap_object, sfs_service):
        """ Returns a list of tasks to configure cache object on NAS.
        """
        tasks = []
        for cache, pool in self._get_caches_pools(sfs_service):
            cache_size = self._calc_cache_object_size(sfs_service)
            description = 'Configure cache object "%s" in pool "%s"' \
                          ' on NAS server "%s"' % \
                     (cache.name, pool.name,
                     sfs_service.properties["management_ipv4"])
            task = self._configure_cache_callback(snap_object, cache,
                                            description, cache_size, pool.name,
                                          sfs_service.get_vpath())
            tasks.append(task)
        return tasks

    def _configure_cache_callback(self, snap_object, cache, description,
            size, pool_name, sfs_service_vpath):
        return build_nas_callback_task(
                snap_object,
                description,
                self._configure_cache,
                cache_name=cache.name,
                size=str(size),
                pool_name=pool_name,
                sfs_service_vpath=sfs_service_vpath,
                tag_name=create_snapshot_tags.NAS_FILESYSTEM_TAG)

    def _configure_cache(self, callback_api, cache_name, size,
            pool_name, sfs_service_vpath):
        """
            Use NAS psl to create cache object:
            rollback cache create cache_name size pool

        """
        conn = self.get_conn_dict(callback_api, sfs_service_vpath)
        self.debug(
                'Starting a callback task to create cache object "%s"' %
                   cache_name)
        conn["username"] = callback_api.sanitize(conn["username"])
        with self.nfs_connection_class(
                callback_api,
                **conn) as nfs:
            try:
                nfs.cache.create(cache_name, size, pool_name)

                log.trace.debug('Cache "%s" has been created '
                               'successfully' % cache_name)

            except Cache.AlreadyExists, err:
                self.debug("%s: %s" % (str(nfs), str(err)))
                cache = nfs.cache.get(cache_name)
                other = Cache(nfs.cache, cache_name, size, pool_name)
                cache_exist_msg = 'The cache "%s" already exists ' \
                                  'on NAS' % cache_name
                if cache.pool != other.pool:
                    msg = 'Pool "%s" does not exist on NAS' \
                          % other.pool.name
                    raise Cache.CreationException(msg)
                if cache.size > other.size:
                    self.warn('%s. Current cache size %s is greater '
                              'than the latest calculated value of %s. '
                              'No cache resizing needed.' % (
                        cache_exist_msg, cache.size, size))
                else:
                    try:
                        nfs.cache.resize(cache_name, size)
                        self.warn('%s and has been resized to '
                                  '%s successfully.' % (cache_exist_msg,
                                                        size))
                    except Cache.SameSizeException as err:
                        self.warn('%s. Current cache size %s is equal '
                                  'to the latest calculated value of %s. '
                                  'No cache resizing needed.' % (
                            cache_exist_msg, cache.size, size))

    def _calc_cache_object_size(self, sfs_service):
        """ Calculates the size of cache object required
        Based on all file systems that are in applied or updated state
        returns size in M
        """
        cache_size = Size("0M")
        for pool in sfs_service.pools:
            for file_system in pool.file_systems:
                if not file_system.is_initial() and \
                    has_property(file_system, 'snap_size') and \
                    (int(file_system.snap_size) > 0):
                    size = Size(
                        file_system.applied_properties['size'])
                    cache_size += size * \
                            (Decimal(file_system.snap_size) / 100)
        size = Size("%s%s" % (cache_size.megas.digit.quantize(Decimal("0."),
            rounding=ROUND_CEILING), 'M'))
        five = Size("5M")
        if size < five:
            size = five
        return size

    def _create_snap_name(self, snap_tag, file_system_path):
        full_snap_name = 'L_' + file_system_path.split("/")[-1] + '_'
        if snap_tag != UPGRADE_SNAPSHOT_NAME:
            full_snap_name = full_snap_name + snap_tag
        return full_snap_name

    def create_snapshot_plan(self, plugin_api_context):
        """
        Create a plan for ``create``, ``remove``  or ``restore``
        snapshot actions.
        Generates tasks for snapshot creation, removal or restore
        of NAS file systems and the creation and growing of cache
        objects on NAS servers.
        """
        log.trace.debug("NasPlugin.create_snapshot_plan")
        try:
            action = plugin_api_context.snapshot_action()
            snapshot_name = plugin_api_context.snapshot_name()
        except Exception as e:
            raise PluginError(e)
        return self._generate_snapshot_tasks(plugin_api_context,
                snapshot_name, action)

    @classmethod
    def _get_snappable_filesystems(cls, item):
        """ Returns a list of file systems that had been snapped. A file
        system is considered snapped if it meets all of the following criteria:
        - any of the status: updated, applied , for_removal
        - has a "cache_name" defined
        - "snap_size" is greater than 0
        """
        nas_type = NasPlugin._get_sfs_nas_type(item)
        file_systems = []
        for fs in item.query('sfs-filesystem'):
            statuses = fs.is_updated() or fs.is_applied() \
                        or fs.is_for_removal()
            snap_size = int(getattr(fs, 'snap_size', 0) or 0)
            # cache_name required for veritas sfs but not for unityxt
            cache_name = 'NA'
            if nas_type == 'veritas':
                cache_name = getattr(fs, 'cache_name', None)
            if statuses and cache_name and snap_size:
                file_systems.append(fs)
        log.trace.debug(
            "NasPlugin._get_snappable_filesystems returning %d fs",
            len(file_systems)
        )
        return file_systems

    def _generate_snapshot_tasks(self, api, snapshot_name, action):
        log.trace.debug(
            "NasPlugin._generate_snapshot_tasks snapshot_name=%s",
            snapshot_name
        )
        tasks = []
        snap_shot_objects = api.query('snapshot-base')
        snapshot_item = [
            snap for snap in snap_shot_objects
            if snap.item_id == snapshot_name][0]
        if len(snapshot_name) > self.MAX_SNAPSHOT_NAME_LENGTH\
                and snapshot_name != UPGRADE_SNAPSHOT_NAME:
            return []
        tag = None
        if action == 'create':
            tasks += self._create_snapshot_tasks(api, snapshot_name,
                                                 snapshot_item)
            tag = create_snapshot_tags.VALIDATION_TAG
        elif action == 'remove':
            tasks += self._remove_snapshot_tasks(api, snapshot_name,
                                                 snapshot_item)
            tag = remove_snapshot_tags.VALIDATION_TAG
        elif action == 'restore':
            tasks += self._restore_snapshot_tasks(api, snapshot_name,
                                                  snapshot_item)
            tag = restore_snapshot_tags.VALIDATION_TAG
        host_key_tasks = self.generate_get_and_save_remote_host_key_tasks(api,
                                                                    tasks, tag)
        tasks = host_key_tasks + tasks  # host_key_tasks must be the first ones
        return tasks

    def _create_snapshot_tasks(self, plugin_api_context, snapshot_name,
                               snapshot_item):
        log.trace.debug(
            "NasPlugin._create_snapshot_tasks snapshot_name=%s",
            snapshot_name
        )
        tasks = []
        for service in plugin_api_context.query("sfs-service"):
            if not self._is_sfs_managed(service):
                continue
            cache_task = None
            file_systems = self._get_snappable_filesystems(service)
            if file_systems:
                cache_tasks = self._configure_cache_object_tasks(
                    snapshot_item, service)
                tasks += cache_tasks
            for filesystem in file_systems:
                full_snap_name = \
                    self._create_snap_name(
                        snapshot_name, filesystem.path)
                if snapshot_name == UPGRADE_SNAPSHOT_NAME:
                    snap_description = 'NAS deployment snapshot "%s"' % \
                                   full_snap_name
                else:
                    snap_description = 'NAS named backup snapshot "%s"' %\
                        full_snap_name
                sfs_ipv4_addr = service.properties["management_ipv4"]
                description = 'Create %s for file system with path "%s" on ' \
                              'NAS server "%s"' % (str(snap_description),
                                            str(filesystem.path),
                                            str(sfs_ipv4_addr))
                create_snap_task = self._create_snapshot_callback(
                    snapshot_item, description,
                    service.get_vpath(),
                    full_snap_name,
                    filesystem.path.split("/")[-1],
                    filesystem.cache_name)
                tasks.append(create_snap_task)
                if cache_task is not None:
                    create_snap_task.requires = set([cache_task])
        log.trace.debug(
            "NasPlugin._create_snapshot_tasks returning %d tasks",
            len(tasks)
        )
        return tasks

    def _remove_snapshot_tasks(self, plugin_api_context, snapshot_name,
                               snapshot_item):
        tasks = []
        snapshot_api = plugin_api_context.snapshot_model()
        if not snapshot_api:  # bug 10581
            msg = 'Snapshot model missing for remove_snapshot action'
            raise PluginError(msg)
        snap_shot_objects = plugin_api_context.query('snapshot-base')
        for snapped_service in snapshot_api.query("sfs-service"):
            if not self._is_sfs_managed(snapped_service):
                continue
            remove_snapshot_tasks = []
            description = 'Check snapshots are currently ' \
                          'not being restored ' \
                          'on NAS server "%s"' % \
                    (str(snapped_service.properties["management_ipv4"]))
            file_systems = self._get_snappable_filesystems(snapped_service)
            snapped_fs_names = [fs.path.split("/")[-1] for fs in file_systems]
            if snapped_fs_names:
                tasks.append(self._check_restore_callback(
                            snapshot_item, description,
                            snapped_service.get_vpath(),
                            snapped_fs_names))
            for filesystem in file_systems:
                full_snap_name = \
                    self._create_snap_name(snapshot_name, filesystem.path)
                snap_description = 'deployment snapshot "%s"' % \
                        full_snap_name \
                        if snapshot_name == UPGRADE_SNAPSHOT_NAME \
                        else 'named backup snapshot "%s"' % full_snap_name
                sfs_ipv4_addr = snapped_service.properties["management_ipv4"]
                description = 'Delete %s for file system with path "%s" on ' \
                              'NAS server "%s"' % (str(snap_description),
                                            str(filesystem.path),
                                            str(sfs_ipv4_addr))
                remove_snapshot_tasks.append(self._remove_snapshot_callback(
                        snapshot_item, description,
                        snapped_service.get_vpath(), filesystem.path,
                        snapshot_name))
            tasks += remove_snapshot_tasks

            for cache, _ in self._get_caches_pools(snapped_service):
                cache_path_for_removal = cache.get_vpath() \
                    if cache is not None else None
                cache_path_for_removal = cache_path_for_removal \
                            if len(snap_shot_objects) == 1 else None
                if cache_path_for_removal:
                    remove_cache_task = self._remove_cache_object_task(
                                    snapshot_item, snapped_service,
                                    cache, cache_path_for_removal)
                    for task in remove_snapshot_tasks:
                        remove_cache_task.requires.add(task)
                    tasks.append(remove_cache_task)
        return tasks

    def _check_restore_callback(self, snap_object, description,
                                sfs_service_vpath,
                                fs_names):
        return build_nas_callback_task(
                snap_object,
                description,
                self._check_restore_tasks_are_completed,
                sfs_service_vpath=str(sfs_service_vpath),
                fs_names=fs_names,
                tag_name=remove_snapshot_tags.VALIDATION_TAG)

    def _check_restore_tasks_are_completed(self, callback_api,
                                           sfs_service_vpath,
                                           fs_names):
        """
            Use naslib to verify that no file systems are being restored
        """
        conn = self.get_conn_dict(callback_api, sfs_service_vpath)
        log.trace.debug(
                'Starting a callback task to verify that no '
                'file systems are in the process of being '
                'restored on the NAS')
        conn["username"] = callback_api.sanitize(conn["username"])
        with self.nfs_connection_class(callback_api,
                                       **conn) as nfs:
            for name in fs_names:
                try:
                    is_running = nfs.filesystem.is_restore_running(name)
                except FileSystem.DoesNotExist:
                    is_running = False
                if is_running:
                    raise CallbackExecutionException('Deleting a snapshot is '
                                                   'not permitted until the '
                                                   'following file system(s) '
                                                   '"%s" are restored on the '
                                                   'NAS.'
                                                   % ', '.join(fs_names))

    def _restore_snapshot_tasks(self, plugin_api_context, snapshot_name,
                                snapshot_item):
        tasks = []
        snapshot_api = plugin_api_context.snapshot_model()
        if not snapshot_api:  # bug 10581
            msg = 'Snapshot model missing for restore_snapshot action.'
            raise PluginError(msg)
        for snapped_service in snapshot_api.query("sfs-service"):
            if not self._is_sfs_managed(snapped_service):
                continue
            file_systems = self._get_snappable_filesystems(snapped_service)
            if not file_systems:
                continue
            file_systems_names = [f.path.split('/')[-1] for f in file_systems]
            for cache, _ in self._get_caches_pools(snapped_service):
                verify_cache_task = build_nas_callback_task(
                    snapshot_item,
                    'Check cache "%s" is valid on NAS server "%s"' %
                    (str(cache.name),
                        str(snapped_service.properties["management_ipv4"])),
                    self.verify_cache_callback,
                    sfs_service_vpath=str(snapped_service.get_vpath()),
                    cache_vpath=str(cache.get_vpath()),
                    tag_name=restore_snapshot_tags.VALIDATION_TAG
                    )
                tasks.append(verify_cache_task)
                action_forced = plugin_api_context.is_snapshot_action_forced()
                if not action_forced:
                    description = 'Check snapshots are present on NAS ' \
                                  'server "%s"' % (
                            str(snapped_service.properties["management_ipv4"]))
                    verify_snapshots_task = build_nas_callback_task(
                        snapshot_item,
                        description,
                        self.verify_snapshots_callback,
                        sfs_service_vpath=str(snapped_service.get_vpath()),
                        snapshot_name=snapshot_name,
                        file_systems_names=file_systems_names,
                        tag_name=restore_snapshot_tags.VALIDATION_TAG,
                        )
                    verify_snapshots_task.requires.add(verify_cache_task)
                    tasks.append(verify_snapshots_task)

            for filesystem in file_systems:
                filesystem_to_be_restored = dict(
                    path=filesystem.path,
                    shares_to_create=[
                        dict(
                            path=filesystem.path,
                            clients=export.applied_properties
                            ['ipv4allowed_clients'].split(','),
                            options=export.options)
                        for export in
                        filesystem.exports]
                )
                sfs_ipv4_addr = snapped_service.properties["management_ipv4"]
                description = 'Restore file system with path "%s" on ' \
                              'NAS server "%s"' % (str(filesystem.path),
                                            str(sfs_ipv4_addr))

                restore_snapshot_task = self._restore_snapshot_callback(
                    snapshot_item,
                    description,
                    snapped_service.get_vpath(),
                    filesystem_to_be_restored,
                    snapshot_name,
                    action_forced)
                tasks.append(restore_snapshot_task)
        return tasks

    def _remove_cache_object_task(self, snap_object, sfs_service,
                                  cache, cache_path_for_removal):
        pool = cache.parent.parent
        description = 'Delete cache object "%s" in pool "%s"'\
                      ' on NAS server "%s"' % \
                (cache.name, pool.name,
                 sfs_service.properties["management_ipv4"])
        return self._remove_cache_callback(snap_object, description,
                cache_path_for_removal, sfs_service.get_vpath())

    def _remove_cache_callback(self, snap_object, description,
                               cache_path_for_removal, sfs_service_vpath):
        return build_nas_callback_task(
                snap_object,
                description,
                self._remove_cache,
                cache_path_for_removal=cache_path_for_removal,
                sfs_service_vpath=sfs_service_vpath,
                tag_name=remove_snapshot_tags.NAS_FILESYSTEM_TAG)

    def _remove_cache(self, callback_api, cache_path_for_removal,
                      sfs_service_vpath):
        """ Use naslib to remove cache object.
        """
        conn = self.get_conn_dict(
            callback_api,
            sfs_service_vpath)
        conn["username"] = callback_api.sanitize(conn["username"])
        with self.nfs_connection_class(callback_api,
                                       **conn) as nfs:
            cache = callback_api.query_by_vpath(cache_path_for_removal)
            if cache:
                try:
                    nfs.cache.delete(cache.name)
                    log.trace.debug('%s: cache "%s" has been deleted '
                                'successfully' % (str(nfs), cache.name))
                except Cache.DoesNotExist:
                    self.warn('%s: cache "%s" does not exist on NAS'
                              % (str(nfs), cache.name))

    def _create_snapshot_callback(self, snap_object, description,
            sfs_service_vpath, snapshot_name, filesystem, cache_name):
        return build_nas_callback_task(
                snap_object,
                description,
                self._create_snapshot,
                sfs_service_vpath=str(sfs_service_vpath),
                snapshot_name=snapshot_name,
                filesystem=filesystem,
                cache_name=cache_name,
                tag_name=create_snapshot_tags.NAS_FILESYSTEM_TAG)

    def _create_snapshot(self, callback_api, sfs_service_vpath, snapshot_name,
            filesystem, cache_name):
        """
            Use NAS psl to create rollback snapshot:
            rollback create space-optimized snapshot_name fs_name cacheobj

        """
        conn = self.get_conn_dict(callback_api, sfs_service_vpath)

        log.trace.debug(
                'Starting a callback task to create snapshot "%s" '
                'on the NAS' % snapshot_name)

        conn["username"] = callback_api.sanitize(conn["username"])
        with self.nfs_connection_class(callback_api,
                                       **conn) as nfs:
            nfs.snapshot.create(snapshot_name, filesystem, cache_name)
            log.trace.debug('%s: snapshot "%s" has been created '
                        'successfully' % (str(nfs), snapshot_name))

    def _remove_snapshot_callback(self, snap_object, description,
            sfs_service_vpath, filesystem_path, snapshot_name):
        return build_nas_callback_task(
                snap_object,
                description,
                self._delete_snapshot,
                sfs_service_vpath=str(sfs_service_vpath),
                snapshot_name=snapshot_name,
                filesystem_path=filesystem_path,
                tag_name=remove_snapshot_tags.NAS_FILESYSTEM_TAG)

    def _delete_snapshot(self, callback_api, sfs_service_vpath, snapshot_name,
            filesystem_path):
        """
            Use NAS psl to delete rollback snapshot:
            rollback destroy snapshot_name fs_name
        """
        conn = self.get_conn_dict(callback_api, sfs_service_vpath)
        log.trace.debug(
                'Starting a callback task to remove snapshot "%s" '
                'on the NAS' % snapshot_name)
        conn["username"] = callback_api.sanitize(conn["username"])
        with self.nfs_connection_class(callback_api,
                                       **conn) as nfs:
            real_fs_path = filesystem_path.split("/")[-1]
            snap_name = self._create_snap_name(snapshot_name, real_fs_path)
            try:
                log.trace.debug('Remove snapshot "%s" on the NAS' % snap_name)
                nfs.snapshot.delete(snap_name, real_fs_path)
                self.debug('%s: snapshot "%s" has been deleted '
                                'successfully' % (str(nfs), snap_name))
            except Snapshot.DoesNotExist, err:
                self.warn('The snapshot "%s" does not exist'
                          ' on NAS' % snap_name)
                self.debug("%s: %s" % (str(nfs), str(err)))
            except FileSystem.DoesNotExist, err:
                self.warn('The file system "%s" does not exist'
                          ' on NAS' % real_fs_path)
                self.debug("%s: %s" % (str(nfs), str(err)))

    def _restore_snapshot_callback(self, snap_object, description,
            sfs_service_vpath, filesystem, snapshot_name,
            action_forced=False):
        return build_nas_callback_task(
                snap_object,
                description,
                self._restore_snapshot,
                sfs_service_vpath=str(sfs_service_vpath),
                snapshot_name=snapshot_name,
                filesystem=filesystem,
                action_forced=action_forced,
                tag_name=restore_snapshot_tags.NAS_FILESYSTEM_TAG)

    def _restore_snapshot(self, callback_api, sfs_service_vpath, snapshot_name,
            filesystem, action_forced=False):
        """
            Use NAS psl to restore rollback snapshot:
            rollback restore snapshot_name fs_name
        """
        conn = self.get_conn_dict(callback_api, sfs_service_vpath)
        log.trace.debug(
                'Starting a callback task to restore snapshot(s) "%s" '
                'on the NAS' % snapshot_name)
        conn["username"] = callback_api.sanitize(conn["username"])
        with self.nfs_connection_class(callback_api,
                                       **conn) as nfs:
            fs_full_path = filesystem["path"]
            snap_name = self._create_snap_name(snapshot_name, fs_full_path)
            fs_path = filesystem["path"][4:]
            for share in nfs.share.list():
                if share.name == fs_full_path:
                    nfs.share.delete(share.name, share.client)
                    share_id = "%s (%s)" % (share.name, share.client)
                    self.debug("%s: deleting share '%s'" %
                               (str(nfs), share_id))
            log.trace.debug('Restore snapshot "%s" on the NAS' % snap_name)
            try:
                nfs.snapshot.restore(snap_name, fs_path)
            except Snapshot.DoesNotExist:
                if not action_forced:
                    raise
                log.trace.info('Snapshot "%s" for filesystem "%s" '
                               'is missing from the NAS; continuing'
                               % (snap_name, fs_path))
            except Snapshot.RollsyncRunning:
                self.warn('Snapshot restore is currently '
                          'running for the sfs file system ' "%s" % fs_path)
            else:
                # XXX: is the snapshot really restored??? The snapshot action
                # runs in background. I think we should change the message
                # below
                self.debug('%s: snapshot "%s" has been restored'
                            ' successfully' % (str(nfs), snap_name))
            self.nfs_shares_creation_callback(
                callback_api, sfs_service_vpath,
                filesystem["shares_to_create"])

    def verify_cache_callback(
            self, callback_api, sfs_service_vpath, cache_vpath):
        conn = self.get_conn_dict(callback_api, sfs_service_vpath)
        cache = callback_api.query_by_vpath(cache_vpath)
        log.trace.debug(
                'Starting a callback task to verify cache'
                ' "%s" exists on the NAS' % cache.name)
        conn["username"] = callback_api.sanitize(conn["username"])
        with self.nfs_connection_class(
                callback_api,
                **conn) as nfs:
            sfs_cache = next(
                (c for c in nfs.cache.list()
                 if c.name == cache.name), None)
            if sfs_cache is None:
                raise CallbackExecutionException(
                    'Cache "%s" does not exist on NAS.'
                    % cache.name)
            if sfs_cache.available_percentage == 0:
                raise CallbackExecutionException(
                    'Snapshot(s) corrupted because no'
                    ' space is available on NAS cache'
                    ' "%s".' % cache.name)

    def verify_snapshots_callback(self, callback_api, sfs_service_vpath,
                               snapshot_name, file_systems_names):
        conn = self.get_conn_dict(callback_api, sfs_service_vpath)
        log.trace.debug('Starting a callback task to verify snapshot(s)'
                        ' "%s" exist on the NAS' % snapshot_name)
        conn["username"] = callback_api.sanitize(conn["username"])
        with self.nfs_connection_class(callback_api, **conn) as nfs:
            sfs_snapshots = set(((s.name, s.filesystem) for s in
                                 nfs.snapshot.list()))
        missing_snaps = []
        for fs_name in file_systems_names:
            snap_name = self._create_snap_name(snapshot_name, fs_name)
            if (snap_name, fs_name) not in sfs_snapshots:
                missing_snaps.append(snap_name)
        if missing_snaps:
            snaps = ", ".join(missing_snaps)
            if len(missing_snaps) > 1:
                msg = "The snapshots %s don't exist on NAS" % snaps
            else:
                msg = "The snapshot %s doesn't exist on NAS" % snaps
            raise CallbackExecutionException(msg)

    def generate_nasserver_tasks(self, plugin_api_context):
        """
        This method will generate CallbackTasks for NAS server creation.
        Applicable for UnityXT nastype only.

        :param plugin_api_context: PluginApiContext instance to access Model
        :type plugin_api_context: litp.core.plugin_context_api.PluginApiContext
        """
        tasks = []
        callback = self.nfs_server_creation_callback
        # Get Nas model information
        sfs_services = plugin_api_context.query('sfs-service')
        if sfs_services is None or len(sfs_services) == 0:
            return tasks
        nas_type = sfs_services[0].properties["nas_type"]
        # Get pool information
        pool = plugin_api_context.query('sfs-pool')

        if nas_type == 'unityxt' and sfs_services[0].is_initial():
            log.event.info('NAS server task creation for Unity XT')
            # Get storage network information
            nas_servers = plugin_api_context.query('sfs-virtual-server')
            for ns in nas_servers:
                log.event.info('Create Unity XT "%s" NAS server task' \
                    % (ns.properties.get('name')))
                description = 'Create Unity XT "%s" NAS server' \
                    % (ns.properties.get('name'))
                storage_network = ns.properties.get('subnet')
                storage_netmask = netaddr.IPNetwork(storage_network) \
                                    .netmask
                network = str(ns.properties.get('sp')) + ',' + \
                          str(ns.properties.get('ipv4address')) + ',' + \
                          str(storage_netmask) + ',' + \
                          str(ns.properties.get('gateway'))
                server_info = {"name": ns.properties.get('name'),
                               "pool": pool[0].name,
                               "ports": ns.properties.get('ports'),
                               "network": network,
                               "protocols": ns.properties.get(
                                    'sharing_protocols'),
                               "ndmp_keypass": ns.properties.get(
                                    'ndmp_password_key')}
                server_task = CallbackTask(ns, description, callback,
                                            sfs_services[0].get_vpath(),
                                            server_info)
                tasks.append(server_task)

        if nas_type == 'unityxt':
            for sfs in sfs_services:
                for virtual_server in sfs.virtual_servers:
                    if virtual_server.is_updated():
                        log.event.info('Updating sharing protocol')
                        new_sharing = virtual_server.sharing_protocols
                        old_sharing = virtual_server.applied_properties.\
                        get('sharing_protocols')
                        if new_sharing != old_sharing:
                            description = 'change sharing protocols' \
                                          ' setting from "%s"' \
                                           ' to "%s"' % (old_sharing,
                                                         new_sharing)
                            cb = self.nfs_ns_change_sharing_protocol_callback
                            vp = sfs_services[0].get_vpath()
                            server_task = build_nas_callback_task(
                                            virtual_server,
                                            description,
                                            cb,
                                            vp,
                                            protocols=new_sharing)
                            tasks.append(server_task)
        return tasks

    def nfs_server_creation_callback(self, api, sfs_service_vpath,
                                     server_info):
        """ This callback task creates a single nas server."""
        conn = self.get_conn_dict(api, sfs_service_vpath)
        log.event.info('Running callback task to create "%s" nas server' \
            % server_info['name'])
        conn["username"] = api.sanitize(conn["username"])
        ndmp_pass = api.get_password(server_info['ndmp_keypass'], 'ndmp')
        with self.nfs_connection_class(api, **conn) as nfs:
            nfs.nasserver.create(server_info['name'], server_info['pool'],
                                 server_info['ports'], server_info['network'],
                                 server_info['protocols'], ndmp_pass)

    def nfs_ns_change_sharing_protocol_callback(self, api, sfs_service_vpath,
                                               protocols):
        """ This callback task changes the nfs sharing protocol

        param api: Callback API to change the NFS sharing protocol
        type api: apiObj
        param sfs_service_vpath: path to sfs_services in the model
        type sfs_service_vpath: str
        param protocols: nfs_sharing protocol
              (e.g. "nfsv3", "nfsv4" or "nfsv3,nfsv4")
        type protocols: str
        """
        conn = self.get_conn_dict(api, sfs_service_vpath)
        log.event.info('Starting a callback task to change the sharing '
                   'protocol to "%s"' % protocols)
        conn["username"] = api.sanitize(conn["username"])
        with self.nfs_connection_class(api, **conn) as nfs:
            try:
                nfs.nasserver.change_sharing_protocol(protocols)
                log.trace.info('NFS sharing protocol set to'
                              ' "%s" successfully' % (protocols))
            except CallbackExecutionException:
                self.warn('Sharing protocol could '
                          'not be set to "%s"' % (protocols))

    @staticmethod
    def _get_sfs_nas_type(sfs_service):
        nas_type = sfs_service.properties.get("nas_type")
        if not nas_type:
            nas_type = 'veritas'
        return nas_type
