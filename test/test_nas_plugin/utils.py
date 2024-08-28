##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################
""" This package contains useful functions for test cases.
"""

import unittest
import pprint

from litp.core.callback_api import CallbackApi
from litp.core.execution_manager import ExecutionManager, CallbackTask, ConfigTask
from litp.core.model_manager import ModelManager
from litp.core.plugin_context_api import PluginApiContext
from litp.core.plugin_manager import PluginManager
from litp.core.puppet_manager import PuppetManager
from litp.extensions.core_extension import CoreExtension
from nas_extension.nas_extension import NasExtension
from nas_plugin.nas_plugin import NasConnectionCallback
from network_extension.network_extension import NetworkExtension
from volmgr_extension.volmgr_extension import VolMgrExtension
from naslib.nasmock.connection import NasConnectionMock
from naslib.nasexceptions import NasException, NasConnectionException
from litp.core.execution_manager import CallbackExecutionException

get_task_props = lambda x: (x.kwargs, x.item_vpath)


class NasConnectionCallbackMock(NasConnectionCallback, NasConnectionMock):
    """ This class just mocks the connection to NFS while executing the
    NFS functions.
    """

    def __init__(self, *args, **kwargs):
        """ At first it decrypts the password through the callback API.
        """
        super(NasConnectionCallbackMock, self).__init__(*args, **kwargs)
        self.driver_name = 'Sfs'
        self.get_decrypted_password = lambda a, b: '<"DECRYPTED" PASSWORD>'

    def __exit__(self, *args):
        super(NasConnectionCallbackMock, self).__exit__(*args)

class IpAddressHelper(object):
    def __init__(self, ipv6=False, network2=False):
        """

        >>> helper = IpAddressHelper(ipv6=True, network2=False)
        >>> helper.get_ipadd_name()
        'ipv6address'
        >>> helper.get_mask()
        '/120'
        >>> helper.get_ipaddr("1")
        '3ffe:1a05:510:1111:0:aaaa:836b:8101'
        >>> helper.get_ipaddr("02")
        '3ffe:1a05:510:1111:0:aaaa:836b:8102'
        >>> helper.get_ipaddr("10")
        '3ffe:1a05:510:1111:0:aaaa:836b:8110'
        >>> helper = IpAddressHelper(ipv6=False)
        >>> helper.get_mask()
        '/24'
        >>> helper.get_ipaddr("1")
        '10.10.10.1'
        >>> helper.get_ipaddr("02")
        '10.10.10.2'
        >>> helper.get_ipaddr("10")
        '10.10.10.10'
        >>> helper = IpAddressHelper(ipv6=True, network2=True)
        >>> helper.get_ipaddr("1")
        '3ffe:1a05:510:1111:0:bbbb:836b:8101'
        >>> helper.get_ipaddr("02")
        '3ffe:1a05:510:1111:0:bbbb:836b:8102'
        >>> helper.get_ipaddr("10")
        '3ffe:1a05:510:1111:0:bbbb:836b:8110'
        >>> helper = IpAddressHelper(ipv6=False, network2=True)
        >>> helper.get_ipaddr("1")
        '20.20.20.1'
        >>> helper.get_ipaddr("02")
        '20.20.20.2'
        >>> helper.get_ipaddr("10")
        '20.20.20.10'
        """
        """
        :param ipv6:
        :return:
        """
        self.networks = [
            ["10.10.10.", "20.20.20."],
            ["3ffe:1a05:510:1111:0:aaaa:836b:81",
                "3ffe:1a05:510:1111:0:bbbb:836b:81"]]
        self.ipv6 = ipv6
        self.network2 = network2

    def get_ipaddr(self, x):
        def normalize_int_for_ipaddr(num):
            int_num = int(num)
            return "0" + str(int_num) if int_num < 10 and self.ipv6 else num

        return self.networks[self.ipv6][self.network2]\
                     + normalize_int_for_ipaddr(x)

    def get_service_ipadd_name(self):
        return "ipv6address" if self.ipv6 else "ipv4address"

    def get_interface_ipadd_name(self):
        return "ipv6address" if self.ipv6 else "ipaddress"

    def get_mask(self):
        return "/120" if self.ipv6 else "/24"


class ItemCounter(object):
    def __init__(self):
        self.counters = {}
    def __getitem__(self, item):
        return self.counters.get(item.get_vpath(), 0)
    def inc(self, item):
        self.counters[item.get_vpath()] = self.counters.get(item.get_vpath(), 0) + 1


class TestNasPluginBase(unittest.TestCase):
    def setUp(self):
        self.item_log = []
        self.node_counter = 0
        self.storage_profile_counter = 0
        self.volume_group_counter = 0
        self.filesystem_item_counter = 0
        self.network_counter = 0
        self.network_interface_counter = 0
        self.sfs_service_counter = 0
        self.nfs_service_counter = 0
        self.export_path_counter = 0
        self.pool_name_counter = 0
        self.pool_counter = ItemCounter()
        self.filesystem_counter = ItemCounter()
        self.cache_name_counter = 0
        self.cache_counter = ItemCounter()
        self.vrt_ser_counter = ItemCounter()
        self.vrt_serv_name = 0
        self.path_name_counter = 0
        self.export_counter = ItemCounter()
        self.nfs_mount_counter = 0
        self.nfs_inherited_mount_counter = ItemCounter()
        self.setUp_min_base_model() # min model with one deployment, cluster

    def assertIn(self, obj1, obj2, msg=""):
        if msg:
            msg = "%s:\n" % msg
        self.assertTrue(obj1 in obj2, '%s"%s"   <-- is not in -->   "%s" details: %s' % (msg, obj1, obj2, self.get_commands_log()))

    def assertNotIn(self, obj1, obj2, msg=""):
        if msg:
            msg = "%s:\n" % msg
        self.assertFalse(obj1 in obj2, '%s"%s"   <-- is in -->   "%s" details: %s' % (msg, obj1, obj2, self.get_commands_log()))

    def assertErrorCount(self, errors, count):
        self.assertEquals(len(errors), count, "%s errors expected, got: %s details: %s\n%s" % (count, len(errors), pprint.pformat(errors), self.get_commands_log()))

    def assertTaskCount(self, tasks, count):
        self.assertEquals(len(tasks), count, "%s tasks expected, got: %s details: %s\n%s" % (count, len(tasks), pprint.pformat(tasks), self.get_commands_log()))

    def assertHostKeyTaskInTasks(self, tasks):
        self.assertTrue(next((task for task in tasks if task.callback == self.plugin.get_and_save_remote_host_key_callback), None))

    def assertHostKeyTaskNotInTasks(self, tasks):
        self.assertFalse(next((task for task in tasks if task.callback == self.plugin.get_and_save_remote_host_key_callback), None))

    def assertIsNotNone(self, obj, msg=None):
        if obj is None:
            self.fail(msg)

    def create_item(self, *args, **kwargs):
        item = self.model.create_item(*args, **kwargs)
        self.item_log.append(["create", dict(type=args[0], options=kwargs, path=args[1])])
        self.assertIsModel(item)
        return item

    def create_inherited(self, *args, **kwargs):
        item = self.model.create_inherited(*args, **kwargs)
        self.item_log.append(["inherit", dict(options=kwargs, path=args[0], source=args[1])])
        self.assertIsModel(item)
        return item

    def assertIsModel(self, model):
        self.assertFalse(isinstance(model, list), "%s\n%s" % (str(model), self.get_commands_log()))

    def count_type_of_Task(self, tasks):
        """ Returns a tuple of number of CallbackTasks, ConfigTasks from a
            list of tasks
        """
        is_cb = lambda x: isinstance(x, CallbackTask)
        is_cfg = lambda x: isinstance(x, ConfigTask)
        return (len([i for i in tasks if is_cb(i)]), len([i for i in tasks if is_cfg(i)]))

    def update_item(self, item, **kwargs):
        # check if the model has that property defined?
        self.item_log.append(["update", dict(path=item.get_vpath(), options=kwargs)])
        if not item._applied_properties:
            item._applied_properties.update(item.properties)
        item.properties.update(kwargs)
        item.set_updated()
        return item

    def get_commands_log(self):
        def get_item_log_iter():
            for item in self.item_log:
                if item[0] == "create":
                    kw = item[1]
                    yield "litp create -t %s -p %s -o %s" % (kw["type"], kw["path"], " ".join("%s=%s" % (k, v) for k, v in kw["options"].items()))
                elif item[0] == "inherit":
                    kw = item[1]
                    yield "litp inherit -p %s -s %s %s" % (kw["path"], "-o %s" % " ".join("%s=%s" % (k, v) for k, v in kw["options"].items()) if kw["options"] else "", kw["source"])
                elif item[0] == "update":
                    kw = item[1]
                    yield "litp update -p %s -o %s" % (kw["path"], " ".join("%s=%s" % (k, v) for k, v in kw["options"].items()))

        return "\n".join(get_item_log_iter())

    def create_node(self):
        self.node_counter += 1
        return self.create_item("node", "/deployments/d1/clusters/c1/nodes/n%s" % self.node_counter, hostname="node%s" % self.node_counter)

    def create_storage_profile(self):
        self.storage_profile_counter += 1
        storage_profile = self.create_item('storage-profile',
                                           '/infrastructure/storage/storage_profiles/profile%s' % self.storage_profile_counter)
        return storage_profile

    def create_volume_group(self, storage_profile, volume_group_name=None):
        self.volume_group_counter += 1
        generated_name = "vg_root%s" % self.volume_group_counter
        volume_group = self.create_item('volume-group',
                                        '%s/volume_groups/vg%s' % (storage_profile.get_vpath(), self.volume_group_counter),
                                        volume_group_name=generated_name
                                        if volume_group_name is None else volume_group_name)
        return volume_group

    def create_filesystem_item(self, volume_group, type, mount_point, size):
        self.filesystem_item_counter += 1
        file_system = \
            self.create_item('file-system',
                             '%s/file_systems/var%s' % (volume_group.get_vpath(), self.filesystem_item_counter),
                             type=type,
                             mount_point=mount_point,
                             size=size)
        return file_system

    def create_network(self, litp_management, name, subnet=None):
        params = dict(
            #subnet=helper.get_ipaddr("0") + helper.get_mask(),
            litp_management=litp_management,
            name=name)
        if subnet is not None:
            params.update(subnet)
        network = \
            self.create_item("network",
                             "/infrastructure/networking/networks/n%s" % self.network_counter,
                             **params)
        self.network_counter += 1
        return network

    def create_network_interface(self, node, network_name="storage", ipaddress=None, ipv6address=None):
        params = {}
        if ipaddress:
            params["ipaddress"] = ipaddress
        if ipv6address:
            params["ipv6address"] = ipv6address
        network_interface = self.create_item("eth",
                                             "%s/network_interfaces/if%s" % (node.get_vpath(), self.network_interface_counter),
                                             device_name="eth%s" % self.network_interface_counter,
                                             macaddress="80:C1:6E:7A:09:C%s" % self.network_interface_counter,
                                             network_name=network_name,
                                             **params)
        self.network_interface_counter += 1
        return network_interface

    def create_sfs_service(self, managed=False, management_ipv4="10.44.86.226", name=None, sfs_nas_type='veritas'):
        managed_params = {
                          "management_ipv4": management_ipv4,
                          "user_name": 'user',
                          "password_key": 'password'} if managed else {}
        managed_params['nas_type'] = sfs_nas_type
        self.sfs_service_counter += 1
        return self.create_item("sfs-service",
                        "/infrastructure/storage/storage_providers/sfs_service%s" % self.sfs_service_counter,
                        name="sfs%s" % self.sfs_service_counter if not name else name,
                        **managed_params)

    def create_nfs_service(self, ipv4address=None, ipv6address=None, name=None):
        params = {}
        if ipv4address:
            params["ipv4address"] = ipv4address
        if ipv6address:
            params["ipv6address"] = ipv6address

        self.nfs_service_counter += 1
        return self.create_item("nfs-service",
                        "/infrastructure/storage/storage_providers/nfs_service%s" % self.nfs_service_counter,
                        name=("nfs%s" % self.nfs_service_counter) if not name else name,
                        **params)

    def create_virtual_server(self, sfs_service, name=None, ipv4address="10.10.10.10",
                              ports="0,2", sharing_protocols="nfsv4",
                              san_pool="pool_1", sp="spa", subnet="30.30.30.30/24",
                              gateway="20.20.20.20"):
        self.vrt_ser_counter.inc(sfs_service)
        if not name:
            self.vrt_serv_name += 1
        generated_vrt_serv_name = "vsvr%s" % self.vrt_serv_name
        vrt_ser = self.create_item("sfs-virtual-server",
                    "%s/virtual_servers/vrt%s" % (sfs_service.get_vpath(), self.vrt_ser_counter[sfs_service]),
                    name=generated_vrt_serv_name if name is None else name,
                    ipv4address=ipv4address,
                    ports=ports,
                    sharing_protocols=sharing_protocols,
                    san_pool=san_pool,
                    sp=sp,
                    subnet=subnet,
                    gateway=gateway)
        return vrt_ser

    def create_pool(self, sfs_service, name=None):
        self.pool_counter.inc(sfs_service)
        if not name:
            self.pool_name_counter += 1
        generated_pool_name = "pool%s" % self.pool_name_counter
        pool = self.create_item("sfs-pool",
                "%s/pools/pool%s" % (sfs_service.get_vpath(), self.pool_counter[sfs_service]),
                name=generated_pool_name if name is None else name,
                )
        return pool

    def create_cache(self, sfs_pool, sfs_service, name=None):
        self.cache_counter.inc(sfs_service)
        if not name:
            self.cache_name_counter += 1
        generated_cache_name = "cache%s" % self.cache_name_counter
        cache = self.create_item("sfs-cache",
                "%s/cache_objects/cache%s" % (sfs_pool.get_vpath(), self.cache_counter[sfs_service]),
                name=generated_cache_name if name is None else name,
                )
        return cache

    def create_filesystem(self, sfs_pool, path=None, size="1G", data_reduction="true", cache_name=None,
            snap_size=None, backup_policy=None, provider=None):
        self.filesystem_counter.inc(sfs_pool)
        if not path:
            self.path_name_counter += 1
        generated_path_name = "/vx/path-%s" % self.path_name_counter
        params = dict(
            path=generated_path_name if path is None else path,
            size=size,
            data_reduction=data_reduction)
        if snap_size:
            params["snap_size"] = snap_size
        if cache_name:
            params["cache_name"] = cache_name
        if backup_policy:
            params["backup_policy"] = backup_policy
        if provider:
            params["provider"] = provider
        filesystem = self.create_item("sfs-filesystem",
                "%s/file_systems/fs%s" % (
                    sfs_pool.get_vpath(), self.filesystem_counter[sfs_pool]),
                **params)
        return filesystem

    def create_export(self, sfs_filesystem, clients="10.10.10.10", options="rw,no_root_squash"):
        self.export_counter.inc(sfs_filesystem)
        export = self.create_item("sfs-export",
                "%s/exports/ex%s" % (sfs_filesystem.get_vpath(), self.export_counter[sfs_filesystem]),
                ipv4allowed_clients=clients,
                options=options,)
        return export

    def create_nfs_mount(self, export_path=None, mount_point=None, mount_options="soft", provider="vsvr1", network_name="storage"):
        self.nfs_mount_counter += 1
        nfs_mount = self.create_item("nfs-mount",
                "/infrastructure/storage/nfs_mounts/nfs_mount%s" % self.nfs_mount_counter,
                export_path=export_path,
                provider=provider,
                mount_point=("/tmp%s" % self.nfs_mount_counter) if mount_point is None else mount_point,
                mount_options=mount_options,
                network_name=network_name,)
        return nfs_mount

    def create_inherited_mount(self, node, inherited_mount):
        self.nfs_inherited_mount_counter.inc(node)
        nfs_mount_node = self.create_inherited(
                inherited_mount.get_vpath(),
                "%s/file_systems/fs%s" % (node.get_vpath(), self.nfs_inherited_mount_counter[node]))
        return nfs_mount_node

    def set_applied(self, model_item):
        model_item.set_applied()
        model_item.applied_properties = model_item.properties

    def setUp_min_base_model(self):
        self.model = ModelManager()
        self.puppet_manager = PuppetManager(self.model)
        self.plugin_manager = PluginManager(self.model)
        self.api = PluginApiContext(self.model)
        self.execution = ExecutionManager(self.model,
                                          self.puppet_manager,
                                          self.plugin_manager)
        self.callback_api = CallbackApi(self.execution)
        self.plugin_manager.add_property_types(
            CoreExtension().define_property_types())
        self.plugin_manager.add_item_types(
            CoreExtension().define_item_types())

        self.plugin_manager.add_property_types(
            NasExtension().define_property_types())
        self.plugin_manager.add_item_types(
            NasExtension().define_item_types())

        # Add network API and Plugin for network_name validation
        self.plugin_manager.add_property_types(
                NetworkExtension().define_property_types())
        self.plugin_manager.add_item_types(
                NetworkExtension().define_item_types())

        # Add volmgr API and Plugin for mount point validation
        self.plugin_manager.add_property_types(
                VolMgrExtension().define_property_types())
        self.plugin_manager.add_item_types(
                VolMgrExtension().define_item_types())

        # Add default minimal model (which creates '/' root item)
        self.model.create_core_root_items()
        self.create_item("deployment", "/deployments/d1")
        self.cluster = self.create_item("cluster",
               "/deployments/d1/clusters/c1")
        self.cluster.set_applied()

    def assertRaisesWithMessageIn(self, exc_class, msg, func, *args, **kwargs):
        try:
            func(*args, **kwargs)
            self.assertTrue(False, "There should be an exception that is instance of %s with message \"%s\"" % (exc_class.__name__, msg))
        except AssertionError:
            pass
        except Exception as inst:
            if isinstance(inst, exc_class):
                if msg not in inst.message:
                    self.assertTrue(False, "Exception should contain message \"%s\"" % (msg))
            else:
                self.assertTrue(False, "The exception should be instance of %s with message \"%s\", but it is instance of %s" % (exc_class.__name__, msg, inst.__class__.__name__))

    def query(self, item_type=None, **kwargs):
        return self.api.query(item_type, **kwargs)

    def query_parent(self, item, item_type):
        if not item:
            return
        if item.item_type_id == item_type:
            return item
        return self.query_parent(item.parent, item_type)
