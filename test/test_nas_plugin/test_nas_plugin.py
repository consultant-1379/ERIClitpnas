##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import mock
import re
import unittest
import base64
import os
from NASStringIO import NASStringIO as StringIO
from paramiko import RSAKey

from litp.core.execution_manager import ExecutionManager, \
                                        CallbackExecutionException, \
                                        PluginError
from litp.core.task import ConfigTask, CallbackTask
from litp.core.rpc_commands import RpcExecutionException
from litp.plan_types.restore_snapshot import restore_snapshot_tags
from nas_plugin.nas_plugin import NasPlugin, NasConnectionCallback, in_ip
from naslib.nasexceptions import NasException, NasConnectionException, \
                                 DoesNotExist
from naslib.nasmock.mockexceptions import MockException
from naslib.drivers.sfs.sfsmock.main import SfsMock
from naslib.drivers.sfs.sfsmock.dbresources import ANY_GENERIC_ERROR
from naslib.drivers.sfs.resources import ShareResource
from nas_plugin.nas_cmd_api import NasCmdApiException
from naslib.objects import Share, Cache, Snapshot, FileSystem, NasServer
from naslib import NasDrivers
from naslib.unityxt.mock_requests import UnityRESTMocker
from utils import get_task_props, IpAddressHelper, TestNasPluginBase, \
                  NasConnectionCallbackMock


class TestNasPlugin(TestNasPluginBase):

    def setUp(self):
        """
        Construct a model, sufficient for test cases
        that you wish to implement in this suite.
        """
        # Instantiate your plugin and register with PluginManager
        super(TestNasPlugin, self).setUp()
        self.plugin = NasPlugin()
        self.plugin.nfs_connection_class = NasConnectionCallbackMock
        self.plugin_manager.add_plugin('NasPlugin', 'nas_plugin.nas_plugin',
                                       '1.0.1-SNAPSHOT', self.plugin)
        self.password_patcher = mock.patch('litp.core.base_plugin_api._SecurityApi.get_password')
        self.password_patch = self.password_patcher.start()
        self.password_patch.return_value = 'password'

    def tearDown(self):
        self.password_patch.stop()

    def setup_sfs_virtual_server(self, managed=False, applied=True, pool_name=None, sfs_nas_type='veritas'):
        self.node1 = self.create_node()
        self.sfs_service1 = self.create_sfs_service(managed=managed, sfs_nas_type=sfs_nas_type)
        self.sfs_virt1 = self.create_virtual_server(self.sfs_service1)
        created_items = [self.node1, self.sfs_service1, self.sfs_virt1]
        if managed:
            self.pool1 = self.create_pool(self.sfs_service1, name=pool_name)
            self.pool2 = self.create_pool(self.sfs_service1)
            self.pool3 = self.create_pool(self.sfs_service1)
            self.pool4 = self.create_pool(self.sfs_service1)
            self.pool5 = self.create_pool(self.sfs_service1)
            created_items.append(self.pool1)
        if applied:
            for item in created_items:
                item.set_applied()

    def setup_nfs_service(self, ipv6=False, ipv4=False):
        params = {}
        if ipv6:
            params["ipv6address"] = "2001::100"
        if ipv4:
            params["ipv4address"] = "10.10.10.100"
        nfs_service = self.create_nfs_service(name="vsvr1", **params)

    def setup_non_sfs_unmanaged_model(self, ipv6=False, ipv4=False):

        self.node1 = self.create_node()

        params = {}
        if ipv6:
            params.update({"ipv6address": "2001::1"})
        if ipv4:
            params.update({"ipaddress": "10.10.10.1"})
        self.eth0 = self.create_network_interface(self.node1, network_name="storage", **params)

        params = {}
        if ipv6:
            params.update({"ipv6address": "2002::1"})
        if ipv4:
            params.update({"ipaddress": "20.20.20.1"})
        self.eth1 = self.create_network_interface(self.node1, network_name="fake", **params)

        params = {}
        if ipv6:
            params.update({"ipv6": True})
        if ipv4:
            params.update({"ipv4": True})

        self.setup_nfs_service(**params)

    def setup_dual_stack_network_model(self):
        self.setup_sfs_virtual_server(managed=False)
        self.node1 = self.create_node()
        self.eth0 = self.create_network_interface(self.node1, network_name="mgmt",
                                                  ipaddress="10.10.10.101",
                                                  ipv6address="fe80::baca:3aff:fe96:8da4/64")
        self.eth1 = self.create_network_interface(self.node1, network_name="fake",
                                                  ipaddress="192.168.100.1")
        nfs_service = self.create_nfs_service(ipv4address="10.10.10.10", ipv6address="fe80::baca:3aff:fe96:8da5")

        nfs_mount = self.create_nfs_mount(export_path="/vx/abcde-fs1", provider=nfs_service.name,
                                          network_name=self.eth0.network_name)
        self.create_inherited_mount(self.node1, nfs_mount)

    def test_create_configuration_unmanaged(self):
        self.setup_sfs_virtual_server(managed=False)
        self.eth0 = self.create_network_interface(self.node1, network_name="storage",
                                                  ipaddress="10.10.10.101")
        nfs_mount = self.create_nfs_mount(export_path="/vx/abcde-fs1")
        self.create_inherited_mount(self.node1, nfs_mount)
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 1)

    def setup_create_configuration_test_environment(self, sfs_nas_type='veritas'):
        number = 5
        self.node1 = self.create_node()
        self.node2 = self.create_node()
        self.nodes = [self.node1, self.node2]
        self.ms = self.api.query("ms")[0]
        self.setup_sfs_virtual_server(
            managed=True, applied=False, pool_name="SFS_Pool", sfs_nas_type=sfs_nas_type)
        exports = []
        filesystems = []
        for i in xrange(1, number + 1):
            fs = self.create_filesystem(
                self.pool1, path="/vx/abcde-fs%s" % i, size="1G")
            exports.append(self.create_export(fs))
            filesystems.append(fs)
        mounts = []
        storage_profile = self.create_storage_profile()
        for node in self.nodes:
            self.create_inherited(storage_profile.get_vpath(), "%s/storage_profile" % node.get_vpath())
        self.create_inherited(storage_profile.get_vpath(), "/ms/storage_profile")
        for i, export in enumerate(exports):
            nfs_mount = self.create_nfs_mount(
                export_path=export.parent.parent.path,
                provider=self.sfs_virt1.name,
                mount_options="soft",
                network_name="storage"
            )
            mount_nodes = []
            for node in self.nodes:
                node_fs = self.create_inherited_mount(node, nfs_mount)
                mount_nodes.append(node_fs)
            ms_fs = self.create_inherited_mount(self.ms, nfs_mount)
            mount_nodes.append(ms_fs)
            mounts.append((nfs_mount, mount_nodes))
        return self.sfs_service1, exports, mounts, filesystems

    def test_create_configuration(self):
        """ This test runs success path and fail path tests for
        create_configuration method, considering a simulation of running
         the tasks and changing it's states properly.
        """

        # positive first
        self._test_create_configuration_success()

        # now negative tests
        self._test_create_configuration_fail()

    def test_unityxt_validate_okay(self):
        self.setup_sfs_virtual_server(
            managed=True,
            applied=False,
            pool_name="XT",
            sfs_nas_type='unityxt'
        )
        self._remove_empty_pools_from_set_up()

        fs = self.create_filesystem(
            self.pool1,
            path="/XT-testfs",
            size="3G"
        )
        fs.set_property('provider', 'vsvr1')

        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)

    def test_unityxt_validate_fail(self):
        self.setup_sfs_virtual_server(
            managed=True,
            applied=False,
            pool_name="XT",
            sfs_nas_type='unityxt'
        )
        self._remove_empty_pools_from_set_up()

        # Too small
        self.create_filesystem(
            self.pool1,
            path="/XT-testfs1",
            size="1G",
            provider='vsvr1'
        )

        # Missing provider
        self.create_filesystem(
            self.pool1,
            path="/XT-testfs2",
            size="3G"
        )

        # Bad provider
        self.create_filesystem(
            self.pool1,
            path="/XT-testfs3",
            size="3G",
            provider='badsrv'
        )

        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 3)

    @mock.patch('nas_plugin.nas_plugin.NasPlugin.nfs_server_creation_callback')
    def test_unityxt_create_fsshare(self, m_server_creation):
        m_server_creation.return_value = []
        json_file_name = "%s/test_unityxt_create_fsshare.json" % os.path.dirname(os.path.abspath(__file__))
        UnityRESTMocker.setup("10.44.86.226")
        UnityRESTMocker.reset()
        UnityRESTMocker.load(json_file_name)

        self.setup_sfs_virtual_server(
            managed=True,
            applied=False,
            pool_name="XT",
            sfs_nas_type='unityxt'
        )
        fs = self.create_filesystem(
            self.pool1,
            path="/vx/XT-testfs",
            size="1G"
        )
        fs.set_property('provider', 'vsvr1')
        export = self.create_export(fs)

        nfs_mount = self.create_nfs_mount(
            export_path=export.parent.parent.path,
            provider=self.sfs_virt1.name,
            mount_options="soft",
            network_name="storage"
        )

        self.node1 = self.create_node()
        self.node2 = self.create_node()
        self.nodes = [self.node1, self.node2]
        self.ms = self.api.query("ms")[0]

        storage_profile = self.create_storage_profile()
        for node in self.nodes:
            self.create_inherited(storage_profile.get_vpath(), "%s/storage_profile" % node.get_vpath())
        self.create_inherited(storage_profile.get_vpath(), "/ms/storage_profile")

        mount_nodes = []
        for node in self.nodes:
            node_fs = self.create_inherited_mount(node, nfs_mount)
            mount_nodes.append(node_fs)
        ms_fs = self.create_inherited_mount(self.ms, nfs_mount)
        mount_nodes.append(ms_fs)

        save_class = self.plugin.nfs_connection_class
        self.plugin.nfs_connection_class = NasConnectionCallback
        tasks = self.plugin.create_configuration(self.api)
        self._run_tasks_test(
            tasks,
            [export],
            [(nfs_mount, mount_nodes)],
            sfs_nas_type='unityxt'
        )
        self.plugin.nfs_connection_class = save_class

    def test_unityxt_create_snapshot(self):
        json_file_name = "%s/test_unityxt_create_snapshot.json" % os.path.dirname(os.path.abspath(__file__))
        UnityRESTMocker.setup("10.44.86.226")
        UnityRESTMocker.reset()
        UnityRESTMocker.load(json_file_name)

        self.setup_sfs_virtual_server(
            managed=True,
            applied=True,
            pool_name="XT",
            sfs_nas_type='unityxt'
        )
        fs = self.create_filesystem(
            self.pool1,
            path="/XT-testfs",
            size="1G",
            snap_size=10
        )
        fs.set_property('provider', 'vsvr1')
        self.set_applied(fs)

        self.api.snapshot_action = mock.MagicMock(return_value='create')
        self.api.snapshot_name = mock.MagicMock(return_value='OMBS')
        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'OMBS', timestamp=None)
        self.api._snapshot_object = mock.MagicMock(return_value=snap_item)

        save_class = self.plugin.nfs_connection_class
        self.plugin.nfs_connection_class = NasConnectionCallback

        tasks = self.plugin.create_snapshot_plan(self.api)
        for task in tasks:
            if task.callback == self.plugin._create_snapshot:
                self.assertIn('Create NAS named backup snapshot "L_', task.description)
                self.assertTrue(isinstance(task, CallbackTask), True)
                self.plugin._create_snapshot(
                    self.callback_api, *task.args, **task.kwargs)

        self.plugin.nfs_connection_class = save_class

    def _test_create_configuration_success(self, sfs_nas_type='veritas'):
        """ Tests successful cases of create_configuration
        """
        service, exports, mounts, filesystems = self.setup_create_configuration_test_environment(sfs_nas_type)
        tasks = self.plugin.create_configuration(self.api)
        # 20 tasks should be created:
        #  - 5 file systems -> 1 fs per each
        #  - 5 shares -> 1 share per each
        #  - 5 mounts -> 1 mount per export for node 1
        #  - 5 mounts -> 1 mount per export for node 2
        #  - 5 mounts -> 1 mount per export for ms
        self.assertTaskCount(tasks, 26)
        # for the 25 tasks:
        #  - 10 should be CallBackTasks: regarding 5 shares and 5 fs
        #  - 15 should be ConfigTasks: regarding 15 mounts, 5 per node and ms
        cbts = [t for t in tasks if isinstance(t, CallbackTask)]
        config_tasks = [t for t in tasks if isinstance(t, ConfigTask)]
        self.assertTaskCount(cbts, 11)
        self.assertTaskCount(config_tasks, 15)
        self.assertTrue(service.is_initial())
        # tests the requires
        cb_dict = self.plugin.callback_tasks_by_export_path(cbts)
        for task in config_tasks:
           if not task.node.is_ms():
               continue
           path = task.model_item.export_path
           provider = task.model_item.provider
           self.assertTrue(provider in cb_dict)
           self.assertTrue(path in cb_dict[provider])
           self.assertEquals(task.requires, set([cb_dict[provider][path]]))
        plan = self.execution.create_plan()
        # let's simulate running the tasks, to check states and mark as applied
        self._run_tasks_test(tasks, exports, mounts)
        # after running, all should be applied
        service.set_applied()
        self.assertTrue(service.is_applied())
        cred = self.plugin.get_security_credentials(self.api)
        self.assertEquals(cred, [('user', 'password')])

    def _test_create_configuration_fail(self):
        """ Tests failure cases of create_configuration
        """
        vs_provider = 'vsvr1'

        # creating a new export but with a huge size 9999999 tera bytes
        fs = self.create_filesystem(
            self.pool1, path="/vx/abcde-fs%s" % 6, size="9999999T")
        export = self.create_export(fs,
                              clients="10.10.10.13")
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 3)
        self.assertTrue(isinstance(tasks[0], CallbackTask))
        self.assertTrue(getattr(tasks[0], 'is_nas_callback_task', False))
        self.assertTrue(isinstance(tasks[1], CallbackTask))
        self.assertTrue(getattr(tasks[1], 'is_nas_callback_task', False))
        self.assertTrue(isinstance(tasks[2], CallbackTask))
        self.assertEquals(tasks[2].callback, self.plugin.get_and_save_remote_host_key_callback)
        self.assertIn(tasks[2], tasks[0].requires)
        self.assertIn(tasks[2], tasks[1].requires)
        try:
            self._run_tasks_test(tasks, [export], [])
            self.assertTrue(False, "Must raise CallbackExecutionException.")
        except CallbackExecutionException, err:
            msg = "FS creation failed: SFS fs ERROR V-288-921 Unable to " \
                  "create fs abcde-fs6 due to either insufficient " \
                  "space/unavailable disk. Please run scanbus.. Command: " \
                  "storage fs create simple abcde-fs6 9999999T SFS_Pool"
            self.assertEqual(str(err), msg)
        tasks = self.plugin.create_configuration(self.api)
        self.assertTrue(isinstance(tasks[0], CallbackTask))
        self.assertTrue(getattr(tasks[0], 'is_nas_callback_task', False))
        self.assertTrue(isinstance(tasks[1], CallbackTask))
        self.assertTrue(getattr(tasks[1], 'is_nas_callback_task', False))
        self.assertTrue(isinstance(tasks[2], CallbackTask))
        self.assertEquals(tasks[2].callback, self.plugin.get_and_save_remote_host_key_callback)
        self.assertIn(tasks[2], tasks[0].requires)
        self.assertIn(tasks[2], tasks[1].requires)
        self.assertTaskCount(tasks, 3)  # because is still in initial state
        self.assertTrue(export.is_initial())

        # trying to create an export with fs name that already exists in SFS
        # but with different arguments
        # actually I know the fs ST66-fs2 already exists in
        # resources.initial.json mock DB
        false_fs = self.create_filesystem(
            self.pool1, path="/vx/ST66-fs2", size="15M")
        export = self.create_export(false_fs,
                              clients="10.10.10.13")
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 5)
        self.assertEquals(tasks[0].kwargs['size'], '9999999T')
        tasks.pop(0)  # removes the previous failed task
        tasks.pop(0)  # and it's dependant
        self.assertTaskCount(tasks, 3)
        self.assertTrue(isinstance(tasks[0], CallbackTask))
        self.assertTrue(getattr(tasks[0], 'is_nas_callback_task', False))
        self.assertTrue(isinstance(tasks[1], CallbackTask))
        self.assertTrue(getattr(tasks[1], 'is_nas_callback_task', False))
        self.assertTrue(isinstance(tasks[2], CallbackTask))
        self.assertEquals(tasks[2].callback, self.plugin.get_and_save_remote_host_key_callback)
        self.assertIn(tasks[2], tasks[0].requires)
        self.assertIn(tasks[2], tasks[1].requires)
        try:
            self._run_tasks_test(tasks, [export], [])
            self.assertTrue(False, "Must raise CallbackExecutionException.")
        except CallbackExecutionException, err:
            msg = 'The file system "ST66-fs2" already exists on ' \
                  'NAS but its attributes don\'t match: size: ' \
                  '"1.00G" != "15M"'
            self.assertEqual(str(err), msg)

        # trying to create a managed mount but with different options
        # actually I know that the share 10.10.10.13
        # already exists and has the option (rw,no_root_squash). It is stored into
        # resources.initial.json as a mock DB.
        fs = self.create_filesystem(
            self.pool1, path="/vx/Int67-int67", size="6G")
        export = self.create_export(fs, clients="10.44.235.42")
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 7)
        self.assertTrue(isinstance(tasks[0], CallbackTask))
        self.assertEquals(tasks[0].kwargs['size'], '9999999T')
        tasks.pop(0)  # removes the previous failed task
        tasks.pop(0)  # and it's dependant
        self.assertTaskCount(tasks, 5)
        self.assertTrue(isinstance(tasks[0], CallbackTask))
        self.assertTrue(getattr(tasks[0], 'is_nas_callback_task', False))
        self.assertTrue(isinstance(tasks[1], CallbackTask))
        self.assertTrue(getattr(tasks[1], 'is_nas_callback_task', False))
        self.assertTrue(isinstance(tasks[2], CallbackTask))
        self.assertTrue(getattr(tasks[2], 'is_nas_callback_task', False))
        self.assertTrue(isinstance(tasks[3], CallbackTask))
        self.assertTrue(getattr(tasks[3], 'is_nas_callback_task', False))
        self.assertTrue(isinstance(tasks[4], CallbackTask))
        self.assertEquals(tasks[4].callback, self.plugin.get_and_save_remote_host_key_callback)
        self.assertIn(tasks[4], tasks[0].requires)
        self.assertIn(tasks[4], tasks[1].requires)
        self.assertIn(tasks[4], tasks[2].requires)
        self.assertIn(tasks[4], tasks[3].requires)
        tasks.pop(0)
        tasks.pop(0)
        self.assertTrue(isinstance(tasks[0], CallbackTask))
        try:
            self._run_tasks_test(tasks, [export], [])
            self.assertTrue(False, "Must raise CallbackExecutionException.")
        except CallbackExecutionException, err:
            msg = 'The share "/vx/Int67-int67" already exists in NAS but ' \
                  'it\'s options do not match: "rw,sync,no_root_squash" != ' \
                  '"rw,no_root_squash"'
            self.assertEqual(str(err), msg)

        # trying to create a managed mount with same options
        # actually I know that the share 10.10.10.13
        # already exists and has the option (rw,no_root_squash).
        # It is stored into resources.initial.json as a mock DB.
        fs = self.create_filesystem(
            self.pool1, path="/vx/Int67-int67", size="6G")

        self.model.remove_item("%s/exports/ex%s" % (fs.get_vpath(), export.get_vpath()))
        export = self.create_export(fs, clients="10.44.235.42",
                                    options='rw,sync,no_root_squash')
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 7)
        self.assertTrue(isinstance(tasks[0], CallbackTask))
        self.assertEquals(tasks[0].kwargs['size'], '9999999T')
        tasks.pop(0)  # removes the previous failed task
        tasks.pop(0)  # and it's dependant
        self.assertTaskCount(tasks, 5)
        self.assertTrue(isinstance(tasks[0], CallbackTask))
        self.assertTrue(getattr(tasks[0], 'is_nas_callback_task', False))
        self.assertTrue(isinstance(tasks[1], CallbackTask))
        self.assertTrue(getattr(tasks[1], 'is_nas_callback_task', False))
        self.assertTrue(isinstance(tasks[2], CallbackTask))
        self.assertTrue(getattr(tasks[2], 'is_nas_callback_task', False))
        self.assertTrue(isinstance(tasks[3], CallbackTask))
        self.assertTrue(getattr(tasks[3], 'is_nas_callback_task', False))
        self.assertTrue(isinstance(tasks[4], CallbackTask))
        self.assertEquals(tasks[4].callback, self.plugin.get_and_save_remote_host_key_callback)
        self.assertIn(tasks[4], tasks[0].requires)
        self.assertIn(tasks[4], tasks[1].requires)
        self.assertIn(tasks[4], tasks[2].requires)
        self.assertIn(tasks[4], tasks[3].requires)
        tasks.pop(0)
        tasks.pop(0)
        self.assertTrue(isinstance(tasks[0], CallbackTask))
        self._run_tasks_test(tasks, [export], [])

        fs = self.create_filesystem(self.pool1, path="/vx/Int14-test_5010",
                                    size="10M")
        export = self.create_export(fs, clients="192.168.1.2")
        tasks = self.plugin.create_configuration(self.api)
        ntasks = tasks[:2] + [tasks[-1]]
        self._run_tasks_test(ntasks, [export], [])

        # testing Faulted Share
        path = '/vx/ST72-fs2'
        client = "10.44.86.72"
        share_id = "%s (%s)" % (path, client)
        fs = self.create_filesystem(self.pool1, path=path, size="1G")
        export = self.create_export(fs, clients=client)
        tasks = self.plugin.create_configuration(self.api)
        try:
            self._run_tasks_test(tasks[0:2], [export], [])
        except CallbackExecutionException, err:
            msg = 'The share "%s" already exists in NAS but is in a ' \
                  'faulted state.' % share_id
            self.assertEqual(str(err), msg)

        # trying to create an export with fs name that already exists in SFS
        # but with different arguments
        # actually I know the fs Int14-storobs_14 already exists in
        # resources.initial.json mock DB
        false_fs = self.create_filesystem(
            self.pool1, path="/vx/Int14-storobs_14", size="15M")
        export = self.create_export(false_fs,
                              clients="10.10.10.13")
        tasks = self.plugin.create_configuration(self.api)[:2]

        self.assertTrue(isinstance(tasks[0], CallbackTask))
        try:
            self._run_tasks_test(tasks, [export], [])
            self.assertTrue(False, "Must raise CallbackExecutionException.")
        except CallbackExecutionException, err:
            msg = 'The file system "Int14-storobs_14" already exists on NAS ' \
                  'but its attributes don\'t match: size: "100.00M" != "15M"'
            self.assertEqual(str(err), msg)

    def _run_tasks_test(
        self,
        tasks,
        exports,
        mounts,
        fs_already_exist=False,
        sfs_nas_type='veritas'
    ):
        """ Gets tasks previously from create_configuration method and
        "simulates" a run plan just to assert its results and model items
        states.
        """
        fs_regex = re.compile(r"^Create file system \"([\w-]+)\"")
        path_regex = re.compile(r"^Create exports for \"([/\w-]+)\"")
        mount_regex = re.compile(r'Mount share "([/\w-]+)" on node "([\.\w-]+)"')
        def _get_export(path):
            return [e for e in exports if e.parent.parent.path == path][0]
        def _get_export_fs(fs):
            return [e for e in exports
                if e.parent.parent.path.split('/')[-1] == fs][0]
        ms_mounts = []
        host_keys_tasks = {}
        sfs_services = set()
        no_callback_tasks = True
        for task in tasks:
            if isinstance(task, CallbackTask):
                no_callback_tasks = False
                par_service = self.query_parent(task.model_item, 'sfs-service')
                self.assertTrue(bool(par_service))
                self.assertEquals(par_service.item_type_id, 'sfs-service')
                sfs_services.add(par_service.get_vpath())
                exp = None
                if task.callback == self.plugin.nfs_fs_creation_callback:
                    if not fs_already_exist:
                        fs_match = fs_regex.match(task.description)
                        self.assertTrue(fs_match is not None)
                        exp = _get_export_fs(fs_match.groups()[0])
                        self.assertTrue(exp.is_initial())
                        self.plugin.nfs_fs_creation_callback(self.callback_api,
                                                    *task.args, **task.kwargs)
                elif task.callback == self.plugin.nfs_shares_creation_callback:
                    path_match = path_regex.match(task.description)
                    if exp is None:
                        exp = _get_export(path_match.groups()[0])
                    self.assertTrue(path_match is not None)
                    self.plugin.nfs_shares_creation_callback(self.callback_api,
                        *task.args, **task.kwargs)
                elif task.callback == self.plugin.get_and_save_remote_host_key_callback:
                    self.assertIn('sfs_service_vpath', task.kwargs)
                    serv = task.kwargs['sfs_service_vpath']
                    self.assertNotIn(serv, host_keys_tasks, "Must be 1 host key task per service")
                    host_keys_tasks[serv] = task
                    continue
                elif task.callback == self.plugin.nfs_server_creation_callback:
                    continue
                else:
                    self.assertTrue(False, "Unknown task %s for this test." % task)
                exp.set_applied()
                exp.parent.parent.set_applied()
            elif isinstance(task, ConfigTask):
                match = mount_regex.match(task.description)
                self.assertTrue(match)
                path, node = match.groups()
                ms, n = [(m, t) for m, t in mounts if m.export_path == path][0]
                self.assertTrue(ms.is_initial())
                ms_mounts.append(ms)
                [i.set_applied() for i in n]
            else:
                self.assertTrue(False, "%s should be a Task base." % task)
        [i.set_applied() for i in ms_mounts]
        if no_callback_tasks:
            if sfs_nas_type == 'veritas':
                self.assertFalse(bool(host_keys_tasks))
            self.assertEquals(len(sfs_services), 0)
        else:
            self.assertEquals(len(sfs_services), 1)
            if sfs_nas_type == 'veritas':
                self.assertTrue(bool(host_keys_tasks))
                self.assertEquals(len(host_keys_tasks), 1)
                self.assertEquals(host_keys_tasks.keys()[0], list(sfs_services)[0])
                self.assertEquals(list(sfs_services)[0],
                                host_keys_tasks.values()[0].kwargs['sfs_service_vpath'])
                self.assertEquals(list(sfs_services)[0],
                                host_keys_tasks.values()[0].model_item.get_vpath())

    def _remove_empty_pools_from_set_up(self):
        for pool in [self.pool2, self.pool3, self.pool4, self.pool5]:
            pool.set_for_removal()

    def test_fs_change_dr_callback(self):
        json_file_name = "%s/test_unityxt_change_data_reduction.json" % os.path.dirname(os.path.abspath(__file__))
        UnityRESTMocker.setup("10.44.86.226")
        UnityRESTMocker.reset()
        UnityRESTMocker.load(json_file_name)

        self.setup_sfs_virtual_server(
            managed=True,
            applied=True,
            pool_name="XT",
            sfs_nas_type='unityxt'
        )
        self._remove_empty_pools_from_set_up()
        self.fs1 = self.create_filesystem(
                                self.pool1, path="/enm1-stor", size="3G",
                                data_reduction="true", provider="vsvr1"
        )
        self.fs2 = self.create_filesystem(
                                self.pool1, path="/enm2-stor", size="4G",
                                data_reduction="true", provider="vsvr1"
        )
        self.fs3 = self.create_filesystem(
                                self.pool1, path="/enm3-stor", size="5G",
                                data_reduction="true", provider="vsvr1"
        )
        self.fs3.set_applied()
        self.update_item(self.fs1, data_reduction="false")
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 2)
        creation_callback = next(
            (t for t in tasks if t.callback == self.plugin.nfs_fs_creation_callback), None)
        self.assertIsNotNone(creation_callback)

        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            exc_message = "DUMMY MESSAGE pool does not exist"
            nfs.filesystem.create.return_value = FileSystem.CreationException(
                exc_message)
            self.assertRaisesWithMessageIn(
                CallbackExecutionException,
                exc_message,
                self.plugin.nfs_fs_creation_callback,
                self.callback_api,
                *creation_callback.args,
                **creation_callback.kwargs)
            nfs.filesystem.create.assert_called_with(
                self.fs2.path[1:], self.fs2.size, self.pool1.name, 'vsvr1', self.fs2.data_reduction)
        dr_callback = next(
            (t for t in tasks if t.callback == self.plugin.nfs_fs_change_dr_callback), None)
        self.assertIsNotNone(dr_callback)
        self.assertEquals(dr_callback.kwargs['name'], self.fs1.path[1:])
        self.assertEquals(dr_callback.kwargs['data_reduction'], self.fs1.data_reduction)

    def test_fs_resize_callback(self):
        self.setup_sfs_virtual_server(
            managed=True,
            pool_name="SFS_Pool",
            sfs_nas_type='veritas'
        )
        self._remove_empty_pools_from_set_up()
        self.fs1 = self.create_filesystem(
                                self.pool1, path="/vx/enm1-stor", size="10M")
        self.fs2 = self.create_filesystem(
                                self.pool1, path="/vx/enm2-stor", size="11M")
        self.fs3 = self.create_filesystem(
                                self.pool1, path="/vx/enm3-stor", size="12M")
        self.fs3.set_applied()
        self.update_item(self.fs1, size="20M")
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 3)
        self.assertHostKeyTaskInTasks(tasks)
        creation_callback = next(
            (t for t in tasks if t.callback == self.plugin.nfs_fs_creation_callback), None)
        self.assertIsNotNone(creation_callback)

        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            exc_message = "DUMMY MESSAGE pool does not exist"
            nfs.filesystem.create.return_value = FileSystem.CreationException(
                exc_message)
            self.assertRaisesWithMessageIn(
                CallbackExecutionException,
                exc_message,
                self.plugin.nfs_fs_creation_callback,
                self.callback_api,
                *creation_callback.args,
                **creation_callback.kwargs)
            nfs.filesystem.create.assert_called_with(
                self.fs2.path[4:], self.fs2.size, self.pool1.name, 'simple')
        resize_callback = next(
            (t for t in tasks if t.callback == self.plugin.nfs_fs_resize_callback), None)
        self.assertIsNotNone(resize_callback)
        self.assertEquals(resize_callback.kwargs['name'], self.fs1.path[4:])
        self.assertEquals(resize_callback.kwargs['size'], self.fs1.size)

        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            self.plugin.nfs_fs_resize_callback(self.callback_api, *resize_callback.args, **resize_callback.kwargs)
            nfs.filesystem.resize.assert_called_with(self.fs1.path[4:], self.fs1.size, pool=self.pool1.name)

    def test_nfs_shares_creation_callback(self):
        self.setup_sfs_virtual_server(managed=True)
        self._remove_empty_pools_from_set_up()
        self.eth0 = self.create_network_interface(self.node1, network_name="storage", ipaddress="10.10.10.12")
        fs = self.create_filesystem(self.pool1, size="20M")
        fs.set_applied()
        sfs_export1 = self.create_export(fs, clients="10.10.10.11,10.10.10.12", options="rw,no_root_squash")
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        tasks = self.plugin.create_configuration(self.api)
        creation_share_task = next((task for task in tasks if task.callback == self.plugin.nfs_shares_creation_callback), None)
        self.assertNotEquals(creation_share_task, None)

        # Raising exception for faulted share
        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            faulted_share = Share(nfs.share, fs.path, sfs_export1.ipv4allowed_clients, sfs_export1.options)
            faulted_share.faulted = True
            nfs.share.get.return_value = faulted_share
            self.assertRaises(Share.CreationException, self.plugin.nfs_shares_creation_callback,
                              self.callback_api, *creation_share_task.args, **creation_share_task.kwargs)

        # Checking for successful creation of shares
        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            nfs.share.get.return_value = None
            nfs.share.get.side_effect = Share.DoesNotExist
            self.plugin.nfs_shares_creation_callback(self.callback_api, *creation_share_task.args, **creation_share_task.kwargs)
            self.assertEquals(nfs.share.create.mock_calls, [
                mock.call(fs.path, '10.10.10.11', sfs_export1.options),
                mock.call(fs.path, '10.10.10.12', sfs_export1.options)])

        # Raising exception for creating the same share but with different options
        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            nfs.share.get.return_value = Share(nfs.share, sfs_export1.get_vpath(), sfs_export1.ipv4allowed_clients, "rw")
            self.assertRaises(Share.CreationException, self.plugin.nfs_shares_creation_callback,
                              self.callback_api, *creation_share_task.args, **creation_share_task.kwargs)

        # Showing warning for every creation of a share that already exists
        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            nfs.share.get.side_effect = [
                Share(nfs.share, fs.path, '10.10.10.11', sfs_export1.options),
                Share(nfs.share, fs.path, '10.10.10.12', sfs_export1.options)]
            self.plugin.nfs_shares_creation_callback(self.callback_api, *creation_share_task.args, **creation_share_task.kwargs)

    def test_nfs_shares_update_callback(self):
        self.setup_sfs_virtual_server(managed=True)
        self._remove_empty_pools_from_set_up()
        self.eth0 = self.create_network_interface(self.node1, network_name="storage", ipaddress="10.10.10.12")
        fs = self.create_filesystem(self.pool1, size="20M")
        fs.set_applied()
        sfs_export1 = self.create_export(fs, clients="10.10.10.11,10.10.10.12", options="rw,no_root_squash")
        sfs_export1.set_for_removal()
        sfs_export2 = self.create_export(fs, clients="10.10.10.11,10.10.10.12", options="rw")
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        tasks = self.plugin.create_configuration(self.api)
        update_share_task = next((task for task in tasks if task.callback == self.plugin.nfs_shares_update_callback), None)
        self.assertNotEquals(update_share_task, None)
        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            self.plugin.nfs_shares_update_callback(self.callback_api, *update_share_task.args, **update_share_task.kwargs)
            self.assertEquals(nfs.share.create.mock_calls, [
                mock.call(fs.path, '10.10.10.11', sfs_export2.options),
                mock.call(fs.path, '10.10.10.12', sfs_export2.options)])
        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            nfs.share.create.side_effect = Share.AlreadyExists
            self.plugin.nfs_shares_update_callback(self.callback_api, *update_share_task.args, **update_share_task.kwargs)
            self.assertEquals(nfs.share.create.mock_calls, [
                mock.call(fs.path, '10.10.10.11', sfs_export2.options),
                mock.call(fs.path, '10.10.10.12', sfs_export2.options)])

    def test_nfs_shares_removal_callback(self):
        self.setup_sfs_virtual_server(managed=True)
        fs = self.create_filesystem(self.pool1, size="20M")
        fs.set_applied()
        sfs_export = self.create_export(fs, clients="10.10.10.11,10.10.10.12,10.10.10.13", options="rw,no_root_squash")
        sfs_export.set_applied()
        self.update_item(sfs_export, ipv4allowed_clients="10.10.10.11")
        tasks = self.plugin.create_configuration(self.api)
        remove_share_task = next((task for task in tasks if task.callback == self.plugin.nfs_shares_removal_callback), None)
        self.assertNotEquals(remove_share_task, None)

        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            self.plugin.nfs_shares_removal_callback(self.callback_api, *remove_share_task.args, **remove_share_task.kwargs)
            self.assertEquals(nfs.share.delete.mock_calls, [
               mock.call(fs.path, '10.10.10.13'),
               mock.call(fs.path, '10.10.10.12')])
        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            nfs.share.exists.return_value = False
            self.plugin.nfs_shares_removal_callback(self.callback_api, *remove_share_task.args, **remove_share_task.kwargs)
            self.assertEquals(nfs.share.delete.mock_calls, [])

    def test_update_clientaddr_option_callback(self):
        node1 = self.create_node()
        self.setup_nfs_network(node1, updated_interface=True, ipv6=True)
        self.setup_nfs_mount(node1, clientaddr=True, ipv6=True)
        self.nfs_mount_node1_1.set_applied()
        tasks = self.plugin.create_client_tasks(self.api, [])
        clientaddr_task = next(
            (task for task in tasks if task.callback == self.plugin.update_clientaddr_option_callback), None)
        new_mount_options = clientaddr_task.kwargs['new_options']
        self.assertNotEquals(self.nfs_mount_node1_1.mount_options, new_mount_options)
        self.plugin.update_clientaddr_option_callback(self.callback_api, *clientaddr_task.args, **clientaddr_task.kwargs)
        self.assertEquals(self.nfs_mount_node1_1.mount_options, new_mount_options)

    def test_service_for_removal(self):
        self.setup_sfs_virtual_server(managed=True)
        fs = self.create_filesystem(self.pool1, size="20M")
        self.create_export(fs, clients="10.10.10.11,10.10.10.12", options="rw,no_root_squash")
        self.sfs_service1.set_for_removal()
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 0)

    def test_export_create_snapshot_initial(self):
        '''
        there is a initial state that has applied properties when snapshot is
        created, this test may be removed if core decides to fix that
        '''
        self.setup_sfs_virtual_server(managed=True)
        fs = self.create_filesystem(self.pool1, size="20M")
        fs.set_applied()
        ex1 = self.create_export(fs, clients="10.10.10.11,10.10.10.12", options="rw,no_root_squash")
        ex1._applied_properties = ex1.properties
        ex2 = self.create_export(fs, clients="10.10.10.13", options="rw")
        ex2._applied_properties = ex2.properties
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 3)
        self.assertHostKeyTaskInTasks(tasks)

    def test_export_update_create(self):
        self.setup_sfs_virtual_server(managed=True)
        fs = self.create_filesystem(self.pool1, size="20M")
        fs.set_applied()
        self.create_export(fs, clients="10.10.10.11,10.10.10.12", options="rw,no_root_squash")
        self.create_export(fs, clients="10.10.10.13", options="rw")
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 3)
        self.assertHostKeyTaskInTasks(tasks)
        create_share_task = tasks[0]
        self.assertTrue(create_share_task is not None)
        self.assertEquals(create_share_task.kwargs['shares'][0]["clients"], list(('10.10.10.11','10.10.10.12',)))
        self.assertEquals(create_share_task.kwargs['shares'][0]["options"], 'rw,no_root_squash')
        create_share_task = tasks[1]
        self.assertTrue(create_share_task is not None)
        self.assertEquals(create_share_task.kwargs['shares'][0]["clients"], list(('10.10.10.13',)))
        self.assertEquals(create_share_task.kwargs['shares'][0]["options"], 'rw')

    def test_export_update_add(self):
        self.setup_sfs_virtual_server(managed=True)
        fs = self.create_filesystem(self.pool1, size="20M")
        fs.set_applied()
        sfs_export = self.create_export(fs, clients="10.10.10.11,10.10.10.12", options="rw,no_root_squash")
        self.update_item(sfs_export, ipv4allowed_clients="10.10.10.11,10.10.10.12,10.10.10.13")
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 2)
        self.assertHostKeyTaskInTasks(tasks)
        create_share_task = next((task for task in tasks if task.callback == self.plugin.nfs_shares_creation_callback), None)
        self.assertTrue(create_share_task is not None)
        self.assertEquals(create_share_task.kwargs['shares'][0]["clients"], list(('10.10.10.13',)))

    def test_export_update_add_subnet(self):
        self.setup_sfs_virtual_server(managed=True)
        fs = self.create_filesystem(self.pool1, size="20M")
        fs.set_applied()
        sfs_export = self.create_export(fs, clients="10.10.10.11,10.10.10.12", options="rw,no_root_squash")
        self.update_item(sfs_export, ipv4allowed_clients="10.10.10.11,10.10.10.12,10.10.10.0/24")
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 2)
        self.assertHostKeyTaskInTasks(tasks)
        create_share_task = next((task for task in tasks if task.callback == self.plugin.nfs_shares_creation_callback), None)
        self.assertTrue(create_share_task is not None)
        self.assertEquals(create_share_task.kwargs['shares'][0]["clients"], list(('10.10.10.0/24',)))

    def test_export_update_remove(self):
        self.setup_sfs_virtual_server(managed=True)
        fs = self.create_filesystem(self.pool1, size="20M")
        fs.set_applied()
        sfs_export = self.create_export(fs, clients="10.10.10.11,10.10.10.12", options="rw,no_root_squash")
        self.update_item(sfs_export, ipv4allowed_clients="10.10.10.11")
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 2)
        self.assertHostKeyTaskInTasks(tasks)
        remove_share_task = next((task for task in tasks if task.callback == self.plugin.nfs_shares_removal_callback), None)
        self.assertTrue(remove_share_task is not None)
        self.assertEquals(remove_share_task.kwargs['shares'][0]["clients"], list(('10.10.10.12',)))

    def test_export_update_options_add_option(self):
        self.setup_sfs_virtual_server(managed=True)
        fs = self.create_filesystem(self.pool1, size="20M")
        fs.set_applied()
        sfs_export = self.create_export(fs, clients="10.10.10.11", options="rw,no_root_squash")
        self.update_item(sfs_export, options="rw,no_root_squash,async")
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 2)
        self.assertHostKeyTaskInTasks(tasks)
        update_share_task = next((task for task in tasks if task.callback == self.plugin.nfs_shares_update_callback),
                                 None)
        self.assertTrue(update_share_task is not None)
        self.assertEquals(update_share_task.kwargs['shares'][0]['options'], 'rw,no_root_squash,async')

    def test_export_update_options_remove_option(self):
        self.setup_sfs_virtual_server(managed=True)
        fs = self.create_filesystem(self.pool1, size="20M")
        fs.set_applied()
        sfs_export = self.create_export(fs, clients="10.10.10.11", options="rw,no_root_squash")
        self.update_item(sfs_export, options="rw")
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 2)
        self.assertHostKeyTaskInTasks(tasks)
        update_share_task = next((task for task in tasks if task.callback == self.plugin.nfs_shares_update_callback),
                                 None)
        self.assertTrue(update_share_task is not None)
        self.assertEquals(update_share_task.kwargs['shares'][0]['options'], 'rw')

    def test_export_update_options_change_option(self):
        self.setup_sfs_virtual_server(managed=True)
        fs = self.create_filesystem(self.pool1, size="20M")
        fs.set_applied()
        sfs_export = self.create_export(fs, clients="10.10.10.11", options="rw,async")
        self.update_item(sfs_export, options="ro,sync")
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 2)
        self.assertHostKeyTaskInTasks(tasks)
        update_share_task = next((task for task in tasks if task.callback == self.plugin.nfs_shares_update_callback),
                                 None)
        self.assertTrue(update_share_task is not None)
        self.assertEquals(update_share_task.kwargs['shares'][0]['options'], 'ro,sync')

    def test_export_update_options_no_change_option(self):
        self.setup_sfs_virtual_server(managed=True)
        fs = self.create_filesystem(self.pool1, size="20M")
        fs.set_applied()
        sfs_export = self.create_export(fs, clients="10.10.10.11", options="rw,async")
        self.update_item(sfs_export, options="rw,async")
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 0)
        update_share_task = next((task for task in tasks if task.callback == self.plugin.nfs_shares_update_callback),
                                 None)
        self.assertTrue(update_share_task is None)

    def test_export_update_add_remove(self):
        self.setup_sfs_virtual_server(managed=True)
        fs = self.create_filesystem(self.pool1, size="20M")
        fs.set_applied()
        sfs_export = self.create_export(fs, clients="10.10.10.11,10.10.10.12", options="rw,no_root_squash")
        self.update_item(sfs_export, ipv4allowed_clients="10.10.10.11,10.10.10.13")
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 3)
        self.assertHostKeyTaskInTasks(tasks)
        remove_share_task = next((task for task in tasks if task.callback == self.plugin.nfs_shares_removal_callback), None)
        self.assertTrue(remove_share_task is not None)
        self.assertEquals(remove_share_task.kwargs['shares'][0]["clients"], list(('10.10.10.12',)))
        create_share_task = next((task for task in tasks if task.callback == self.plugin.nfs_shares_creation_callback), None)
        self.assertTrue(create_share_task is not None)
        self.assertEquals(create_share_task.kwargs['shares'][0]["clients"], list(('10.10.10.13',)))

    def test_export_update_change_all(self):
        self.setup_sfs_virtual_server(managed=True)
        fs = self.create_filesystem(self.pool1, size="20M")
        fs.set_applied()
        sfs_export = self.create_export(fs, clients="10.10.10.11,10.10.10.12", options="rw,no_root_squash")
        self.update_item(sfs_export, ipv4allowed_clients="10.10.10.13,10.10.10.14")
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 3)
        self.assertHostKeyTaskInTasks(tasks)
        remove_share_task = next((task for task in tasks if task.callback == self.plugin.nfs_shares_removal_callback), None)
        self.assertTrue(remove_share_task is not None)
        self.assertEquals(remove_share_task.kwargs['shares'][0]["clients"], list(('10.10.10.11', '10.10.10.12',)))
        create_share_task = next((task for task in tasks if task.callback == self.plugin.nfs_shares_creation_callback), None)
        self.assertTrue(create_share_task is not None)
        self.assertEquals(create_share_task.kwargs['shares'][0]["clients"], list(('10.10.10.14', '10.10.10.13',)))

    def test_export_update_remove_with_mount_fail(self):
        self.setup_sfs_virtual_server(managed=True)
        self._remove_empty_pools_from_set_up()
        self.eth0 = self.create_network_interface(self.node1, network_name="storage", ipaddress="10.10.10.12")
        fs = self.create_filesystem(self.pool1, size="20M")
        fs.set_applied()
        sfs_export = self.create_export(fs, clients="10.10.10.11,10.10.10.12")
        self.update_item(sfs_export, ipv4allowed_clients="10.10.10.11")
        nfs_mount = self.create_nfs_mount(
            export_path=fs.path, network_name=self.eth0.network_name,
            provider=self.sfs_virt1.name)
        self.create_inherited_mount(self.node1, nfs_mount)
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 1)
        self.assertIn('The IP address for the network "storage" must be included in the property "ipv4allowed_clients"' \
             ' of an sfs-export which is defined under an sfs-filesystem which has a property "path"' \
             ' defined as "/vx/path-1"', str(errors))

    def test_export_update_carry(self):
        self.setup_sfs_virtual_server(managed=True)
        self._remove_empty_pools_from_set_up()
        self.eth0 = self.create_network_interface(self.node1, network_name="storage", ipaddress="10.10.10.12")
        fs = self.create_filesystem(self.pool1, size="20M")
        fs.set_applied()
        sfs_export1 = self.create_export(fs, clients="10.10.10.11,10.10.10.12")
        sfs_export2 = self.create_export(fs, clients="10.10.10.9")

        self.update_item(sfs_export1, ipv4allowed_clients="10.10.10.11")
        self.update_item(sfs_export2, ipv4allowed_clients="10.10.10.9,10.10.10.12")
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 0)

    def test_export_update_update_share_callback(self):
        self.setup_sfs_virtual_server(managed=True)
        self._remove_empty_pools_from_set_up()
        self.eth0 = self.create_network_interface(self.node1, network_name="storage", ipaddress="10.10.10.12")
        fs = self.create_filesystem(self.pool1, size="20M")
        fs.set_applied()
        sfs_export1 = self.create_export(fs, clients="10.10.10.11,10.10.10.12", options="rw,no_root_squash")
        sfs_export1.set_for_removal()
        self.create_export(fs, clients="10.10.10.11,10.10.10.12", options="rw")
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        tasks = self.plugin.create_configuration(self.api)
        update_share_task = next((task for task in tasks if task.callback == self.plugin.nfs_shares_update_callback), None)
        self.assertTrue(update_share_task is not None)
        self.assertEquals(update_share_task.kwargs['shares'][0]["clients"], list(('10.10.10.11', '10.10.10.12',)))

    def test_export_update_carry_reverse(self):
        self.setup_sfs_virtual_server(managed=True)
        self._remove_empty_pools_from_set_up()
        self.eth0 = self.create_network_interface(self.node1, network_name="storage", ipaddress="10.10.10.12")
        fs = self.create_filesystem(self.pool1, size="20M")
        fs.set_applied()
        sfs_export1 = self.create_export(fs, clients="10.10.10.11")
        sfs_export2 = self.create_export(fs, clients="10.10.10.9,10.10.10.12")

        self.update_item(sfs_export1, ipv4allowed_clients="10.10.10.11,10.10.10.12")
        self.update_item(sfs_export2, ipv4allowed_clients="10.10.10.9")
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 0)

    def _remove_faulted_items(self, shares):
        shares = '\n'.join(shares).split('Faulted Shares:')[0]\
                                  .strip().splitlines()
        return shares

    def test_nfs_connection(self):
        conn_args = (NasDrivers.Sfs, "host", "username")
        def _test_connection():
            with NasConnectionCallbackMock(self.callback_api, *conn_args) as sfs:
                shares = sfs.execute("nfs share show")
                shares = self._remove_faulted_items(shares)
                for share in shares:
                    self.assertTrue(isinstance(share, str))
                    self.assertTrue(ShareResource.display_regex.search(share))
                self.assertTrue(isinstance(shares, list))
            return True

        self.assertTrue(_test_connection())

        def _test_raise_exception():
            with NasConnectionCallbackMock(self.callback_api, *conn_args) as sfs:
                shares = sfs.execute("nfs share show")
                shares = self._remove_faulted_items(shares)
                self.assertTrue(isinstance(shares, list))
                for share in shares:
                    self.assertTrue(isinstance(share, str))
                    self.assertTrue(ShareResource.display_regex.search(share))
                raise NasException("some error")
        self.assertRaises(CallbackExecutionException, _test_raise_exception)

        def _test_any_exception():
            with NasConnectionCallbackMock(self.callback_api, *conn_args) as s:
                raise Exception("any error")

        self.assertRaises(Exception, _test_any_exception)

        # def _test_bad_connection():
        #     with NasConnectionCallbackMock(self.callback_api, mock_connection_failure=True,
        #                            *conn_args) as sfs:
        #         pass
        #
        # self.assertRaises(CallbackExecutionException, _test_bad_connection)
        #
        # def _test_bad_connection_callback():
        #     with NasConnectionCallbackMock(self.callback_api,
        #                       mock_connection_failure=True, *conn_args) as sfs:
        #         super(NasConnectionCallbackMock, self).__init__
        #
        # self.assertRaises(CallbackExecutionException,
        #                  _test_bad_connection_callback)

    def setup_nfs_network(self, node, updated_interface=False,
                           ipv6=False):
        helper = IpAddressHelper(ipv6=ipv6)
        self.nfs_service1 = self.create_nfs_service(**{
            helper.get_service_ipadd_name(): helper.get_ipaddr("1")})

        self.network1 = self.create_network(litp_management="true",
                                            #subnet=helper.get_ipaddr("0") + helper.get_mask(),
                                            name="storage")

        key1 = helper.get_interface_ipadd_name()
        value1 = helper.get_ipaddr("10")
        self.node1_interface1 = self.create_network_interface(
             node, network_name="storage", **{key1: value1})

        helper = IpAddressHelper(ipv6=ipv6, network2=True)
        self.node1_interface2 = self.create_network_interface(
           node, network_name="mgmt", **{helper.get_interface_ipadd_name():helper.get_ipaddr("8")
               if updated_interface else helper.get_ipaddr("10")})

        if updated_interface:
            self.node1_interface1.set_applied()
            self.node1_interface1.set_property(key1, helper.get_ipaddr("8"))
            self.node1_interface1.set_updated()
        else:
            self.node1_interface1.set_applied()

    def setup_nfs_mount(self, node, clientaddr=False,
                        ipv6=False, nfs_mount_network_name="storage",
                        provider="nfs1"):

        helper = IpAddressHelper(ipv6=ipv6)
        params = dict(
            export_path="/abcde-fs1",
            provider=provider,
            mount_point="/tmp1",
            mount_options=
            "soft"
            if not clientaddr else "soft,clientaddr=" + helper.get_ipaddr("10"),
            network_name=nfs_mount_network_name)

        self.nfs_mount_source1 = self.create_nfs_mount(**params)
        self.nfs_mount_node1_1 = self.create_inherited_mount(node, self.nfs_mount_source1)

    def setup_nfs_mount_clientaddr(self, node, clientaddr,
                                   nfs_mount_network_name="storage",
                                   provider="nfs1"):
        params = dict(
            export_path="/abcde-fs1",
            provider=provider,
            mount_point="/tmp1",
            mount_options="soft,clientaddr=%s" % clientaddr,
            network_name=nfs_mount_network_name)
        mount = self.create_nfs_mount(**params)
        mount._applied_properties = mount.properties
        self.nfs_mount_source1 = mount
        self.nfs_mount_node1_1 = self.create_inherited_mount(node, mount)

    def test_nfs_mount_create(self):
        node1 = self.create_node()
        self.setup_nfs_network(node1)
        self.setup_nfs_mount(node1)
        # See if we can generate a mount task
        tasks = self.plugin.create_client_tasks(self.api, [])
        self.assertTaskCount(tasks, 1)
        params, item_vpath = get_task_props(tasks[0])
        self.assertEqual(params['mount_status'], 'mounted')
        self.assertEqual(item_vpath, '/deployments/d1/clusters/c1/nodes/n1/file_systems/fs1')

    def test_nfs_mount_do_nothing(self):
        node1 = self.create_node()
        self.setup_nfs_network(node1)
        self.setup_nfs_mount(node1)

        # See if we can generate nothing for a mount that is
        # already created
        self.nfs_mount_node1_1.set_applied()
        tasks = self.plugin.create_client_tasks(self.api, [])
        self.assertTaskCount(tasks, 0)

    def test_nfs_mount_remove(self):
        node1 = self.create_node()
        self.setup_nfs_network(node1)
        self.setup_nfs_mount(node1)
        # See if we can generate an unmount task
        self.nfs_mount_node1_1.set_for_removal()
        tasks = self.plugin.create_client_tasks(self.api, [])
        self.assertTaskCount(tasks, 1)
        params, item_vpath = get_task_props(tasks[0])
        self.assertEquals(params['mount_status'], 'absent')
        self.assertEqual(item_vpath, '/deployments/d1/clusters/c1/nodes/n1/file_systems/fs1')

    def test_nfs_mount_remount(self):
        node1 = self.create_node()
        self.setup_nfs_network(node1, updated_interface=True)
        self.setup_nfs_mount(node1)

        # See if we can create a mount task
        tasks = self.plugin.create_client_tasks(self.api, [])
        self.nfs_mount_node1_1.set_applied()
        self.node1_interface1.set_applied()
        self.setup_sfs_virtual_server(managed=False)
        self.node1_interface1.set_property("ipaddress", "10.10.10.20")
        self.node1_interface1.set_updated()
        tasks = self.plugin.create_client_tasks(self.api, [])
        # expect a reboot task
        self.assertTaskCount(tasks, 1)
        self.assertTrue(isinstance(tasks[0], CallbackTask))
        self.assertEquals(tasks[0].callback.__name__, "_reboot_node_and_wait")
        tasks = self.plugin.create_configuration(self.api)
        self.assertTrue(isinstance(tasks[0], CallbackTask))
        # no reboot if cluster is initial
        node1.parent.parent.set_initial()
        tasks = self.plugin.create_client_tasks(self.api, [])
        self.assertTaskCount(tasks, 0)

    def test_nfs_mount_remount_ms(self):
        ms = self.api.query('ms')[0]
        self.setup_nfs_network(ms, updated_interface=True)
        self.setup_nfs_mount(ms)
        self.setup_sfs_virtual_server(managed=False)
        # See if we can create a mount task
        tasks = self.plugin.create_client_tasks(self.api, [])
        self.nfs_mount_node1_1.set_applied()
        self.node1_interface1.set_applied()
        self.node1_interface2.set_applied()
        self.assertTaskCount(tasks, 1)

        self.node1_interface1.set_property("ipaddress", "10.10.10.1")
        self.node1_interface1.set_updated()
        #self.nfs_mount_node1_1.set_updated()
        tasks = self.plugin.create_configuration(self.api)
        # wont generate the reboot since this is ms with no clientaddr
        self.assertTaskCount(tasks, 0)

    def _test_nfs_mount_remount_with_clientaddr(self, ipv6):
        helper = IpAddressHelper(ipv6=ipv6)
        node1 = self.create_node()
        self.setup_nfs_network(node1, updated_interface=True, ipv6=ipv6)
        self.setup_nfs_mount(node1, clientaddr=True, ipv6=ipv6)

        # See if we can create a mount task
        tasks = self.plugin.create_client_tasks(self.api, [])
        self.node1_interface1.set_applied()
        self.nfs_mount_node1_1.set_applied()
        self.assertTaskCount(tasks, 1)
        self.setup_sfs_virtual_server(managed=False)
        # See if we can create a remount task
        if ipv6:
            self.node1_interface1.set_property("ipv6address", "3ffe:1a05:510:1111:0:aaaa:836b:8109")
        else:
            self.node1_interface1.set_property("ipaddress", "10.10.10.20")
        self.node1_interface1.set_updated()
        tasks = self.plugin.create_client_tasks(self.api, [])
        self.assertTaskCount(tasks, 3)
        remount_task = next(
            task for task in tasks if isinstance(task, ConfigTask))
        self.assertEquals(remount_task.description,
                          'Remount "/abcde-fs1" on node "node1"')
        params, item_vpath = get_task_props(remount_task)

        self.assertEquals(params['mount_status'], 'remount')
        if ipv6:
            self.assertEquals(params['mount_options'],
                'soft,clientaddr=%s' % "3ffe:1a05:510:1111:0:aaaa:836b:8109")
        else:
            self.assertEquals(params['mount_options'],
                'soft,clientaddr=%s' % "10.10.10.20")


        self.assertEqual(item_vpath, '/deployments/d1/clusters/c1/nodes/n1/file_systems/fs1')

        reboot_task = next(
            (task for task in tasks if isinstance(task, CallbackTask) and task.callback.__name__=="_reboot_node_and_wait"), None)
        self.assertTrue(reboot_task != None)
        clientaddr_task = next(
            (task for task in tasks if isinstance(task, CallbackTask) and task.callback.__name__=="update_clientaddr_option_callback"), None)
        self.assertTrue(clientaddr_task != None)
        self.assertIn(reboot_task, clientaddr_task.requires)
        self.assertIn(remount_task, clientaddr_task.requires)
        self.assertNotIn(reboot_task, reboot_task.requires)
        if ipv6:
            self.assertEquals(clientaddr_task.kwargs,
                          {'node_vpath': '/deployments/d1/clusters/c1/nodes/n1',
                           'nfs_vpath': '/deployments/d1/clusters/c1/nodes/n1/file_systems/fs1',
                           'new_options': 'soft,clientaddr=%s' % "3ffe:1a05:510:1111:0:aaaa:836b:8109"})
        else:
            self.assertEquals(clientaddr_task.kwargs,
                          {'node_vpath': '/deployments/d1/clusters/c1/nodes/n1',
                           'nfs_vpath': '/deployments/d1/clusters/c1/nodes/n1/file_systems/fs1',
                           'new_options': 'soft,clientaddr=%s' % "10.10.10.20"})

        # test that create config returns a reboot Callback
        create_config_tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(create_config_tasks, 3)
        task_types_count = self.count_type_of_Task(create_config_tasks)
        self.assertEquals(task_types_count[0], 2) # expect 2 callBacks
        self.assertEquals(task_types_count[1], 1) # expect 1 config

    def _test_nfs_mount_remount_with_clientaddr_initial_interface(self, ipv6):
        helper = IpAddressHelper(ipv6=ipv6)
        node1 = self.create_node()
        self.nfs_service1 = self.create_nfs_service(**{
            helper.get_service_ipadd_name(): helper.get_ipaddr("1")})

        self.network1 = self.create_network(litp_management="true",
                                            name="storage")
        self.node1_interface1 = self.create_network_interface(
             node1, network_name="storage",
             **{helper.get_interface_ipadd_name():helper.get_ipaddr("8")})
        self.setup_nfs_mount_clientaddr(node1, clientaddr=helper.get_ipaddr("8"))
        self.nfs_mount_node1_1.set_applied()
        # there may be an initial interface related with the mount, and no
        # previous applied interface in the case of a stopped plan
        # we should do nothing in that case
        tasks = self.plugin.create_client_tasks(self.api, [])
        self.assertTaskCount(tasks, 0)
        self.node1_bond = self.create_item("bond",
            "%s/network_interfaces/bond10" % (node1.get_vpath()),
            network_name=self.node1_interface1.network_name,
            device_name="bond0",
            **{helper.get_interface_ipadd_name():helper.get_ipaddr("10")})
        self.update_item(self.node1_interface1, network_name=None,
                         ipaddress=None, master=self.node1_bond.device_name)
        # See if we can create a remount, clientaddr and reboot task
        tasks = self.plugin.create_client_tasks(self.api, [])
        self.assertTaskCount(tasks, 3)
        remount_task = next(
            task for task in tasks if isinstance(task, ConfigTask))
        self.assertEquals(remount_task.description,
                          'Remount "/abcde-fs1" on node "node1"')
        params, item_vpath = get_task_props(remount_task)

        self.assertEquals(params['mount_status'], 'remount')
        self.assertEquals(params['mount_options'],
                          'soft,clientaddr=%s' % helper.get_ipaddr("10"))
        self.assertEqual(item_vpath, '/deployments/d1/clusters/c1/nodes/n1/file_systems/fs1')

        reboot_task = next(
            (task for task in tasks if isinstance(task, CallbackTask) and task.callback.__name__=="_reboot_node_and_wait"), None)
        self.assertTrue(reboot_task != None)
        clientaddr_task = next(
            (task for task in tasks if isinstance(task, CallbackTask) and task.callback.__name__=="update_clientaddr_option_callback"), None)
        self.assertTrue(clientaddr_task != None)
        self.assertIn(reboot_task, clientaddr_task.requires)
        self.assertIn(remount_task, clientaddr_task.requires)
        self.assertNotIn(reboot_task, reboot_task.requires)
        self.assertEquals(clientaddr_task.kwargs,
                          {'node_vpath': '/deployments/d1/clusters/c1/nodes/n1',
                           'nfs_vpath': '/deployments/d1/clusters/c1/nodes/n1/file_systems/fs1',
                           'new_options': 'soft,clientaddr=%s' % helper.get_ipaddr("10")})
        # double stack case
        helper = IpAddressHelper(ipv6=not ipv6)
        self.nfs_mount_node1_1 = self.api.query_by_vpath(self.nfs_mount_node1_1.get_vpath())
        self.node1_bond._properties.update(
            device_name=(self.nfs_service1.ipv4address or self.nfs_service1.ipv6address) + ":" + self.nfs_mount_node1_1.export_path,
            **{helper.get_interface_ipadd_name():helper.get_ipaddr("10")})
        self.assertTaskCount(tasks, 3)

    def test_nfs_mount_remount_with_clientaddr_initial_interface_ipv6(self):
        self._test_nfs_mount_remount_with_clientaddr_initial_interface(True)

    def test_nfs_mount_remount_with_clientaddr_initial_interface_ipv4(self):
        self._test_nfs_mount_remount_with_clientaddr_initial_interface(False)

    def _test_nfs_mount_update_remount_with_clientaddr(self, ipv6):
        helper = IpAddressHelper(ipv6=ipv6, network2=True)
        node1 = self.create_node()
        self.setup_nfs_network(node1, updated_interface=False, ipv6=ipv6)
        self.setup_nfs_mount(
                node1, clientaddr=True, ipv6=ipv6, nfs_mount_network_name="storage")
        self.setup_sfs_virtual_server(managed=False)
        # See if we can create a remount task
        self.nfs_mount_node1_1.set_applied()
        self.nfs_mount_source1.set_applied()
        self.nfs_mount_node1_1.set_property('network_name', 'mgmt')
        self.nfs_mount_node1_1.set_updated()
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        tasks = self.plugin.create_client_tasks(self.api, [])
        self.assertTaskCount(tasks, 3)
        remount_task = next(
            task for task in tasks if isinstance(task, ConfigTask))
        params, item_vpath = get_task_props(remount_task)

        self.assertEquals(params['mount_status'], 'remount')

        self.assertEquals(params['mount_options'],
                          'soft,clientaddr=%s' % helper.get_ipaddr("10"))
        self.assertEqual(item_vpath, '/deployments/d1/clusters/c1/nodes/n1/file_systems/fs1')
        clientaddr_task = next(
            task for task in tasks if isinstance(task, CallbackTask))
        self.assertTrue(any(
            task.item_vpath=="/deployments/d1/clusters/c1/nodes/n1/file_systems/fs1" for task in tasks))

        self.assertEquals(clientaddr_task.kwargs,
                          {'node_vpath': '/deployments/d1/clusters/c1/nodes/n1',
                           'nfs_vpath': '/deployments/d1/clusters/c1/nodes/n1/file_systems/fs1',
                           'new_options': 'soft,clientaddr=%s' % helper.get_ipaddr("10")})
        create_config_tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(create_config_tasks, 3)
        task_types_count = self.count_type_of_Task(create_config_tasks)
        self.assertEquals(task_types_count[0], 2) # expect 2 callBacks
        self.assertEquals(task_types_count[1], 1) # expect 1 config

    def test_nfs_mount_remount_with_clientaddr(self):
        self._test_nfs_mount_remount_with_clientaddr(False)

    def test_nfs_mount_remount_with_clientaddr_ipv6(self):
        self._test_nfs_mount_remount_with_clientaddr(True)

    def test_nfs_mount_update_remount_with_clientaddr(self):
        self._test_nfs_mount_update_remount_with_clientaddr(False)

    def test_nfs_mount_update_remount_with_clientaddr_ipv6(self):
        self._test_nfs_mount_update_remount_with_clientaddr(True)

    def test_nfs_mount_update_remount_reboot_souce(self):
        helper = IpAddressHelper(ipv6=False, network2=False)
        node1 = self.create_node()
        self.setup_nfs_network(node1, updated_interface=False)
        self.setup_nfs_mount_clientaddr(node1, clientaddr="10.10.10.11",
                                        nfs_mount_network_name="storage")
        self.setup_sfs_virtual_server(managed=False)
        self.nfs_mount_node1_1.set_applied()
        self.nfs_mount_node1_1.source.set_applied()
        self.nfs_mount_node1_1.source.set_property('network_name', 'mgmt')
        self.nfs_mount_node1_1.source.set_updated()
        self.nfs_mount_node1_1.set_updated()
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        tasks = self.plugin.create_client_tasks(self.api, [])
        self.assertTaskCount(tasks, 3)
        remount_task = next(
            task for task in tasks if isinstance(task, ConfigTask))
        params, item_vpath = get_task_props(remount_task)

        self.assertEquals(params['mount_status'], 'remount')

        helper_network2 = IpAddressHelper(ipv6=False, network2=True)
        self.assertEquals(params['mount_options'],
                          'soft,clientaddr=%s' % helper_network2.get_ipaddr("10"))
        self.assertEqual(item_vpath,
                       '/deployments/d1/clusters/c1/nodes/n1/file_systems/fs1')
        create_config_tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(create_config_tasks, 3)
        task_types_count = self.count_type_of_Task(create_config_tasks)
        self.assertEquals(task_types_count[0], 2)  # expect 2 callbacks
        self.assertEquals(task_types_count[1], 1)  # expect 1 config
        task = next(t for t in create_config_tasks if isinstance(t,
                                                                 CallbackTask))
        self.assertEquals(task.call_type, 'update_clientaddr_option_callback')

    def test_nfs_mount_update_remount_reboot_node1(self):
        helper = IpAddressHelper(ipv6=False, network2=False)
        node1 = self.create_node()
        self.setup_nfs_network(node1, updated_interface=False)
        self.setup_nfs_mount_clientaddr(node1, clientaddr="10.10.10.10",
                                        nfs_mount_network_name="storage")
        self.setup_sfs_virtual_server(managed=False)
        self.nfs_mount_node1_1.set_applied()
        self.nfs_mount_node1_1.set_property('network_name', 'mgmt')
        self.nfs_mount_node1_1.set_updated()
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 3)
        remount_task = next(
            task for task in tasks if isinstance(task, ConfigTask))
        params, item_vpath = get_task_props(remount_task)

        self.assertEquals(params['mount_status'], 'remount')
        helper_network2 = IpAddressHelper(ipv6=False, network2=True)
        self.assertEquals(params['mount_options'],
                          'soft,clientaddr=%s' % helper_network2.get_ipaddr("10"))
        self.assertEqual(item_vpath,
                       '/deployments/d1/clusters/c1/nodes/n1/file_systems/fs1')
        clientaddr_task = next(t for t in tasks if isinstance(t, CallbackTask)if
                t.call_type == 'update_clientaddr_option_callback')
        self.assertEquals(clientaddr_task.kwargs["new_options"], "soft,clientaddr=20.20.20.10")
        self.assertEquals(clientaddr_task.model_item.vpath, self.nfs_mount_node1_1.vpath)
        reboot_task = next(t for t in tasks if isinstance(t, CallbackTask)if
                t.call_type == '_reboot_node_and_wait')

        self.assertEquals(reboot_task.description, 'Reboot node "node1"')

    def test_nfs_mount_update_remount_reboot_ms(self):
        helper = IpAddressHelper(ipv6=False, network2=False)
        ms = self.api.query("ms")[0]
        self.setup_nfs_network(ms, updated_interface=False)
        self.setup_nfs_mount_clientaddr(ms, clientaddr="10.10.10.10",
                                        nfs_mount_network_name="storage")
        self.setup_sfs_virtual_server(managed=False)
        self.nfs_mount_node1_1.set_applied()
        self.nfs_mount_node1_1.set_property('network_name', 'mgmt')
        self.nfs_mount_node1_1.set_updated()
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        tasks = self.plugin.create_client_tasks(self.api, [])
        self.assertTaskCount(tasks, 2)
        remount_task = next(
            task for task in tasks if isinstance(task, ConfigTask))
        params, item_vpath = get_task_props(remount_task)

        self.assertEquals(params['mount_status'], 'remount')
        helper_network2 = IpAddressHelper(ipv6=False, network2=True)

        self.assertEquals(params['mount_options'],
                          'soft,clientaddr=%s' % helper_network2.get_ipaddr("10"))
        self.assertEqual(item_vpath, '/ms/file_systems/fs1')
        create_config_tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(create_config_tasks, 2)
        task_types_count = self.count_type_of_Task(create_config_tasks)
        self.assertEquals(task_types_count[0], 1)  # expect 0 callbacks
        self.assertEquals(task_types_count[1], 1)  # expect 1 config

    def test_mount_provider_updated_inherited(self):
        helper = IpAddressHelper(ipv6=False, network2=False)
        node1 = self.create_node()
        self.setup_nfs_network(node1, updated_interface=False)
        self.node1_interface2.set_for_removal()
        self.setup_nfs_mount_clientaddr(node1, clientaddr="10.10.10.10",
                                        nfs_mount_network_name="storage", provider="vsvr1")
        sfs_service1 = self.create_sfs_service(managed=False, management_ipv4="10.10.10.10")
        vip = self.sfs_virtual_server1 = self.create_virtual_server(sfs_service1, name="vsvr1",
                ipv4address="10.10.10.100")
        vip = self.sfs_virtual_server2 = self.create_virtual_server(sfs_service1, name="vsvr2",
                ipv4address="10.10.10.101")

        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 1)
        self.nfs_mount_source1.set_applied()
        self.nfs_mount_node1_1.set_applied()
        self.nfs_mount_node1_1.set_property('provider', 'vsvr2')
        self.nfs_mount_node1_1.set_updated()
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        tasks = self.plugin.create_client_tasks(self.api, [])
        self.assertTaskCount(tasks, 1)
        remount_tasks =\
            [ task for task in tasks if isinstance(task, ConfigTask) ]

        params, item_vpath = get_task_props(remount_tasks[0])
        self.assertEquals(params['mount_status'],
                          'remount')
        self.assertEquals(params['path'],
                '10.10.10.101:/abcde-fs1')
        #Test IP's are correct applied, updated
        ip = self.plugin._find_provider_updated_ip(self.nfs_mount_node1_1, self.api)
        self.assertEquals('10.10.10.101', ip)

    def test_mount_provider_updated_source(self):
        helper = IpAddressHelper(ipv6=False, network2=False)
        node1 = self.create_node()
        self.setup_nfs_network(node1, updated_interface=False)
        self.node1_interface2.set_for_removal()
        self.node1_interface1.set_applied()
        self.setup_nfs_mount_clientaddr(node1, clientaddr="10.10.10.10",
                                        nfs_mount_network_name="storage", provider="vsvr1")
        sfs_service1 = self.create_sfs_service(managed=False, management_ipv4="10.10.10.10")
        vip = self.sfs_virtual_server1 = self.create_virtual_server(sfs_service1, name="vsvr1",
                ipv4address="10.10.10.100")
        vip = self.sfs_virtual_server2 = self.create_virtual_server(sfs_service1, name="vsvr2",
                ipv4address="10.10.10.101")


        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 1)
        params, item_vpath = get_task_props(tasks[0])
        self.nfs_mount_node1_1.set_applied()

        self.nfs_mount_source1.set_applied()
        self.nfs_mount_source1.set_property('provider', 'vsvr2')
        self.nfs_mount_source1.set_updated()
        self.nfs_mount_node1_1.set_property('provider', 'vsvr2')
        self.nfs_mount_node1_1.set_updated()
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        tasks = self.plugin.create_client_tasks(self.api, [])
        self.assertTaskCount(tasks, 1)
        remount_tasks =\
            [ task for task in tasks if isinstance(task, ConfigTask) ]

        params, item_vpath = get_task_props(remount_tasks[0])
        self.assertEquals(params['mount_status'],
                          'remount')
        self.assertEquals(params['path'],
                '10.10.10.101:/abcde-fs1')
        #Test IP's are correct applied, updated
        ip = self.plugin._find_provider_updated_ip(self.nfs_mount_node1_1, self.api)
        self.assertEquals('10.10.10.101', ip)

    def test_dual_stack_task(self):
        self.setup_dual_stack_network_model()
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 2)  # one callbk, one puppet task

    def setup_dual_stack_mount_system(self):
        self.node1 = self.create_node()
        self.eth0 = self.create_network_interface(self.node1, network_name="mgmt",
                                                  ipaddress="10.10.10.101",
                                                  ipv6address="fe80::baca:3aff:fe96:8da4/64")
        self.eth1 = self.create_network_interface(self.node1, network_name="fake", ipaddress="192.168.100.1")
        self.nfs_service1 = self.create_nfs_service(ipv4address="10.10.10.10", ipv6address="fe80::baca:3aff:fe96:8da5")
        self.nfs_mount = self.create_nfs_mount(export_path="/vx/dummy-1", provider=self.nfs_service1.name,
                                               mount_options="soft", network_name=self.eth0.network_name)
        self.create_inherited_mount(self.node1, self.nfs_mount)

    def test_dual_stack_method_pos(self):
        self.setup_dual_stack_mount_system()
        result = self.plugin._is_dual_stack(self.api, self.node1, self.nfs_mount)
        self.assertTrue(result)

    def test_dual_stack_method_neg(self):
        self.node1 = self.create_node()
        self.eth1 = self.create_network_interface(self.node1, network_name="mgmt", ipaddress="192.168.100.1")
        self.nfs_service1 = self.create_nfs_service(ipv4address="10.10.10.10", ipv6address="fe80::baca:3aff:fe96:8da5")
        self.nfs_mount = self.create_nfs_mount(export_path="/vx/dummy-1", provider=self.nfs_service1.name,
                                               mount_options="soft", network_name=self.eth1.network_name)
        self.create_inherited_mount(self.node1, self.nfs_mount)
        self.assertEquals("soft", self.nfs_mount.mount_options)
        result = self.plugin._is_dual_stack(self.api, self.node1, self.nfs_mount)
        self.assertFalse(result)

    def test_find_ip_provider(self):
        self.setup_non_sfs_unmanaged_model(ipv4=True)
        nfs_mount = self.create_nfs_mount(export_path="/vx/abcde-fs1")
        self.create_inherited_mount(self.node1, nfs_mount)
        result = self.plugin._find_provider_ip(nfs_mount, self.api)
        self.assertEquals(result[0], "10.10.10.100")

    @mock.patch('nas_plugin.nas_plugin.wait_for_node_timestamp')
    @mock.patch('nas_plugin.nas_plugin.PuppetMcoProcessor.enable_puppet')
    @mock.patch('nas_plugin.nas_plugin.NasPlugin._execute_rpc_in_callback_task')
    @mock.patch('nas_plugin.nas_plugin.wait_for_node')
    @mock.patch('nas_plugin.nas_plugin.wait_for_node_down')
    def test_reboot_node_and_wait(self,  wait_for_node_down, wait_for_node,
                                  _execute_rpc_in_callback_task, enable_puppet,
                                  wait_for_node_timestamp):
        node1 = self.create_node()
        self.setup_nfs_network(node1, updated_interface=True)
        self.setup_nfs_mount(node1)
        tasks = self.plugin.create_client_tasks(self.api, [])
        self.nfs_mount_node1_1.set_applied()

        self.nfs_mount_node1_1.source.set_property('network_name', 'mgmt')
        self.nfs_mount_node1_1.set_updated()
        tasks = self.plugin.create_client_tasks(self.api, [])
        self.assertTrue(isinstance(tasks[0], CallbackTask), True)

        self.plugin._reboot_node_and_wait(self.callback_api, node1.hostname)
        _execute_rpc_in_callback_task.assert_called_with(self.callback_api,
                                                         [node1.hostname], "core",
                                                         "reboot")
        wait_for_node_down.assert_called_with(self.callback_api, [node1.hostname], True)
        wait_for_node_timestamp.assert_called_with(self.callback_api, [node1.hostname], mock.ANY, True)
        wait_for_node.assert_called_with(self.callback_api, [node1.hostname], True)

    @mock.patch('nas_plugin.nas_plugin.BaseRpcCommandProcessor.execute_rpc_and_process_result')
    def test_execute_rpc_in_callback_task_success(self, execute_rpc_and_process_result):
        node1 = self.create_node()
        self.setup_nfs_network(node1, updated_interface=True)
        self.setup_nfs_mount(node1)
        tasks = self.plugin.create_client_tasks(self.api, [])
        self.nfs_mount_node1_1.set_applied()

        self.nfs_mount_node1_1.source.set_property('network_name', 'mgmt')
        self.nfs_mount_node1_1.set_updated()

        tasks = self.plugin.create_client_tasks(self.api, [])
        self.assertTrue(isinstance(tasks[0], CallbackTask), True)

        execute_rpc_and_process_result.return_value = (None, [])
        self.plugin._execute_rpc_in_callback_task(self.callback_api, [node1.hostname], "core", "reboot")

        execute_rpc_and_process_result.assert_called_with(
            self.callback_api, [node1.hostname], "core", "reboot", None, 30, retries=5)

    @mock.patch('nas_plugin.nas_plugin.BaseRpcCommandProcessor.execute_rpc_and_process_result')
    def test_execute_rpc_in_callback_task_fail(self, execute_rpc_and_process_result):
        node1 = self.create_node()
        self.setup_nfs_network(node1, updated_interface=True)
        self.setup_nfs_mount(node1)
        self.nfs_mount_node1_1.set_applied()
        tasks = self.plugin.create_client_tasks(self.api, [])

        self.nfs_mount_node1_1.source.set_property('network_name', 'mgmt')
        self.nfs_mount_node1_1.set_updated()
        tasks = self.plugin.create_client_tasks(self.api, [])
        self.assertTrue(isinstance(tasks[0], CallbackTask), True)

        execute_rpc_and_process_result.side_effect = RpcExecutionException("")
        self.assertRaises(CallbackExecutionException, self.plugin._execute_rpc_in_callback_task,
                          self.callback_api, [node1.hostname], "core", "reboot")

        execute_rpc_and_process_result.side_effect = None
        execute_rpc_and_process_result.return_value = (None, ["error_string"])
        self.assertRaises(CallbackExecutionException, self.plugin._execute_rpc_in_callback_task,
                          self.callback_api, [node1.hostname], "core", "reboot")

    @mock.patch('nas_plugin.nas_cmd_api.run_rpc_command')
    def test_mco_callback_success(self, run_rpc_command):
        self.setup_dual_stack_mount_system()
        self.setup_sfs_virtual_server(managed=False)
        tasks = self.plugin.create_configuration(self.api)
        self.assertTrue(isinstance(tasks[0], CallbackTask), True)
        self.assertTrue(isinstance(tasks[1], ConfigTask), True)
        run_rpc_command.return_value = {
           'node1': {'errors': '',
                     'data': {'retcode': 0, 'err': '', 'out': ''}}
        }
        t = tasks[0]
        self.plugin.attempt_dual_stack_mount(self.callback_api, **t.kwargs)

    @mock.patch('nas_plugin.nas_cmd_api.run_rpc_command')
    @mock.patch('nas_plugin.nas_cmd_api.NasCmdApi.unmount')
    def test_mco_callback_success_failing_umount(self, unmount,
                                                 run_rpc_command):
        self.setup_dual_stack_mount_system()
        self.setup_sfs_virtual_server(managed=False)
        tasks = self.plugin.create_configuration(self.api)
        self.assertTrue(isinstance(tasks[0], CallbackTask), True)
        self.assertTrue(isinstance(tasks[1], ConfigTask), True)
        run_rpc_command.return_value = {
           'node1': {'errors': '',
                     'data': {'retcode': 0, 'err': '', 'out': ''}}
        }
        unmount.side_effect = NasCmdApiException("")
        t = tasks[0]
        self.plugin.attempt_dual_stack_mount(self.callback_api, **t.kwargs)


    @mock.patch('nas_plugin.nas_cmd_api.run_rpc_command')
    @mock.patch('nas_plugin.nas_cmd_api.NasCmdApi.mount_ipv4')
    def test_mco_callback_fail_ipv4(self, mount_ipv4, run_rpc_command):
        self.setup_dual_stack_mount_system()
        self.setup_sfs_virtual_server(managed=True, pool_name="SFS_Pool")
        tasks = self.plugin.create_configuration(self.api)
        self.assertTrue(isinstance(tasks[0], CallbackTask), True)
        self.assertTrue(isinstance(tasks[1], ConfigTask), True)
        run_rpc_command.return_value = {
           'node1': {'errors': '',
                     'data': {'retcode': 0, 'err': '', 'out': ''}}
        }
        mount_ipv4.side_effect = NasCmdApiException("")
        t = tasks[0]
        self.plugin.attempt_dual_stack_mount(self.callback_api, **t.kwargs)

    @mock.patch('nas_plugin.nas_cmd_api.run_rpc_command')
    @mock.patch('nas_plugin.nas_cmd_api.NasCmdApi.mount_ipv4')
    @mock.patch('nas_plugin.nas_cmd_api.NasCmdApi.mount_ipv6')
    def test_mco_callback_fail_ipv6(self, mount_ipv6, mount_ipv4,
                               run_rpc_command):
        self.setup_dual_stack_mount_system()
        self.setup_sfs_virtual_server(managed=False)
        tasks = self.plugin.create_configuration(self.api)
        self.assertTrue(isinstance(tasks[0], CallbackTask), True)
        self.assertTrue(isinstance(tasks[1], ConfigTask), True)
        run_rpc_command.return_value = {
           'node1': {'errors': '',
                     'data': {'retcode': 0, 'err': '', 'out': ''}}
        }
        mount_ipv4.side_effect = NasCmdApiException("")
        mount_ipv6.side_effect = NasCmdApiException("")
        t = tasks[0]
        self.assertRaises(CallbackExecutionException,
                          self.plugin.attempt_dual_stack_mount,
                          self.callback_api, **t.kwargs)

    def test_in_ip(self):
        self.assertTrue(in_ip('1.1.1.1', '1.1.1.1'))
        self.assertFalse(in_ip('2.2.2.3', '2.2.2.2'))
        self.assertTrue(in_ip('1.1.1.1', '1.1.1.0/24'))
        self.assertFalse(in_ip('2.2.2.3', '1.1.1.0/24'))

    def test_isolated_nfs_mounts(self):
        self.nfs_mount = self.create_nfs_mount(export_path="/vx/dummy-1", provider="nfs1",
                                               mount_options="soft", network_name="mgmt")
        mounts = []
        mounts.append(self.nfs_mount)
        result = self.plugin._validate_nfs_mount_valid_providers([], mounts, [], [])
        self.assertTrue(result)

    def _test_validate_nfs_provider(self):
        managed_nodes = self.query('node')
        mses = self.query('ms')
        all_nodes = mses + managed_nodes
        nfs_services = self.query('nfs-service')
        nfs_mounts = self.query('nfs-mount')

        return self.plugin._validate_nfs_mount_valid_providers(all_nodes, nfs_mounts, [], nfs_services)

    def test_valid_nfs_mounts(self):
        self.setup_non_sfs_unmanaged_model(ipv4=True)
        mount = self.create_nfs_mount(export_path="/vx/dummy-1")
        self.assertErrorCount(self._test_validate_nfs_provider(), 0)

    def test_invalid_nfs_mounts_provider1(self):
        self.setup_non_sfs_unmanaged_model(ipv4=True)
        mount = self.create_nfs_mount(export_path="/vx/dummy-1")
        mount2 = self.create_nfs_mount(export_path="/vx/dummy-1",
                                       provider="invalid_name")
        self.assertErrorCount(self._test_validate_nfs_provider(), 1)

    def test_invalid_nfs_mounts_provider2(self):
        self.setup_non_sfs_unmanaged_model(ipv4=True)
        mount = self.create_nfs_mount(export_path="/vx/dummy-1")
        self.create_inherited_mount(self.node1, mount)
        mount2 = self.create_nfs_mount(export_path="/vx/dummy-1",
                                       provider="invalid_name")
        self.assertErrorCount(self._test_validate_nfs_provider(), 1)

    def test_invalid_nfs_mounts_provider_no_orphans(self):
        self.setup_non_sfs_unmanaged_model(ipv4=True)
        mount = self.create_nfs_mount(export_path="/vx/dummy-1")
        self.create_inherited_mount(self.node1, mount)
        mount2 = self.create_nfs_mount(export_path="/vx/dummy-1",
                                       provider="invalid_name")
        self.create_inherited_mount(self.node1, mount2)
        self.assertErrorCount(self._test_validate_nfs_provider(), 1)

    def set_up_snapshot(self, filesystems_applied=False, set_up_nfs=False,
                        snap_tag=None, extra_fss=None):
        self.setup_sfs_virtual_server(managed=True, pool_name="SFS_Pool")
        self.cache = self.create_cache(self.pool1, self.sfs_service1, name="mycache")
        self.fs1 = self.create_filesystem(
                                self.pool1, path="/vx/enm1-stor", size="10M", snap_size='31',
                                backup_policy="No", cache_name=self.cache.name)
        self.fs2 = self.create_filesystem(
                                self.pool1, path="/vx/pm1", size="10M", snap_size='010',
                                backup_policy="No", cache_name=self.cache.name)
        self.fs3 = self.create_filesystem(
                                self.pool1, path="/vx/pmlinks1", size="10M", snap_size='0',
                                backup_policy="No", cache_name=self.cache.name)
        self.fs4 = self.create_filesystem(
                                self.pool1, path="/vx/enm1-stor2", size="10M", snap_size='100',
                                backup_policy="No", cache_name=self.cache.name)
        self.fs5 = self.create_filesystem(
                                self.pool1, path="/vx/enm1-stor3", size="100M", snap_size=None,
                                backup_policy="No", cache_name=None)

        if extra_fss is None:
            extra_fss = []
        extra = []
        for fs in extra_fss:
            extra.append(self.create_filesystem(self.pool1, **fs))
        fs_list = [self.fs1, self.fs2, self.fs3, self.fs4, self.fs5] + extra

        self.export1 = self.create_export(self.fs1, clients="10.10.10.10")

        if filesystems_applied:
            for fs in fs_list:
                self.set_applied(fs)
            self.set_applied(self.export1)
        sfs_service1 = self.api.query_by_vpath(self.sfs_service1.get_vpath())
        if set_up_nfs:
            fs_names = [f.path.split('/')[-1] for f in fs_list]
            self.cache.set_applied()
            mock_args = NasDrivers.Sfs, "10.44.86.226", "support", "support"
            with NasConnectionCallbackMock(self.callback_api,
                                           *mock_args) as nfs:
                caches = []
                for snapshot in nfs.snapshot.list():
                    if snapshot.filesystem in fs_names:
                        caches.append(snapshot.get_cache())
                        snapshot.delete()
                for cache in caches:
                    try:
                        cache.delete()
                    except Cache.DoesNotExist:
                        pass
                #for cache in nfs.cache.list():
                #    cache.delete()
                for filesystem in nfs.filesystem.list():
                    if filesystem.name in fs_names:
                        filesystem.delete()

                try:
                    nfs.cache.create(self.cache.name,
                                     str(self.plugin._calc_cache_object_size(sfs_service1)),
                                     self.pool1.name)
                except Cache.AlreadyExists:
                    pass

                for fs in fs_list:
                    nfs.filesystem.create(fs.path[4:], fs.size, self.pool1.name, "simple")
                if snap_tag:
                    for fs in [self.fs1, self.fs2, self.fs4]:
                        nfs.snapshot.create(('L_' + fs.path[4:] + '_' + snap_tag),
                                            fs.path[4:], self.cache.name)

    def test_updated_backup_policy_on_filesystem(self):
        self.set_up_snapshot(filesystems_applied=True)
        self.cache.set_applied()
        self.update_item(self.fs1, backup_policy="yes")
        tasks = self.plugin.create_configuration(self.api)
        self.assertEquals(0, len(tasks))

    def test_get_caches_pools(self):
        self.setup_sfs_virtual_server(managed=True, pool_name='SFS_Pool')
        actual_cache = self.create_cache(self.pool1, self.sfs_service1, name="mycache")
        fs = self.create_filesystem(
            self.pool1, path="/vx/enm1-stor", size="10M", snap_size='30',
            backup_policy="No", cache_name="mycache")
        fs.set_applied()
        sfs_service = self.api.query_by_vpath(self.sfs_service1.get_vpath())
        for expected_cache, expected_pool in self.plugin._get_caches_pools(sfs_service):
            self.assertEquals((actual_cache.name, self.pool1.name),
                              (expected_cache.name, expected_pool.name))

    def test_get_caches_pools_cache_collection_empty(self):
        self.setup_sfs_virtual_server(managed=True, pool_name='SFS_Pool')
        actual_cache = None
        actual_pool = None
        fs = self.create_filesystem(
            self.pool1, path="/vx/enm1-stor", size="10M", snap_size='30',
            backup_policy="No", cache_name="mycache")
        fs.set_applied()
        sfs_service = self.api.query_by_vpath(self.sfs_service1.get_vpath())
        for expected_cache, expected_pool in self.plugin._get_caches_pools(sfs_service):
            self.assertEquals((actual_cache, actual_pool),
                              (expected_cache, expected_pool))

    def test_calc_cache_object_size(self):
        self.set_up_snapshot(filesystems_applied=True)
        self.cache.set_applied()
        # 5M is minimum cache size on SFS

        self.assertEqual("15M", str(self.plugin._calc_cache_object_size(self.api.query_by_vpath(self.sfs_service1.get_vpath()))))

    def test_calc_cache_object_size_min_size(self):
        self.setup_sfs_virtual_server(managed=True)
        self.create_cache(self.pool1, self.sfs_service1, name="mycache")
        self.create_filesystem(
                                self.pool1, path="/vx/enm1-stor", size="10M", snap_size='10',
                                backup_policy="No", cache_name="mycache")
        # 5M is minimum cache size on SFS
        self.assertEqual("5M", str(self.plugin._calc_cache_object_size(self.api.query_by_vpath(self.sfs_service1.get_vpath()))))

    def test_calc_cache_object_size_returns_mb(self):
        self.setup_sfs_virtual_server(managed=True)
        self.create_cache(self.pool1, self.sfs_service1, name="mycache")

        create_filesystem_for_snapshot = lambda: self.create_filesystem(
            self.pool1, path="/vx/enm1-stor", size="1G", snap_size='10',
            backup_policy="No", cache_name="mycache")
        sfs_service1 = self.api.query_by_vpath(self.sfs_service1.get_vpath())
        self.fs1 = create_filesystem_for_snapshot()
        self.fs1.set_applied()
        self.assertEqual("103M", str(self.plugin._calc_cache_object_size(sfs_service1)))

        self.fs2 = create_filesystem_for_snapshot()
        self.fs2.set_applied()
        self.fs2.set_for_removal()
        sfs_service2 = self.api.query_by_vpath(self.sfs_service1.get_vpath())
        self.assertEqual("205M", str(self.plugin._calc_cache_object_size(sfs_service2)))

        self.fs3 = create_filesystem_for_snapshot()
        self.fs3.set_updated()
        self.update_item(self.fs3, size="2G", snap_size='10')
        sfs_service3 = self.api.query_by_vpath(self.sfs_service1.get_vpath())
        self.assertEqual("308M", str(self.plugin._calc_cache_object_size(sfs_service3)))

        self.fs4 = create_filesystem_for_snapshot()
        self.fs4.set_initial()
        sfs_service4 = self.api.query_by_vpath(self.sfs_service1.get_vpath())
        self.assertEqual("308M", str(self.plugin._calc_cache_object_size(sfs_service4)))

    def test_create_cache_object_success(self):
        self.set_up_snapshot(filesystems_applied=True)

        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'snapshot', timestamp=None)
        sfs_service = self.api.query_by_vpath(self.sfs_service1.get_vpath())
        tasks = self.plugin._configure_cache_object_tasks(snap_item, sfs_service)

        for task in tasks:
            # cache successfully created
            with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
                nfs = nfs_connection_class.return_value.__enter__.return_value
                self.plugin._configure_cache(self.callback_api, *task.args, **task.kwargs)
                nfs.cache.create.assert_called_once_with(self.cache.name, "15M", self.pool1.name)

    def test_create_cache_object_fail(self):
        self.set_up_snapshot(filesystems_applied=True)

        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'snapshot', timestamp=None)
        sfs_service = self.api.query_by_vpath(self.sfs_service1.get_vpath())
        tasks = self.plugin._configure_cache_object_tasks(snap_item, sfs_service)

        for task in tasks:
            # cache that already exist on SFS and has the same attributes
            with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
                nfs = nfs_connection_class.return_value.__enter__.return_value
                nfs.cache.create.side_effect = Cache.AlreadyExists
                nfs.cache.get.return_value = Cache(nfs.cache, self.cache.name, "15M", self.pool1.name)
                self.plugin._configure_cache(self.callback_api, *task.args, **task.kwargs)
                nfs.cache.create.assert_called_once_with(self.cache.name, "15M", self.pool1.name)
                nfs.cache.get.assert_called_once_with(self.cache.name)

        # cache being on different pool
        pool2 = self.create_pool(self.sfs_service1)
        pool2.set_applied()
        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            nfs.cache.create.side_effect = Cache.AlreadyExists
            nfs.cache.get.return_value = Cache(nfs.cache, self.cache.name, "15M", pool2.name)
            self.assertRaises(Cache.CreationException,
                              self.plugin._configure_cache,
                              self.callback_api,
                              *task.args,
                              **task.kwargs)

        # cache with the bigger size already exist in SFS
        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            nfs.cache.create.side_effect = Cache.AlreadyExists
            nfs.cache.get.return_value = Cache(nfs.cache, self.cache.name, "1G", self.pool1.name)
            self.plugin._configure_cache(self.callback_api, *task.args, **task.kwargs)
            nfs.cache.create.assert_called_once_with(self.cache.name, "15M", self.pool1.name)
            nfs.cache.get.assert_called_once_with(self.cache.name)

    def test_resizing_of_already_existing_cache(self):
        self.set_up_snapshot()

        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'snapshot', timestamp=None)

        # cache with the smaller size already exist in SFS resizing
        fs1 = self.create_filesystem(
            self.pool1, path="/vx/enm1-stor", size="1G", snap_size='10',
            backup_policy="No", cache_name="mycache")
        fs1.set_applied()
        self.cache.set_applied()
        sfs_service1 = self.api.query_by_vpath(self.sfs_service1.get_vpath())
        tasks = self.plugin._configure_cache_object_tasks(snap_item, sfs_service1)
        for task in tasks:
            with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
                nfs = nfs_connection_class.return_value.__enter__.return_value
                nfs.cache.create.side_effect = Cache.AlreadyExists
                nfs.cache.get.return_value = Cache(nfs.cache, self.cache.name, "5M", self.pool1.name)
                self.plugin._configure_cache(self.callback_api, *task.args, **task.kwargs)
                nfs.cache.create.assert_called_once_with(self.cache.name, "103M", self.pool1.name)
                nfs.cache.get.assert_called_once_with(self.cache.name)
                nfs.cache.resize.assert_called_once_with(self.cache.name, "103M")

    def test_resizing_of_already_existing_cache_fail(self):
        self.set_up_snapshot()

        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'snapshot', timestamp=None)

        # cache with the smaller size already exist in SFS resizing catches Cache.SameSizeException
        fs1 = self.create_filesystem(
            self.pool1, path="/vx/enm1-stor", size="1G", snap_size='10',
            backup_policy="No", cache_name="mycache")
        fs1.set_applied()
        self.cache.set_applied()
        sfs_service1 = self.api.query_by_vpath(self.sfs_service1.get_vpath())
        tasks = self.plugin._configure_cache_object_tasks(snap_item, sfs_service1)
        for task in tasks:
            with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
                nfs = nfs_connection_class.return_value.__enter__.return_value
                nfs.cache.create.side_effect = Cache.AlreadyExists
                nfs.cache.resize.side_effect = Cache.SameSizeException
                nfs.cache.get.return_value = Cache(nfs, self.cache.name, "5M", self.pool1.name)
                self.plugin._configure_cache(self.callback_api, *task.args, **task.kwargs)
                nfs.cache.create.assert_called_once_with(self.cache.name, "103M", self.pool1.name)
                nfs.cache.get.assert_called_once_with(self.cache.name)
                nfs.cache.resize.assert_called_once_with(self.cache.name, "103M")

    def test_create_cache_object_task(self):
        self.set_up_snapshot(filesystems_applied=True)

        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'snapshot', timestamp=None)
        sfs_service1 = self.api.query_by_vpath(self.sfs_service1.get_vpath())
        tasks = self.plugin._configure_cache_object_tasks(snap_item, sfs_service1)
        for task in tasks:
            if task.callback == self.plugin._configure_cache:
                self.assertIn('Configure cache object "mycache" in pool "SFS_Pool" '
                              'on NAS server "10.44.86.226"',
                              task.description)
                self.assertTrue(isinstance(task, CallbackTask), True)


    def test_snapshot_action_gives_exception(self):
        self.set_up_snapshot(filesystems_applied=True)
        self.api.snapshot_action = mock.MagicMock(return_value='update')
        self.api.snapshot_name = mock.MagicMock(return_value='OMBS')
        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'OMBS', timestamp=None, active='false')
        self.api._snapshot_object = mock.MagicMock(return_value=snap_item)
        self.api.snapshot_action.side_effect = Exception

        self.assertRaises(PluginError, self.plugin.create_snapshot_plan, self.api)

        self.assertRaises(PluginError, self.plugin.validate_model_snapshot, self.api)

    def test_create_named_snapshot(self):
        self.set_up_snapshot(filesystems_applied=True, set_up_nfs=True)
        self.api.snapshot_action = mock.MagicMock(return_value='create')
        self.api.snapshot_name = mock.MagicMock(return_value='OMBS')
        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'OMBS', timestamp=None)
        self.api._snapshot_object = mock.MagicMock(return_value=snap_item)
        tasks = self.plugin.create_snapshot_plan(self.api)
        self.assertTaskCount(tasks, 5)
        self.assertHostKeyTaskInTasks(tasks)

        mock_args = NasDrivers.Sfs, "10.44.86.226", "support", "support"
        with NasConnectionCallbackMock(self.callback_api, *mock_args) as nfs:
            for task in tasks:
                if task.callback == self.plugin._create_snapshot:
                    self.assertIn('Create NAS named backup snapshot "L_', task.description)
                    self.assertTrue(isinstance(task, CallbackTask), True)
                    self.plugin._create_snapshot(
                        self.callback_api, *task.args, **task.kwargs)

            self.assertFalse(
                set(['L_enm1-stor_OMBS', 'L_pm1_OMBS', 'L_enm1-stor2_OMBS']) - set((s.name for s in nfs.snapshot.list()))
            )

    def test_create_deployment_snapshot(self):
        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'snapshot', timestamp=None)
        self.api._snapshot_object = mock.MagicMock(return_value=snap_item)
        self.set_up_snapshot(filesystems_applied=True, set_up_nfs=True)
        self.api.snapshot_action = mock.MagicMock(return_value='create')
        self.api.snapshot_name = mock.MagicMock(return_value='snapshot')
        tasks = self.plugin.create_snapshot_plan(self.api)
        self.assertTaskCount(tasks, 5)
        self.assertHostKeyTaskInTasks(tasks)

        mock_args = NasDrivers.Sfs, "10.44.86.226", "support", "support"
        with NasConnectionCallbackMock(self.callback_api, *mock_args) as nfs:
            for task in tasks:
                if task.callback == self.plugin._create_snapshot:
                    self.assertIn('Create NAS deployment snapshot "L_', task.description)
                    self.assertTrue(isinstance(task, CallbackTask), True)
                    self.plugin._create_snapshot(
                        self.callback_api, *task.args, **task.kwargs)

            self.assertFalse(
                set(['L_enm1-stor_', 'L_pm1_', 'L_enm1-stor2_']) - set((s.name for s in nfs.snapshot.list()))
            )

    def test_snapshot_tasks_unmanaged_service(self):
        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'snapshot', timestamp=None)
        self.api._snapshot_object = mock.MagicMock(return_value=snap_item)
        self.create_sfs_service(managed=False, management_ipv4=None,
                                name="test")
        self.api.snapshot_action = mock.MagicMock(return_value='create')
        self.api.snapshot_name = mock.MagicMock(return_value='snapshot')
        tasks = self.plugin.create_snapshot_plan(self.api)
        self.assertTaskCount(tasks, 0)

        #--
        self.api.snapshot_model = mock.MagicMock(return_value=self.callback_api)
        self.api.snapshot_action = mock.MagicMock(return_value='remove')
        tasks = self.plugin.create_snapshot_plan(self.api)
        self.assertTaskCount(tasks, 0)

        #--
        self.api.snapshot_action = mock.MagicMock(return_value='restore')
        tasks = self.plugin.create_snapshot_plan(self.api)
        self.assertTaskCount(tasks, 0)

    def test_remove_named_snapshot(self):
        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'OMBS', timestamp=None)
        self.api._snapshot_object = mock.MagicMock(return_value=snap_item)
        self.api.snapshot_action = mock.MagicMock(return_value='remove')
        snap_tag_mock = self.api.snapshot_name = mock.MagicMock(return_value='OMBS')
        self.set_up_snapshot(filesystems_applied=True, set_up_nfs=True,
                             snap_tag=snap_tag_mock.return_value)
        mock_args = NasDrivers.Sfs, "10.44.86.226", "support", "support"

        # # TODO temporary solution
        self.api.snapshot_model = mock.MagicMock(return_value=self.callback_api)

        with NasConnectionCallbackMock(self.callback_api, *mock_args) as nfs:
            tasks = self.plugin.create_snapshot_plan(self.api)
            self.assertHostKeyTaskInTasks(tasks)
            delete_snapshot_tasks = [t for t in tasks if t.callback \
                                     == self.plugin._delete_snapshot]
            self.assertTaskCount(delete_snapshot_tasks, 3)
            for task in delete_snapshot_tasks:
                self.assertEqual(task.callback, self.plugin._delete_snapshot)
                self.assertTrue(isinstance(task, CallbackTask), True)
                try:
                    self.plugin._delete_snapshot(self.callback_api,
                                                        *task.args, **task.kwargs)
                except Exception as err:
                    self.assertEquals('CallbackExecutionException',
                                      err.__class__.__name__)
                try:
                    nfs.snapshot.delete("L_enm1-stor_OMBS", "enm1-stor")
                    self.plugin._delete_snapshot(self.callback_api,
                                                        *task.args, **task.kwargs)

                except Exception as err:
                    self.assertEquals('DoesNotExist',
                                      err.__class__.__name__)
                try:
                    #nfs.snapshot.delete("L_enm1-stor_OMBS", "enm1-stor")
                    self.plugin._delete_snapshot(self.callback_api,
                                                        *task.args, **task.kwargs)
                except CallbackExecutionException as err:
                    msg = 'SFS rollback ERROR V-288-2028 Rollback L_enm1-stor_OMBS '\
                          'does not exist for file system enm1-stor.. Command: '\
                          'storage rollback destroy L_enm1-stor_OMBS enm1-stor'
                    self.assertEqual(str(err), msg)
            remove_cache_task = next((t for t in tasks if t.callback \
                                      == self.plugin._remove_cache), None)
            self.assertEqual(remove_cache_task.callback, self.plugin._remove_cache)
            self.assertTrue(isinstance(remove_cache_task, CallbackTask), True)

    def test_remove_deployment_snapshot(self):
        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'snapshot', timestamp=None)
        self.api._snapshot_object = mock.MagicMock(return_value=snap_item)
        self.api.snapshot_action = mock.MagicMock(return_value='remove')
        snap_tag_mock = self.api.snapshot_name = mock.MagicMock(return_value='snapshot')
        self.set_up_snapshot(filesystems_applied=True, set_up_nfs=True,
                             snap_tag=snap_tag_mock.return_value)

        # # TODO temporary solution
        self.api.snapshot_model = mock.MagicMock(return_value=self.callback_api)

        mock_args = NasDrivers.Sfs, "10.44.86.226", "support", "support"
        with NasConnectionCallbackMock(self.callback_api, *mock_args) as nfs:
            tasks = self.plugin.create_snapshot_plan(self.api)
            delete_snapshot_tasks = [t for t in tasks if t.callback \
                                     == self.plugin._delete_snapshot]
            self.assertTaskCount(delete_snapshot_tasks, 3)
            for task in delete_snapshot_tasks:
                self.assertEqual(task.callback, self.plugin._delete_snapshot)
                self.assertTrue(isinstance(task, CallbackTask), True)

                try:
                    self.plugin._delete_snapshot(self.callback_api,
                                                        *task.args, **task.kwargs)
                except Exception as err:
                    self.assertEquals('CallbackExecutionException',
                                      err.__class__.__name__)
                try:
                    #nfs.snapshot.delete("L_enm1-stor_", "enm1-stor")
                    self.plugin._delete_snapshot(self.callback_api,
                                                        *task.args, **task.kwargs)

                except Exception as err:
                    msg = 'Snapshot deletion failed: SFS rollback ERROR V-288-758 '\
                          'File system enm1-stor does not exist.. Command: storage '\
                          'rollback destroy L_enm1-stor_ enm1-stor'
                    self.assertEqual(str(err), msg)
                try:

                    pool = nfs.pool.list()[0]
                    self.snap = nfs.snapshot.create("L_enm1-stor_", "enm1-stor", "mycache1")
                    self.plugin._delete_snapshot(self.callback_api,
                                                        *task.args, **task.kwargs)
                except Exception as err:
                    self.assertEquals('DoesNotExist',
                                      err.__class__.__name__)

                    msg = 'Snapshot creation failed: SFS rollback ERROR V-288-1768 '\
                          'cache object mycache1 does '\
                          'not exist. Create with <rollback cache create> Command: '\
                          'storage rollback create space-optimized L_enm1-stor_ enm1-stor mycache1'

                    self.assertEqual(str(err), msg)

            remove_cache_task = next((t for t in tasks if t.callback \
                                      == self.plugin._remove_cache), None)
            self.assertEqual(remove_cache_task.callback, self.plugin._remove_cache)
            self.assertTrue(isinstance(remove_cache_task, CallbackTask), True)

    def test_remove_deployment_snapshot_with_restore(self):
        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'OMBS', timestamp=None)
        self.api._snapshot_object = mock.MagicMock(return_value=snap_item)
        self.api.snapshot_action = mock.MagicMock(return_value='remove')
        snap_tag_mock = self.api.snapshot_name = mock.MagicMock(return_value='OMBS')
        self.set_up_snapshot(filesystems_applied=True)

        self.api.snapshot_model = mock.MagicMock(return_value=self.callback_api)

        tasks = self.plugin.create_snapshot_plan(self.api)
        self.assertTaskCount(tasks, 6)
        self.assertHostKeyTaskInTasks(tasks)
        task = tasks[1]

        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value

            # -- If restore is running - delete snapshot should
            #    raise a CallbackExecutionException
            nfs.filesystem.is_restore_running.return_value = True
            self.assertRaises(CallbackExecutionException, task.callback,
                    self.callback_api, *task.args, **task.kwargs)

            # -- If restore is not running - delete snapshot should
            #    succeed
            nfs.filesystem.is_restore_running.return_value = False
            self.plugin._check_restore_tasks_are_completed(
                    self.callback_api, *task.args, **task.kwargs)

    def test_remove_deployment_snapshot_with_restore_no_fs(self):
        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'OMBS',
                                     timestamp=None)
        self.api._snapshot_object = mock.MagicMock(return_value=snap_item)
        self.api.snapshot_action = mock.MagicMock(return_value='remove')
        self.set_up_snapshot(filesystems_applied=True)
        self.api.snapshot_model = mock.MagicMock(return_value=self.callback_api)
        tasks = self.plugin.create_snapshot_plan(self.api)
        self.assertTaskCount(tasks, 6)
        self.assertHostKeyTaskInTasks(tasks)
        check_tasks = [t for t in tasks if
                  t.callback == self.plugin._check_restore_tasks_are_completed]
        self.assertTaskCount(check_tasks, 1)
        task = check_tasks[0]
        fss = task.kwargs['fs_names']
        mock_args = NasDrivers.Sfs, "1.1.1.1", "some", "password"
        with NasConnectionCallbackMock(self.callback_api, *mock_args) as nfs:
            [i.delete() for i in nfs.snapshot.list() if i.filesystem in fss]
            [i.delete() for i in nfs.filesystem.list() if i.name in fss]
        task.callback(self.callback_api, *task.args, **task.kwargs)

    def test_incorrect_cache_name_on_remove_snapshot(self):
        # Don't give errors for files systems with incorrect cache_name
        # when removing the snapshot
        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'snapshot', timestamp=None)
        self.api._snapshot_object = mock.MagicMock(return_value=snap_item)
        self.api.snapshot_action = mock.MagicMock(return_value='remove')
        snap_tag_mock = self.api.snapshot_name = mock.MagicMock(return_value='snapshot')
        self.set_up_snapshot(filesystems_applied=True, set_up_nfs=True,
                             snap_tag=snap_tag_mock.return_value)

        # # TODO temporary solution
        self.api.snapshot_model = mock.MagicMock(return_value=self.callback_api)

        fs = self.create_filesystem(
            self.pool1, path="/vx/enm1-stor4", size="10M", snap_size='31',
            backup_policy="No", cache_name="incorrect")

        tasks = self.plugin.create_snapshot_plan(self.api)
        self.assertHostKeyTaskInTasks(tasks)
        delete_snapshot_tasks = [t for t in tasks if t.callback \
                                     == self.plugin._delete_snapshot]
        self.assertTaskCount(delete_snapshot_tasks, 3)

        for task in delete_snapshot_tasks:
            self.assertEqual(task.callback, self.plugin._delete_snapshot)
            self.assertTrue(isinstance(task, CallbackTask), True)
            self.plugin._delete_snapshot(
                self.callback_api, *task.args, **task.kwargs)

        errors = self.plugin.validate_model_snapshot(self.api)
        self.assertErrorCount(errors, 0)

    def test_remove_snapshot_without_cache_model_item(self):
        self.api.snapshot_model = mock.MagicMock(return_value=self.callback_api)
        self.setup_sfs_virtual_server(managed=True, pool_name="SFS_Pool")
        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'OMBS', timestamp=None)
        self.api._snapshot_object = mock.MagicMock(return_value=snap_item)
        snap_tag_mock = self.api.snapshot_name = mock.MagicMock(return_value='OMBS')

        fs = self.create_filesystem(self.pool1, path="/vx/enm1-stor", size="10M")
        fs.set_applied()
        self.plugin._remove_snapshot_tasks(self.api, snap_tag_mock.return_value,
                                           snap_item)

    def test_remove_snapshot_fail(self):
        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'OMBS', timestamp=None)
        self.api._snapshot_object = mock.MagicMock(return_value=snap_item)
        self.api.snapshot_action = mock.MagicMock(return_value='remove')
        snap_tag_mock = self.api.snapshot_name = mock.MagicMock(return_value='OMBS')
        self.set_up_snapshot(filesystems_applied=True)

        # # TODO temporary solution
        self.api.snapshot_model = mock.MagicMock(return_value=self.callback_api)

        tasks = self.plugin.create_snapshot_plan(self.api)
        self.assertTaskCount(tasks, 6)
        self.assertHostKeyTaskInTasks(tasks)
        tasks = tasks[2:5]
        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            snap = [Snapshot(nfs.snapshot, ('L_' + self.fs1.path[4:] + '_' + snap_tag_mock.return_value),
                             self.fs1.path[4:], self.cache.name)]
            nfs.snapshot.list.return_value = snap
            nfs.snapshot.delete.side_effect = Snapshot.DoesNotExist
            self.plugin._delete_snapshot(
                self.callback_api, *tasks[0].args, **tasks[0].kwargs)

        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            snap = [Snapshot(nfs.snapshot, ('L_' + self.fs1.path[4:] + '_' + snap_tag_mock.return_value),
                             self.fs1.path[4:], self.cache.name)]
            nfs.snapshot.list.return_value = snap
            nfs.snapshot.delete.side_effect = FileSystem.DoesNotExist
            self.plugin._delete_snapshot(
                self.callback_api, *tasks[0].args, **tasks[0].kwargs)
        with mock.patch.object(self.plugin, '_get_caches_pools') as _get_caches_pools:
            _get_caches_pools.return_value = [(self.cache, self.pool1)]
            tasks = self.plugin.create_snapshot_plan(self.api)
            self.assertTaskCount(tasks, 6)
            self.assertHostKeyTaskInTasks(tasks)

    def test_restore_deployment_snapshot(self):
        self._test_restore_snapshot('snapshot')

    def test_restore_named_snapshot(self):
        self._test_restore_snapshot('OMBS')

    def _test_restore_snapshot(self, snap_tag):
        snap_item = self.create_item("snapshot-base", "/snapshots/" + snap_tag, timestamp=None)
        self.api._snapshot_object = mock.MagicMock(return_value=snap_item)
        self.api.snapshot_action = mock.MagicMock(return_value='create')
        self.api.snapshot_name = mock.MagicMock(return_value=snap_tag)
        self.set_up_snapshot(filesystems_applied=True)

        # TODO temporary solution
        # As of now we are not able to get the snapshot model so we give it a current one
        # This means recreation of shares won't be tested fully, meaning will create them
        # based on current model where the snapshot model should have been used
        self.api.snapshot_model = mock.MagicMock(return_value=self.callback_api)
        self.plugin.create_snapshot_plan(self.api)

        exports = []
        export2 = self.create_export(self.fs1, clients="10.10.10.11")
        export3 = self.create_export(self.fs1, clients="10.10.10.12")
        exports.append(export2)
        exports.append(export3)
        exports.append(self.export1)
        for export in exports:
            export.set_applied()
            export._applied_properties = export.properties

        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            snaps = []
            for fs in [self.fs1, self.fs2, self.fs4]:
                snaps.append(Snapshot(nfs, self.plugin._create_snap_name(snap_tag, fs.path),
                             fs.path[4:], self.cache.name))
            nfs.snapshot.list.return_value = snaps

            nfs.share.list.return_value = [
                Share(nfs.share, self.fs1.path, '10.10.10.10', self.export1.options),
                Share(nfs.share, self.fs1.path, '10.10.10.11', export2.options),
                Share(nfs.share, self.fs1.path, '10.10.10.12', export3.options)]

            with mock.patch.object(self.plugin, 'nfs_shares_creation_callback') as nfs_shares_creation_callback:
                # TODO temporary solution
                # Won't be used until snapshot model is available in unit tests
                # shares_before_snap = [{
                #     'path': self.fs1.path,
                #     'clients': [self.export1.properties['ipv4allowed_clients']],
                #     'options': self.export1.properties['options']
                # }]

                all_shares = []
                for export in exports:
                    all_shares.append({
                        'path': self.fs1.path,
                        'clients': [export.properties['ipv4allowed_clients']],
                        'options': export.properties['options']
                    })

                self.api.snapshot_action = mock.MagicMock(return_value='restore')
                nfs.cache.list.return_value = [
                    Cache(self.pool1.name, self.cache.name, '10M', used=0, available=10)
                ]
                tasks = self.plugin.create_snapshot_plan(self.api)
                self.assertTaskCount(tasks, 6)
                self.assertHostKeyTaskInTasks(tasks)
                restore_snapshot_tasks = [task for task in tasks if task.callback == self.plugin._restore_snapshot]

                for restore_snapshot_task in restore_snapshot_tasks[0:2]:
                    self.plugin._restore_snapshot(
                        self.callback_api, *restore_snapshot_task.args, **restore_snapshot_task.kwargs)

                #Case where restore is running
                nfs.snapshot.restore.side_effect = Snapshot.RollsyncRunning
                self.plugin._restore_snapshot(
                    self.callback_api, *restore_snapshot_tasks[2].args, **restore_snapshot_tasks[2].kwargs)

                self.assertEquals(nfs.share.delete.mock_calls, [
                    mock.call(self.fs1.path, '10.10.10.10'),
                    mock.call(self.fs1.path, '10.10.10.11'),
                    mock.call(self.fs1.path, '10.10.10.12')])

                nfs.snapshot.restore.mock_calls.sort()

                self.assertEquals(nfs.snapshot.restore.mock_calls, [
                    mock.call(self.plugin._create_snap_name(snap_tag, self.fs4.path), self.fs4.path[4:]),
                    mock.call(self.plugin._create_snap_name(snap_tag, self.fs1.path), self.fs1.path[4:]),
                    mock.call(self.plugin._create_snap_name(snap_tag, self.fs2.path), self.fs2.path[4:])
                ])

                # TODO temporary solution
                nfs_shares_creation_callback.mock_calls.sort()
                self.assertEquals(nfs_shares_creation_callback.mock_calls, [
                    mock.call(self.callback_api,  self.sfs_service1.get_vpath(), []),
                    mock.call(self.callback_api,  self.sfs_service1.get_vpath(), []),
                    mock.call(self.callback_api,  self.sfs_service1.get_vpath(), all_shares),
                    # Once the snapshot model is available we can replace above line with the one below
                    # mock.call(self.callback_api, "Sfs", self.sfs_service1.get_vpath(), shares_before_snap)
                ])

    def test_restore_deployment_snapshot_fail(self):
        self._test_test_restore_snapshot_fail('snapshot')

    def test_restore_named_snapshot_fail(self):
        self._test_test_restore_snapshot_fail('OMBS')

    def _test_test_restore_snapshot_fail(self, snap_tag):
        snap_item = self.create_item("snapshot-base", "/snapshots/" + snap_tag, timestamp=None)
        self.api._snapshot_object = mock.MagicMock(return_value=snap_item)
        self.api.snapshot_action = mock.MagicMock(return_value='create')
        self.api.snapshot_name = mock.MagicMock(return_value=snap_tag)
        self.set_up_snapshot(filesystems_applied=True)
        self.plugin.create_snapshot_plan(self.api)

        # TODO temporary solution
        self.api.snapshot_model = mock.MagicMock(return_value=self.callback_api)
        self.api.snapshot_action = mock.MagicMock(return_value='restore')

        # Raise plugin error when there is no cache on SFS
        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            snaps = []
            for fs in [self.fs1, self.fs2, self.fs4]:
                snaps.append(Snapshot(nfs, self.plugin._create_snap_name(snap_tag, fs.path),
                             fs.path[4:], self.cache.name))
            nfs.snapshot.list.return_value = snaps
            nfs.cache.list.return_value = []
            tasks = self.plugin._restore_snapshot_tasks(self.api,
                              snap_tag, snap_item)
            self.assertTaskCount(tasks, 5)
            verify_cache_tasks = [task for task in tasks if task.callback == self.plugin.verify_cache_callback]
            self.assertTaskCount(verify_cache_tasks, 1)
            verify_snapshot_task = next((task for task in tasks if task.callback == self.plugin.verify_snapshots_callback), None)
            verify_cache_task = verify_cache_tasks[0]
            self.assertIn(verify_cache_task, verify_snapshot_task.requires)
            self.assertRaises(CallbackExecutionException, self.plugin.verify_cache_callback,
                    self.callback_api, *verify_cache_task.args, **verify_cache_task.kwargs)

        # Raise plugin error when cache on SFS is full
        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            snaps = []
            for fs in [self.fs1, self.fs2, self.fs4]:
                snaps.append(Snapshot(nfs, self.plugin._create_snap_name(snap_tag, fs.path),
                                      fs.path[4:], self.cache.name))
            nfs.snapshot.list.return_value = snaps
            nfs.cache.list.return_value = [
                Cache(self.pool1.name, self.cache.name, '10M', used=100, available=0)
            ]
            tasks = self.plugin._restore_snapshot_tasks(self.api,
                              snap_tag, snap_item)
            self.assertTaskCount(tasks, 5)
            verify_cache_tasks = [task for task in tasks if task.callback == self.plugin.verify_cache_callback]
            self.assertTaskCount(verify_cache_tasks, 1)
            verify_snapshot_task = next((task for task in tasks if task.callback == self.plugin.verify_snapshots_callback), None)
            verify_cache_task = verify_cache_tasks[0]
            self.assertIn(verify_cache_task, verify_snapshot_task.requires)
            self.assertTrue(
                verify_cache_task.tag_name == restore_snapshot_tags.VALIDATION_TAG,
                "verify cache task should have tag name VALIDATION_TAG")
            self.assertRaises(CallbackExecutionException, self.plugin.verify_cache_callback,
                self.callback_api, *verify_cache_task.args, **verify_cache_task.kwargs)


        # Raise plugin error when there are snapshot(s) missing on SFS
        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            nfs.snapshot.list.return_value = []
            nfs.cache.list.return_value = [
                Cache(self.pool1.name, self.cache.name, '10M', used=0, available=10)
            ]
            tasks = self.plugin._restore_snapshot_tasks(self.api,
                              snap_tag, snap_item)
            self.assertTaskCount(tasks, 5)
            verify_snapshot_tasks = [task for task in tasks if task.callback == self.plugin.verify_snapshots_callback]
            self.assertTaskCount(verify_snapshot_tasks, 1)
            verify_snapshot_task = verify_snapshot_tasks[0]
            try:
                self.plugin.verify_snapshots_callback(self.callback_api, *verify_snapshot_task.args, **verify_snapshot_task.kwargs)
            except CallbackExecutionException as e:
                pass
            self.assertTrue(isinstance(e, CallbackExecutionException))
            if snap_tag != 'snapshot':
                msg1 = 'The snapshots L_enm1-stor2_{snap_tag}, L_enm1-stor_{snap_tag}, L_pm1_{snap_tag} don\'t exist on NAS'.format(snap_tag=snap_tag)
                msg2 = 'The snapshots L_enm1-stor2_{snap_tag}, L_pm1_{snap_tag}, L_enm1-stor_{snap_tag} don\'t exist on NAS'.format(snap_tag=snap_tag)
                msg3 = 'The snapshots L_enm1-stor_{snap_tag}, L_enm1-stor2_{snap_tag}, L_pm1_{snap_tag} don\'t exist on NAs'.format(snap_tag=snap_tag)
                msg4 = 'The snapshots L_enm1-stor_{snap_tag}, L_pm1_{snap_tag}, L_enm1-stor2_{snap_tag} don\'t exist on NAS'.format(snap_tag=snap_tag)
                msg5 = 'The snapshots L_pm1_{snap_tag}, L_enm1-stor2_{snap_tag}, L_enm1-stor_{snap_tag} don\'t exist on NAS'.format(snap_tag=snap_tag)
                msg6 = 'The snapshots L_pm1_{snap_tag}, L_enm1-stor_{snap_tag}, L_enm1-stor2_{snap_tag} don\'t exist on NAS'.format(snap_tag=snap_tag)
            else:
                msg1 = 'The snapshots L_enm1-stor2_, L_pm1_, L_enm1-stor_ don\'t exist on NAS'
                msg2 = 'The snapshots L_enm1-stor2_, L_enm1-stor_, L_pm1_ don\'t exist on NAS'
                msg3 = 'The snapshots L_enm1-stor_, L_enm1-stor2_, L_pm1_ don\'t exist on NAS'
                msg4 = 'The snapshots L_enm1-stor_, L_pm1_, L_enm1-stor2_ don\'t exist on NAS'
                msg5 = 'The snapshots L_pm1_, L_enm1-stor2_, L_enm1-stor_ don\'t exist on NAS'
                msg6 = 'The snapshots L_pm1_, L_enm1-stor_, L_enm1-stor2_ don\'t exist on NAS'

            expected_errs = [msg1, msg2, msg3, msg4, msg5, msg6]
            self.assertTrue(any(x in str(e) for x in expected_errs))
            self.assertTrue(
                verify_snapshot_task.tag_name == restore_snapshot_tags.VALIDATION_TAG,
                "verify snapshots task should have tag name VALIDATION_TAG")

    def test_create_snap_name(self):
        self.setup_sfs_virtual_server(managed=True)
        create_filesystem_for_snapshot = lambda: self.create_filesystem(
            self.pool1, path="/vx/enm1-stor", size="1G", snap_size='10',
            backup_policy="No", cache_name="mycache")

        self.fs1 = create_filesystem_for_snapshot()
        self.fs1.set_applied()

        snap_tag = 'snapshot'
        snap_name = self.plugin._create_snap_name(snap_tag, self.fs1.path)
        self.assertEquals("L_enm1-stor_", str(snap_name))

        snap_tag = 'OMBS'
        snap_name = self.plugin._create_snap_name(snap_tag, self.fs1.path)
        self.assertEquals("L_enm1-stor_OMBS", str(snap_name))

        snap_tag = 'foo'
        snap_name = self.plugin._create_snap_name(snap_tag, self.fs1.path)
        self.assertNotEquals("L_enm1-stor_", str(snap_name))

    def test_remove_cache_object_success(self):
        self.set_up_snapshot(filesystems_applied=True)

        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'snapshot', timestamp=None)
        task = self.plugin._remove_cache_object_task(snap_item, self.sfs_service1,
                                                     self.cache, self.cache.get_vpath())

        # cache successfully created
        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            self.plugin._remove_cache(self.callback_api, *task.args, **task.kwargs)
            nfs.cache.delete.assert_called_once_with(self.cache.name)

    def test_remove_cache_object_fail(self):
        self.set_up_snapshot(filesystems_applied=True)

        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'snapshot', timestamp=None)
        task = self.plugin._remove_cache_object_task(snap_item, self.sfs_service1,
                                                     self.cache, self.cache.get_vpath())

        # cache successfully created
        with mock.patch.object(self.plugin, 'nfs_connection_class') as nfs_connection_class:
            nfs = nfs_connection_class.return_value.__enter__.return_value
            nfs.cache.delete.side_effect = Cache.DeletionException
            err = None
            try:
                self.plugin._remove_cache(self.callback_api, *task.args, **task.kwargs)
            except Exception as err:
                pass
            self.assertTrue(isinstance(err, Cache.DeletionException))
            nfs.cache.delete.assert_called_once_with(self.cache.name)

            #---
            nfs.cache.delete.side_effect = Cache.DoesNotExist
            err = None
            try:
                self.plugin._remove_cache(self.callback_api, *task.args, **task.kwargs)
            except Exception as err:
                self.assertTrue(isinstance(err, Cache.DoesNotExist))
                nfs.cache.delete.assert_called_once_with(self.cache.name)

    def test_restore_snapshot_force_option(self):
        snap_item = self.create_item("snapshot-base", "/snapshots/" + 'snapshot', timestamp=None)
        self.api._snapshot_object = mock.MagicMock(return_value=snap_item)
        self.set_up_snapshot(filesystems_applied=True, set_up_nfs=True)
        self.api.snapshot_action = mock.MagicMock(return_value='create')
        self.api.snapshot_name = mock.MagicMock(return_value='snapshot')

        tasks = self.plugin.create_snapshot_plan(self.api)
        self.assertTaskCount(tasks, 5)
        self.assertHostKeyTaskInTasks(tasks)

        for task in tasks:
            if task.callback != self.plugin._create_snapshot:
                continue
            self.assertIn('Create NAS deployment snapshot "L_', task.description)
            self.assertTrue(isinstance(task, CallbackTask), True)
            self.plugin._create_snapshot(self.callback_api, *task.args, **task.kwargs)

        # without -f option first
        self.api.snapshot_model = mock.MagicMock(return_value=self.callback_api)
        tasks = self.plugin._restore_snapshot_tasks(self.api, 'snapshot', snap_item)
        self.assertTaskCount(tasks, 5)
        self.assertTaskCount([t for t in tasks if t.callback == self.plugin._restore_snapshot], 3)
        self.assertTaskCount([t for t in tasks if t.callback == self.plugin.verify_snapshots_callback], 1)
        self.assertTaskCount([t for t in tasks if t.callback == self.plugin.verify_cache_callback], 1)

        # test RestoreException first
        snap_names = []
        for task in tasks:
            if task.callback != self.plugin._restore_snapshot:
                continue
            snap_names.append("L_%s_" % task.kwargs['filesystem']['path'].split('/')[-1])
            err = None
            fs = task.kwargs['filesystem']['path'].split('/')[-1]
            try:
                self.plugin._restore_snapshot(self.callback_api, *task.args, **task.kwargs)
            except CallbackExecutionException as err:
                pass
            self.assertEquals(err, None)

        # test snapshots missing

        # delete snapshots from sfs first
        mock_args = NasDrivers.Sfs, "0.0.0.0", "user", "password"

        with NasConnectionCallbackMock(self.callback_api, *mock_args) as nas:
            for snapshot in nas.snapshot.list():
                if snapshot.name in snap_names:
                    snapshot.delete()

        for task in tasks:
            if task.callback != self.plugin._restore_snapshot:
                continue
            snap_names.append("L_%s_" % task.kwargs['filesystem']['path'].split('/')[-1])
            fs = task.kwargs['filesystem']['path'].split('/')[-1]
            snap = "L_%s_" % fs
            err = None
            try:
                self.plugin._restore_snapshot(self.callback_api, *task.args, **task.kwargs)
            except CallbackExecutionException as err:
                pass
            if fs in ["enm1-stor2", "enm1-stor", "pm1"]:
                msg = "File system failed to restore: SFS rollback ERROR " \
                      "V-288-2029 Rollback %s does not exist for file " \
                      "system %s" % (snap, fs)
                self.assertTrue(msg in str(err), str(err))
            else:
                self.assertEquals(err, None)

        # with -f option
        self.api.is_snapshot_action_forced = mock.MagicMock(return_value=True)
        tasks = self.plugin._restore_snapshot_tasks(self.api, 'snapshot', snap_item)
        self.assertTaskCount(tasks, 4)
        self.assertTaskCount([t for t in tasks if t.callback == self.plugin._restore_snapshot], 3)
        self.assertTaskCount([t for t in tasks if t.callback == self.plugin.verify_cache_callback], 1)

        for task in tasks:
            if task.callback != self.plugin._restore_snapshot:
                continue
            # we expect everything to pass
            self.plugin._restore_snapshot(self.callback_api, *task.args, **task.kwargs)

    @mock.patch("naslib.ssh.SSHClient.get_remote_host_key")
    @mock.patch("naslib.paramikopatch.PatchedHostKeys.load")
    @mock.patch("__builtin__.open")
    def test_get_and_save_remote_host_key_callback_success(self, mock_open, load, get_remote):
        """ The SSHClient.get_remote_host_key method from "naslib" is
        completely mocked here, as it's been properly tested in there.

        A happy scenario is tested here:
         - The local known_host key file initially doesn't contain any key for
           the management_ipv4.
         - The remote key is then retrieved through naslib and saved to the
           known_hosts files.
        """

        # setup mock
        known_hosts_content = """
|1|nO527Fp0g6b2u8t62Y3CVaAvACo=|nUhi0mGYskcWpMd7xp1p0PlaFYM= ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAz4Mx3d1Houmq12jr0Pwqh84YfnPRvCHJ02WeTuiBjfZgRogj/EYhfbwCvW0m8L4/TUm4WhwPOn+8pbxnNadoB1E4Xy6En9FNDx8XZGlJNkmbIqvFzGXFLRGEQqTAY0BWOrbnP/hoo9e9dpxOrtHSAzdYEwMY4I8g1NMWQoPU9v1UT3m4jYfTzp0lMH5I8U7+sQxLsUdWfoAteiyc2ldzJLxnsFNRjpCjLYxuX757bJkeub3KAy09KZwIddpdxdpcgW09v+MCzoTxLiqrt7ojeSjz/yba0PTD9LM2OemPHZmr0CkZZ52D5JrJjbfCl0+NYtM5ONEaCPao4FaBcxto8Q==
|1|SYGH0OHF0EsQJZHgt15iUBpFsAk=|rlps+sOFWJFAZ/Y2X5xSzrLtnkQ= ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAyb/XrK6W3ZjLKafS3HFILL8+Hi+aoHxnqNhHzHWF4TZaVRKSZRLCWybjMNpopJOLWs/QC5JBeqERg88ZSqnemLo8dZaa/x52ohomFlyPRCe2JfyJPl4mki8CFfBHoCvXEDEliLmVnkaTGVTxwnNA0eMsIvJkxGpnPQ3qxakajlXFn0toykXFmv1STY96CwaayrqOCctjXptn3kc9UgBoOJlQhpEgHRoixl64dxgX2+SA2n6o4Xt9qDZH/g2/VDrlMU42jfDPTdWBwcJagWx6AZBTDdr5uraXkzVl5wtb2u3jZf8rdpMl7IVJaMYwz7XDj7wOdWXGduBhU/pB2c4CUQ==
|1|DwHb26gFhNfZ5MStJ3nGlIsmpgY=|wFKBFMNPnuR1qImxWkUZ7T7qvXg= ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAyb/XrK6W3ZjLKafS3HFILL8+Hi+aoHxnqNhHzHWF4TZaVRKSZRLCWybjMNpopJOLWs/QC5JBeqERg88ZSqnemLo8dZaa/x52ohomFlyPRCe2JfyJPl4mki8CFfBHoCvXEDEliLmVnkaTGVTxwnNA0eMsIvJkxGpnPQ3qxakajlXFn0toykXFmv1STY96CwaayrqOCctjXptn3kc9UgBoOJlQhpEgHRoixl64dxgX2+SA2n6o4Xt9qDZH/g2/VDrlMU42jfDPTdWBwcJagWx6AZBTDdr5uraXkzVl5wtb2u3jZf8rdpMl7IVJaMYwz7XDj7wOdWXGduBhU/pB2c4CUQ==
2.2.2.2 ssh-rsa CORRUPTED_ONE_oHxnqNhHzHWF4TZaVRKSZRLCWybjMNpopJOLWs/QC5JBeqERg88ZSqnemLo8dZaa/x52ohomFlyPRCe2JfyJPl4mki8CFfBHoCvXEDEliLmVnkaTGVTxwnNA0eMsIvJkxGpnPQ3qxakajlXFn0toykXFmv1STY96CwaayrqOCctjXptn3kc9UgBoOJlQhpEgHRoixl64dxgX2+SA2n6o4Xt9qDZH/g2/VDrlMU42jfDPTdWBwcJagWx6AZBTDdr5uraXkzVl5wtb2u3jZf8rdpMl7IVJaMYwz7XDj7wOdWXGduBhU/pB2c4CUQ==
"""
        # mocking the SSHClient.get_remote_host_key method
        string_key = "AAAAB3NzaC1yc2EAAAABIwAAAQEAyb/XrK6W3ZjLKafS3HFILL8+Hi+aoHxnqNhHzHWF4TZaVRKSZRLCWybjMNpopJOLWs/QC5JBeqERg88ZSqnemLo8dZaa/x52ohomFlyPRCe2JfyJPl4mki8CFfBHoCvXEDEliLmVnkaTGVTxwnNA0eMsIvJkxGpnPQ3qxakajlXFn0toykXFmv1STY96CwaayrqOCctjXptn3kc9UgBoOJlQhpEgHRoixl64dxgX2+SA2n6o4Xt9qDZH/g2/VDrlMU42jfDPTdWBwcJagWx6AZBTDdr5uraXkzVl5wtb2u3jZf8rdpMl7IVJaMYwz7XDj7wOdWXGduBhU/pB2c4CUQ=="
        get_remote.return_value = RSAKey(data=base64.decodestring(string_key))

        # mocking PatchedHostKeys.load method to raise IOError
        load.side_effect = IOError

        # end of SSHClient.get_remote_host_key method mock

        file_to_be_saved = StringIO()  # reference to be used at the end of this test
        def mopen(filename, mode):
            if filename.endswith('.ssh/known_hosts'):
                if mode == 'r':
                    return StringIO(known_hosts_content)
                elif mode == 'w':
                    return file_to_be_saved
                else:
                    raise Exception('known_hosts file not expected to be '
                        'opened with a different mode other than "r" and "w".')
            else:
                return StringIO()

        mock_open.side_effect = mopen

        # setup litp model
        self.setup_sfs_virtual_server(managed=True, pool_name="SFS_Pool")
        self._remove_empty_pools_from_set_up()
        fs1 = self.create_filesystem(self.pool1, path="/vx/enm1-stor",
                                     size="10M")
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 2)
        self.assertHostKeyTaskInTasks(tasks)
        cb = self.plugin.get_and_save_remote_host_key_callback
        creation_callback = next((t for t in tasks if t.callback == cb), None)
        self.assertIsNotNone(creation_callback)
        service = self.query_parent(fs1, 'sfs-service')
        self.assertIsNotNone(service)

        # run get_and_save_remote_host_key_callback
        creation_callback.callback(self.callback_api, service.get_vpath())

        management_ipv4 = "10.44.86.226"
        buflist = reduce(lambda a, b: a + b, [l.split('\n') for l in file_to_be_saved.buflist], [])
        entries = [l.strip() for l in buflist if l.strip().startswith(management_ipv4)]
        self.assertEquals(len(entries), 1)
        entry = entries[0]
        self.assertIsNotNone(entry)
        splited = entry.split()
        self.assertEquals(len(splited), 3)
        ip, key_type, base64_key = splited
        self.assertEquals(ip, management_ipv4)
        self.assertEquals(key_type, 'ssh-rsa')
        self.assertEquals(base64_key, string_key)

    @mock.patch("naslib.ssh.SSHClient.get_remote_host_key")
    @mock.patch("__builtin__.open")
    def test_get_and_save_remote_host_key_callback_already_in_success(self, mock_open, get_remote):
        """ The SSHClient.get_remote_host_key method from "naslib" is
        completely mocked here, as it's been properly tested in there.

        Another happy scenario is tested here, but:
         - The local known_host key file initially already contains the key for
           the management_ipv4.
         - The remote key is retrieved through naslib and compared with local
           and it just skips.
        """

        # setup mock
        known_hosts_content = """
|1|nO527Fp0g6b2u8t62Y3CVaAvACo=|nUhi0mGYskcWpMd7xp1p0PlaFYM= ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAz4Mx3d1Houmq12jr0Pwqh84YfnPRvCHJ02WeTuiBjfZgRogj/EYhfbwCvW0m8L4/TUm4WhwPOn+8pbxnNadoB1E4Xy6En9FNDx8XZGlJNkmbIqvFzGXFLRGEQqTAY0BWOrbnP/hoo9e9dpxOrtHSAzdYEwMY4I8g1NMWQoPU9v1UT3m4jYfTzp0lMH5I8U7+sQxLsUdWfoAteiyc2ldzJLxnsFNRjpCjLYxuX757bJkeub3KAy09KZwIddpdxdpcgW09v+MCzoTxLiqrt7ojeSjz/yba0PTD9LM2OemPHZmr0CkZZ52D5JrJjbfCl0+NYtM5ONEaCPao4FaBcxto8Q==
|1|SYGH0OHF0EsQJZHgt15iUBpFsAk=|rlps+sOFWJFAZ/Y2X5xSzrLtnkQ= ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAyb/XrK6W3ZjLKafS3HFILL8+Hi+aoHxnqNhHzHWF4TZaVRKSZRLCWybjMNpopJOLWs/QC5JBeqERg88ZSqnemLo8dZaa/x52ohomFlyPRCe2JfyJPl4mki8CFfBHoCvXEDEliLmVnkaTGVTxwnNA0eMsIvJkxGpnPQ3qxakajlXFn0toykXFmv1STY96CwaayrqOCctjXptn3kc9UgBoOJlQhpEgHRoixl64dxgX2+SA2n6o4Xt9qDZH/g2/VDrlMU42jfDPTdWBwcJagWx6AZBTDdr5uraXkzVl5wtb2u3jZf8rdpMl7IVJaMYwz7XDj7wOdWXGduBhU/pB2c4CUQ==
|1|DwHb26gFhNfZ5MStJ3nGlIsmpgY=|wFKBFMNPnuR1qImxWkUZ7T7qvXg= ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAyb/XrK6W3ZjLKafS3HFILL8+Hi+aoHxnqNhHzHWF4TZaVRKSZRLCWybjMNpopJOLWs/QC5JBeqERg88ZSqnemLo8dZaa/x52ohomFlyPRCe2JfyJPl4mki8CFfBHoCvXEDEliLmVnkaTGVTxwnNA0eMsIvJkxGpnPQ3qxakajlXFn0toykXFmv1STY96CwaayrqOCctjXptn3kc9UgBoOJlQhpEgHRoixl64dxgX2+SA2n6o4Xt9qDZH/g2/VDrlMU42jfDPTdWBwcJagWx6AZBTDdr5uraXkzVl5wtb2u3jZf8rdpMl7IVJaMYwz7XDj7wOdWXGduBhU/pB2c4CUQ==
10.44.86.226 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAyb/XrK6W3ZjLKafS3HFILL8+Hi+aoHxnqNhHzHWF4TZaVRKSZRLCWybjMNpopJOLWs/QC5JBeqERg88ZSqnemLo8dZaa/x52ohomFlyPRCe2JfyJPl4mki8CFfBHoCvXEDEliLmVnkaTGVTxwnNA0eMsIvJkxGpnPQ3qxakajlXFn0toykXFmv1STY96CwaayrqOCctjXptn3kc9UgBoOJlQhpEgHRoixl64dxgX2+SA2n6o4Xt9qDZH/g2/VDrlMU42jfDPTdWBwcJagWx6AZBTDdr5uraXkzVl5wtb2u3jZf8rdpMl7IVJaMYwz7XDj7wOdWXGduBhU/pB2c4CUQ==
2.2.2.2 ssh-rsa CORRUPTED_ONE_oHxnqNhHzHWF4TZaVRKSZRLCWybjMNpopJOLWs/QC5JBeqERg88ZSqnemLo8dZaa/x52ohomFlyPRCe2JfyJPl4mki8CFfBHoCvXEDEliLmVnkaTGVTxwnNA0eMsIvJkxGpnPQ3qxakajlXFn0toykXFmv1STY96CwaayrqOCctjXptn3kc9UgBoOJlQhpEgHRoixl64dxgX2+SA2n6o4Xt9qDZH/g2/VDrlMU42jfDPTdWBwcJagWx6AZBTDdr5uraXkzVl5wtb2u3jZf8rdpMl7IVJaMYwz7XDj7wOdWXGduBhU/pB2c4CUQ==
"""
        # mocking the SSHClient.get_remote_host_key method
        string_key = "AAAAB3NzaC1yc2EAAAABIwAAAQEAyb/XrK6W3ZjLKafS3HFILL8+Hi+aoHxnqNhHzHWF4TZaVRKSZRLCWybjMNpopJOLWs/QC5JBeqERg88ZSqnemLo8dZaa/x52ohomFlyPRCe2JfyJPl4mki8CFfBHoCvXEDEliLmVnkaTGVTxwnNA0eMsIvJkxGpnPQ3qxakajlXFn0toykXFmv1STY96CwaayrqOCctjXptn3kc9UgBoOJlQhpEgHRoixl64dxgX2+SA2n6o4Xt9qDZH/g2/VDrlMU42jfDPTdWBwcJagWx6AZBTDdr5uraXkzVl5wtb2u3jZf8rdpMl7IVJaMYwz7XDj7wOdWXGduBhU/pB2c4CUQ=="
        get_remote.return_value = RSAKey(data=base64.decodestring(string_key))
        # end of SSHClient.get_remote_host_key method mock

        file_to_be_saved = StringIO(known_hosts_content)  # reference to be used at the end of this test
        def mopen(filename, mode):
            if filename.endswith('.ssh/known_hosts'):
                if mode == 'r':
                    return StringIO(known_hosts_content)
                elif mode == 'w':
                    return file_to_be_saved
                else:
                    raise Exception('known_hosts file not expected to be '
                        'opened with a different mode other than "r" and "w".')
            else:
                return StringIO(known_hosts_content)

        mock_open.side_effect = mopen

        # setup litp model
        self.setup_sfs_virtual_server(managed=True, pool_name="SFS_Pool")
        self._remove_empty_pools_from_set_up()
        fs1 = self.create_filesystem(self.pool1, path="/vx/enm1-stor",
                                     size="10M")
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 2)
        self.assertHostKeyTaskInTasks(tasks)
        cb = self.plugin.get_and_save_remote_host_key_callback
        creation_callback = next((t for t in tasks if t.callback == cb), None)
        self.assertIsNotNone(creation_callback)
        service = self.query_parent(fs1, 'sfs-service')
        self.assertIsNotNone(service)

        # run get_and_save_remote_host_key_callback
        creation_callback.callback(self.callback_api, service.get_vpath())

        management_ipv4 = "10.44.86.226"
        buflist = reduce(lambda a, b: a + b, [l.split('\n') for l in file_to_be_saved.buflist], [])
        entries = [l.strip() for l in buflist if l.strip().startswith(management_ipv4)]
        self.assertEquals(len(entries), 0)

    @mock.patch("naslib.ssh.SSHClient.get_remote_host_key")
    @mock.patch("__builtin__.open")
    def test_get_and_save_remote_host_key_callback_already_in_but_different_base64(self, mock_open, get_remote):
        """ The SSHClient.get_remote_host_key method from "naslib" is
        completely mocked here, as it's been properly tested in there.

        The test is basically:
         - The local known_host key file initially already contains a key for
           the management_ipv4, however it is a different one and it doesn't
           match the remote.
         - The remote key is retrieved through naslib, compared with local,
           and it should be included in the known_hosts file. The old key
           that didn't match should be still there as well.
        """

        # setup mock
        old_key = "AAAAB3NzaC1yc2EAAAABIwAAAIEA1tpsh/tUchGaleEmTcEIQuxXxzOyq6uMQgN0QsbTmRNzgtKCbBitwqPO3sxMVWyIpF9DpK2/VFDxdJAE/tHB7Tn/2ogrKAGtn4WXWtUH8YuDitVGUhpfrZGpvaqD7QciCaYdHs7kBAMgkD8IY8q/8SCrnNEAaMp+rSoy+97GAAA="
        known_hosts_content = """
|1|nO527Fp0g6b2u8t62Y3CVaAvACo=|nUhi0mGYskcWpMd7xp1p0PlaFYM= ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAz4Mx3d1Houmq12jr0Pwqh84YfnPRvCHJ02WeTuiBjfZgRogj/EYhfbwCvW0m8L4/TUm4WhwPOn+8pbxnNadoB1E4Xy6En9FNDx8XZGlJNkmbIqvFzGXFLRGEQqTAY0BWOrbnP/hoo9e9dpxOrtHSAzdYEwMY4I8g1NMWQoPU9v1UT3m4jYfTzp0lMH5I8U7+sQxLsUdWfoAteiyc2ldzJLxnsFNRjpCjLYxuX757bJkeub3KAy09KZwIddpdxdpcgW09v+MCzoTxLiqrt7ojeSjz/yba0PTD9LM2OemPHZmr0CkZZ52D5JrJjbfCl0+NYtM5ONEaCPao4FaBcxto8Q==
|1|SYGH0OHF0EsQJZHgt15iUBpFsAk=|rlps+sOFWJFAZ/Y2X5xSzrLtnkQ= ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAyb/XrK6W3ZjLKafS3HFILL8+Hi+aoHxnqNhHzHWF4TZaVRKSZRLCWybjMNpopJOLWs/QC5JBeqERg88ZSqnemLo8dZaa/x52ohomFlyPRCe2JfyJPl4mki8CFfBHoCvXEDEliLmVnkaTGVTxwnNA0eMsIvJkxGpnPQ3qxakajlXFn0toykXFmv1STY96CwaayrqOCctjXptn3kc9UgBoOJlQhpEgHRoixl64dxgX2+SA2n6o4Xt9qDZH/g2/VDrlMU42jfDPTdWBwcJagWx6AZBTDdr5uraXkzVl5wtb2u3jZf8rdpMl7IVJaMYwz7XDj7wOdWXGduBhU/pB2c4CUQ==
|1|DwHb26gFhNfZ5MStJ3nGlIsmpgY=|wFKBFMNPnuR1qImxWkUZ7T7qvXg= ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAyb/XrK6W3ZjLKafS3HFILL8+Hi+aoHxnqNhHzHWF4TZaVRKSZRLCWybjMNpopJOLWs/QC5JBeqERg88ZSqnemLo8dZaa/x52ohomFlyPRCe2JfyJPl4mki8CFfBHoCvXEDEliLmVnkaTGVTxwnNA0eMsIvJkxGpnPQ3qxakajlXFn0toykXFmv1STY96CwaayrqOCctjXptn3kc9UgBoOJlQhpEgHRoixl64dxgX2+SA2n6o4Xt9qDZH/g2/VDrlMU42jfDPTdWBwcJagWx6AZBTDdr5uraXkzVl5wtb2u3jZf8rdpMl7IVJaMYwz7XDj7wOdWXGduBhU/pB2c4CUQ==
10.44.86.226 ssh-rsa %s
2.2.2.2 ssh-rsa CORRUPTED_ONE_oHxnqNhHzHWF4TZaVRKSZRLCWybjMNpopJOLWs/QC5JBeqERg88ZSqnemLo8dZaa/x52ohomFlyPRCe2JfyJPl4mki8CFfBHoCvXEDEliLmVnkaTGVTxwnNA0eMsIvJkxGpnPQ3qxakajlXFn0toykXFmv1STY96CwaayrqOCctjXptn3kc9UgBoOJlQhpEgHRoixl64dxgX2+SA2n6o4Xt9qDZH/g2/VDrlMU42jfDPTdWBwcJagWx6AZBTDdr5uraXkzVl5wtb2u3jZf8rdpMl7IVJaMYwz7XDj7wOdWXGduBhU/pB2c4CUQ==
""" % old_key

        # mocking the SSHClient.get_remote_host_key method
        string_key = "AAAAB3NzaC1yc2EAAAABIwAAAQEAyb/XrK6W3ZjLKafS3HFILL8+Hi+aoHxnqNhHzHWF4TZaVRKSZRLCWybjMNpopJOLWs/QC5JBeqERg88ZSqnemLo8dZaa/x52ohomFlyPRCe2JfyJPl4mki8CFfBHoCvXEDEliLmVnkaTGVTxwnNA0eMsIvJkxGpnPQ3qxakajlXFn0toykXFmv1STY96CwaayrqOCctjXptn3kc9UgBoOJlQhpEgHRoixl64dxgX2+SA2n6o4Xt9qDZH/g2/VDrlMU42jfDPTdWBwcJagWx6AZBTDdr5uraXkzVl5wtb2u3jZf8rdpMl7IVJaMYwz7XDj7wOdWXGduBhU/pB2c4CUQ=="
        get_remote.return_value = RSAKey(data=base64.decodestring(string_key))
        # end of SSHClient.get_remote_host_key method mock

        file_to_be_saved = StringIO(known_hosts_content)  # reference to be used at the end of this test
        def mopen(filename, mode):
            if filename.endswith('.ssh/known_hosts'):
                if mode == 'r':
                    return StringIO(known_hosts_content)
                elif mode == 'w':
                    return file_to_be_saved
                else:
                    raise Exception('known_hosts file not expected to be '
                        'opened with a different mode other than "r" and "w".')
            else:
                return StringIO(known_hosts_content)

        mock_open.side_effect = mopen

        # setup litp model
        self.setup_sfs_virtual_server(managed=True, pool_name="SFS_Pool")
        self._remove_empty_pools_from_set_up()
        fs1 = self.create_filesystem(self.pool1, path="/vx/enm1-stor",
                                     size="10M")
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        tasks = self.plugin.create_configuration(self.api)
        self.assertTaskCount(tasks, 2)
        self.assertHostKeyTaskInTasks(tasks)
        cb = self.plugin.get_and_save_remote_host_key_callback
        creation_callback = next((t for t in tasks if t.callback == cb), None)
        self.assertIsNotNone(creation_callback)
        service = self.query_parent(fs1, 'sfs-service')
        self.assertIsNotNone(service)

        # run get_and_save_remote_host_key_callback
        creation_callback.callback(self.callback_api, service.get_vpath())

        management_ipv4 = "10.44.86.226"
        buflist = reduce(lambda a, b: a + b, [l.split('\n') for l in file_to_be_saved.buflist], [])
        entries = [l.strip() for l in buflist if l.strip().startswith(management_ipv4)]
        self.assertEquals(len(entries), 2)
        entry = entries[0]
        splited = entry.split()
        self.assertEquals(len(splited), 3)
        ip, key_type, base64_key = splited
        self.assertEquals(ip, management_ipv4)
        self.assertEquals(key_type, 'ssh-rsa')
        self.assertEquals(base64_key, old_key)

        # now the second entry
        entry = entries[1]
        splited = entry.split()
        self.assertEquals(len(splited), 3)
        ip, key_type, base64_key2 = splited
        self.assertNotEquals(base64_key, base64_key2)
        self.assertEquals(ip, management_ipv4)
        self.assertEquals(key_type, 'ssh-rsa')
        self.assertEquals(base64_key2, string_key)

    def test_prepare_restore_behaviour(self):
        # setup litp model
        service, exports, mounts, filesystems = self.setup_create_configuration_test_environment()
        tasks = self.plugin.create_configuration(self.api)
        # 20 tasks should be created:
        #  - 5 file systems -> 1 fs per each
        #  - 5 shares -> 1 share per each
        #  - 5 mounts -> 1 mount per export for node 1
        #  - 5 mounts -> 1 mount per export for node 2
        #  - 5 mounts -> 1 mount per export for ms
        self.assertTaskCount(tasks, 26)
        # for the 25 tasks:
        #  - 10 should be CallBackTasks: regarding 5 shares and 5 fs
        #  - 15 should be ConfigTasks: regarding 15 mounts, 5 per node and ms
        cbts = [t for t in tasks if isinstance(t, CallbackTask)]
        config_tasks = [t for t in tasks if isinstance(t, ConfigTask)]
        self.assertTaskCount(cbts, 11)
        self.assertTaskCount(config_tasks, 15)
        self.assertTrue(service.is_initial())
        # tests the requires
        cb_dict = self.plugin.callback_tasks_by_export_path(cbts)
        for task in config_tasks:
           if not task.node.is_ms():
               continue
           path = task.model_item.export_path
           provider = task.model_item.provider
           self.assertTrue(provider in cb_dict)
           self.assertTrue(path in cb_dict[provider])
           self.assertEquals(task.requires, set([cb_dict[provider][path]]))
        plan = self.execution.create_plan()
        # let's simulate running the tasks, to check states and mark as applied
        self._run_tasks_test(tasks, exports, mounts)
        # after running, all should be applied
        service.set_applied()
        self.assertTrue(service.is_applied())
        # Set FS's and exports back to initial but leave mounts on MS
        # in applied state set mounts on node back to initial
        # same as BUR does with prepare_restore
        for filesystem in filesystems:
            filesystem.set_initial()
        for export in exports:
            export.set_initial()
        for node in self.nodes:
            for mount_model_item in node.file_systems.children.values():
                mount_model_item.set_initial()
        tasks = self.plugin.create_configuration(self.api)
        # we expect 26 tasks, 5 for each FS and export
        # 5 for the mounts on the MS/nodes each and one for the host keys
        self.assertEquals(len(tasks), 26)
        cbts = [t for t in tasks if isinstance(t, CallbackTask)]
        config_tasks = [t for t in tasks if isinstance(t, ConfigTask)]
        self.assertTaskCount(cbts, 11)
        self.assertTaskCount(config_tasks, 15)

    def test_unityxt_create_nasserver(self):
        json_file_name = "%s/test_unityxt_create_nasserver.json" % os.path.dirname(os.path.abspath(__file__))
        UnityRESTMocker.setup("10.44.86.226")
        UnityRESTMocker.reset()
        UnityRESTMocker.load(json_file_name)

        self.setup_sfs_virtual_server(
            managed=True,
            applied=False,
            sfs_nas_type='unityxt'
        )

        save_class = self.plugin.nfs_connection_class
        self.plugin.nfs_connection_class = NasConnectionCallback

        tasks = self.plugin.generate_nasserver_tasks(self.api)
        for task in tasks:
            if task.callback == self.plugin.nfs_server_creation_callback:
                #self.assertIn('Create NAS server "L_', task.description)
                self.assertTrue(isinstance(task, CallbackTask), True)
                test_callback = self.plugin.nfs_server_creation_callback(
                    self.callback_api, *task.args, **task.kwargs)
            else:
                self.assertIsNotNone(task.callback)

        self.plugin.nfs_connection_class = save_class

    def test_create_nasserver_no_nas_sfs_empty(self):
        self.api.query = mock.MagicMock(return_value=[])
        tasks = self.plugin.generate_nasserver_tasks(self.api)
        self.assertTrue(len(tasks) == 0)

    def test_create_nasserver_no_nas_no_sfs(self):
        self.api.query = mock.MagicMock(return_value=None)
        tasks = self.plugin.generate_nasserver_tasks(self.api)
        self.assertTrue(len(tasks) == 0)

    def test_nfs_ns_change_sharing_protocol_callback(self):
        json_file_name = "%s/test_unityxt_change_sharing_protocol.json" % os.path.dirname(os.path.abspath(__file__))
        UnityRESTMocker.setup("10.44.86.226")
        UnityRESTMocker.reset()
        UnityRESTMocker.load(json_file_name)

        self.setup_sfs_virtual_server(
            managed=True,
            applied=True,
            sfs_nas_type='unityxt'
        )
        self._remove_empty_pools_from_set_up()
        self.fs1 = self.create_filesystem(
                                self.pool1, path="/enm1-stor", size="3G",
                                data_reduction="true", provider="vsvr1")
        helper = IpAddressHelper(ipv6=False, network2=False)
        node1 = self.create_node()
        self.setup_nfs_network(node1, updated_interface=False)
        self.node1_interface2.set_for_removal()
        self.setup_nfs_mount_clientaddr(node1, clientaddr="10.10.10.10",
                                        nfs_mount_network_name="storage", provider="vsvr9")
        sfs_service1 = self.create_sfs_service(managed=False, management_ipv4="10.10.10.10")
        self.vs1 = self.sfs_virtual_server1 = self.create_virtual_server(sfs_service1, name="vsvr9",
                ipv4address="10.10.10.100", sharing_protocols="nfsv3")
        self.vs1.set_applied()
        self.vs2 = self.sfs_virtual_server2 = self.create_virtual_server(sfs_service1, name="vsvr8",
                ipv4address="10.10.10.101", sharing_protocols="nfsv3")
        self.vs2.set_applied()
        self.plugin.nfs_connection_class = NasConnectionCallback
        self.update_item(self.vs1, sharing_protocols="nfsv3,nfsv4")
        self.update_item(self.vs2, sharing_protocols="nfsv3,nfsv4")
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)

        tasks = self.plugin.generate_nasserver_tasks(self.api)
        for task in tasks:
            if task.callback == self.plugin.nfs_ns_change_sharing_protocol_callback:
                self.assertTrue(isinstance(task, CallbackTask), True)
                test_callback = self.plugin.nfs_ns_change_sharing_protocol_callback(
                    self.callback_api, *task.args, **task.kwargs)
        self.assertIsNotNone(task.callback)


if __name__ == '__main__':
    unittest.main()
