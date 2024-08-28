##############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from litp.core.execution_manager import ExecutionManager
from litp.core.model_manager import ModelManager
from litp.core.model_type import ItemType, Child
from litp.core.plugin_context_api import PluginApiContext
from litp.core.plugin_manager import PluginManager
from litp.extensions.core_extension import CoreExtension
from litp.core.callback_api import CallbackApi

from litp.core.puppet_manager import PuppetManager
from nas_extension.nas_extension import NasExtension
from nas_plugin.nas_plugin import NasPlugin
from nas_plugin.nas_cmd_api import NasCmdApi, NasCmdApiException
import unittest
import mock



class TestNasCmdApi(unittest.TestCase):

    def setUp(self):
        self.plugin = NasPlugin()
        self.model = ModelManager()
        self.plugin_manager = PluginManager(self.model)
        self.puppet_manager = PuppetManager(self.model)
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
        self.plugin_manager.add_default_model()
        self.model.item_types.pop('root')
        self.model.register_item_type(ItemType("another_node",
                extend_item="node"))
        self.model.register_item_type(ItemType("root",
            node1=Child("node"),
            node2=Child("another_node"),
            ))
        self.model.create_root_item("root", "/")
        node = self.model.create_item("node", "/node1", hostname="node1")

        self.plugin = NasPlugin()
        self.plugin_manager.add_plugin('NasPlugin', 'nas_plugin.nas_plugin',
                '1.0.1-SNAPSHOT', self.plugin)
        self.nodes = []
        self.nodes.append(node.hostname)
        self.nas = NasCmdApi(self.nodes)
        self.assertEquals("node1", self.nas.node[0])

    @mock.patch('nas_plugin.nas_cmd_api.NasCmdApi._call_mco')
    def test_call_mount_ipv4_success(self, _call_mco):
        _call_mco.return_value = {"retcode" : 0, "out": "Worked"}
        args = {'ipv4': '192.168.56.111', 'export_path' : '/cluster', 'mount_point' : '/cluster'}
        self.nas.mount_ipv4(args)
        _call_mco.assert_called_once_with('mount_ipv4',
                                          { 'ipv4': '192.168.56.111',
                                            'export_path' : '/cluster',
                                            'mount_point' : '/cluster'},
                                            None) # None is default timeout arg

    @mock.patch('nas_plugin.nas_cmd_api.log')
    @mock.patch('nas_plugin.nas_cmd_api.run_rpc_command')
    def test_mount_ipv4_success(self, run_rpc_command, log):
        #_call_mco.return_value = {"retcode" : 0, "out": "Worked"}
        args = {'ipv4': '192.168.56.111', 'export_path' : '/cluster', 'mount_point' : '/cluster'}
        run_rpc_command.return_value = {
                'node1': {'errors': '',
                        'data':
                            {'retcode': 0, 'err': '', 'out': ''}}
                }
        data_result = self.nas._call_mco("mount_ipv4", args)
        self.assertEquals(log.trace.info.call_args_list, [
            mock.call('Running MCO NAS command \"mco rpc nas mount_ipv4 '\
                    'mount_point=/cluster ipv4=192.168.56.111 '\
                    'export_path=/cluster'\
                    ' -I [\'node1\']\" '),
            ])

    @mock.patch('nas_plugin.nas_cmd_api.log')
    @mock.patch('nas_plugin.nas_cmd_api.run_rpc_command')
    def test_mount_ipv4_unsuccessful(self, run_rpc_command, log):
        #_call_mco.return_value = {"retcode" : 0, "out": "Worked"}
        args = {'ipv4': '192.168.56.111', 'export_path' : '/cluster', 'mount_point' : '/cluster'}
        run_rpc_command.return_value = {
                'node1': {'errors': "mount.nfs: /cluster is busy or already mounted",
                        'data':
                        {'retcode': 1, 'err': 'mount.nfs: /cluster is busy or already mounted', 'out': ''}}
                }
        self.assertRaises(NasCmdApiException, self.nas.mount_ipv4, args)

    @mock.patch('nas_plugin.nas_cmd_api.log')
    @mock.patch('nas_plugin.nas_cmd_api.run_rpc_command')
    def test_mount_ipv4_unsuccessful2(self, run_rpc_command, log):
        #_call_mco.return_value = {"retcode" : 0, "out": "Worked"}
        args = {'ipv4': '192.168.56.111', 'export_path' : '/cluster', 'mount_point' : '/cluster'}
        run_rpc_command.return_value = {
                'node1': {'errors': "",
                        'data':
                        {'retcode': 1, 'err': 'mount.nfs: /cluster is busy or already mounted', 'out': ''}}
                }
        self.assertRaises(NasCmdApiException, self.nas.mount_ipv4, args)

    @mock.patch('nas_plugin.nas_cmd_api.log')
    @mock.patch('nas_plugin.nas_cmd_api.run_rpc_command')
    def test_mount_ipv6_success(self, run_rpc_command, log):
        #_call_mco.return_value = {"retcode" : 0, "out": "Worked"}
        args = {'ipv6': '3ffe:1a05:510:1111:0:5efe:836b:8107',
                'export_path' : '/cluster', 'mount_point' : '/cluster'}
        run_rpc_command.return_value = {
                'node1': {'errors': '',
                        'data':
                            {'retcode': 0, 'err': '', 'out': ''}}
                }
        data_result = self.nas._call_mco("mount_ipv6", args)
        self.assertEquals(log.trace.info.call_args_list, [
            mock.call('Running MCO NAS command \"mco rpc nas mount_ipv6 '\
                    'export_path=/cluster mount_point=/cluster '
                    'ipv6=3ffe:1a05:510:1111:0:5efe:836b:8107 '\
                    '-I [\'node1\']\" '),
            ])

    @mock.patch('nas_plugin.nas_cmd_api.log')
    @mock.patch('nas_plugin.nas_cmd_api.run_rpc_command')
    def test_mount_ipv6_unsuccessful(self, run_rpc_command, log):
        #_call_mco.return_value = {"retcode" : 0, "out": "Worked"}
        args = {'ipv6': '3ffe:1a05:510:1111:0:5efe:836b:8107',
                'export_path' : '/cluster', 'mount_point' : '/cluster'}
        run_rpc_command.return_value = {
                'node1': {'errors': "mount.nfs: /cluster is busy or already mounted",
                        'data':
                        {'retcode': 1, 'err': 'mount.nfs: /cluster is busy or already mounted', 'out': ''}}
                }
        self.assertRaises(NasCmdApiException, self.nas.mount_ipv6, args)

    @mock.patch('nas_plugin.nas_cmd_api.log')
    @mock.patch('nas_plugin.nas_cmd_api.run_rpc_command')
    def test_mount_ipv6_unsuccessful2(self, run_rpc_command, log):
        #_call_mco.return_value = {"retcode" : 0, "out": "Worked"}
        args = {'ipv6': '3ffe:1a05:510:1111:0:5efe:836b:8107',
                'export_path' : '/cluster', 'mount_point' : '/cluster'}
        run_rpc_command.return_value = {
                'node1': {'errors': "",
                        'data':
                        {'retcode': 1, 'err': 'mount.nfs: /cluster is busy or already mounted', 'out': ''}}
                }
        self.assertRaises(NasCmdApiException, self.nas.mount_ipv6, args)


    @mock.patch('nas_plugin.nas_cmd_api.log')
    @mock.patch('nas_plugin.nas_cmd_api.run_rpc_command')
    def test_unmount_success(self, run_rpc_command, log):
        #_call_mco.return_value = {"retcode" : 0, "out": "Worked"}
        args = {'ipv6': '3ffe:1a05:510:1111:0:5efe:836b:8107',
                'export_path' : '/cluster', 'mount_point' : '/cluster'}
        run_rpc_command.return_value = {
                'node1': {'errors': '',
                        'data':
                            {'retcode': 0, 'err': '', 'out': ''}}
                }
        data_result = self.nas._call_mco("unmount", args)
        self.assertEquals(log.trace.info.call_args_list, [
            mock.call('Running MCO NAS command \"mco rpc nas unmount '\
                    'export_path=/cluster mount_point=/cluster '
                    'ipv6=3ffe:1a05:510:1111:0:5efe:836b:8107 '\
                    '-I [\'node1\']\" '),
            ])

    @mock.patch('nas_plugin.nas_cmd_api.log')
    @mock.patch('nas_plugin.nas_cmd_api.run_rpc_command')
    def test_unmount_unsuccessful(self, run_rpc_command, log):
        #_call_mco.return_value = {"retcode" : 0, "out": "Worked"}
        args = {'ipv6': '3ffe:1a05:510:1111:0:5efe:836b:8107',
                'export_path' : '/cluster', 'mount_point' : '/cluster'}
        run_rpc_command.return_value = {
                'node1': {'errors': "mount.nfs: /cluster device is busy",
                        'data':
                        {'retcode': 1, 'err': 'mount.nfs: /cluster device is busy', 'out': ''}}
                }
        self.assertRaises(NasCmdApiException, self.nas.unmount, args)

    @mock.patch('nas_plugin.nas_cmd_api.log')
    @mock.patch('nas_plugin.nas_cmd_api.run_rpc_command')
    def test_unmount_unsuccessful2(self, run_rpc_command, log):
        #_call_mco.return_value = {"retcode" : 0, "out": "Worked"}
        args = {'ipv6': '3ffe:1a05:510:1111:0:5efe:836b:8107',
                'export_path' : '/cluster', 'mount_point' : '/cluster'}
        run_rpc_command.return_value = {
                'node1': {'errors': "",
                        'data':
                        {'retcode': 1, 'err': 'mount.nfs: /cluster device is busy', 'out': ''}}
                }
        self.assertRaises(NasCmdApiException, self.nas.unmount, args)

    @mock.patch('nas_plugin.nas_cmd_api.log')
    @mock.patch('nas_plugin.nas_cmd_api.run_rpc_command')
    def test_call_mco_success(self, run_rpc_command, log):
        args = {'ipv6': '3ffe:1a05:510:1111:0:5efe:836b:8107',
                'export_path' : '/cluster', 'mount_point' : '/cluster'}
        action = 'mount_ipv4'
        run_rpc_command.return_value = {'node1': {'errors': '',
                'data': {'retcode': 0, 'err': '', 'out': ''}}}

        data_result = self.nas._call_mco(action, args)
        self.assertEqual(data_result, {'retcode': 0, 'err': '', 'out': ''})

    @mock.patch('nas_plugin.nas_cmd_api.log')
    @mock.patch('nas_plugin.nas_cmd_api.run_rpc_command')
    def test_call_mco_unsuccess(self, run_rpc_command, log):
        args = {'ipv6': '3ffe:1a05:510:1111:0:5efe:836b:8107',
                'export_path' : '/cluster', 'mount_point' : '/cluster'}
        action = 'mount_ipv4'
        run_rpc_command.return_value = {'node1': {'errors': 'ERROR',
                'data': {'retcode': 0, 'err': '', 'out': ''}}}

        #data_result = self.nas._call_mco(action, args)
        #self.assertEqual(data_result, {'retcode': 1, 'err': '', 'out': ''})
        self.assertRaises(NasCmdApiException, self.nas._call_mco, action, args)
        self.assertEquals(log.trace.error.call_args_list, [
            mock.call("Failure to execute command: \"mco rpc nas mount_ipv4 export_path=/cluster mount_point=/cluster ipv6=3ffe:1a05:510:1111:0:5efe:836b:8107 -I ['node1']\" Reason: MCO failure... ERROR"),
            ])

    @mock.patch('nas_plugin.nas_cmd_api.log')
    @mock.patch('nas_plugin.nas_cmd_api.run_rpc_command')
    def test_call_mco_unsuccess2(self, run_rpc_command, log):
        args = {'ipv6': '3ffe:1a05:510:1111:0:5efe:836b:8107',
                'export_path' : '/cluster', 'mount_point' : '/cluster'}
        action = 'mount_ipv4'
        run_rpc_command.return_value = {'node1': {'errors': 'ERROR',
            'data': {'retcode': 0, 'err': '', 'out': ''}},
            'node2':{'errors': 'ERROR', 'data': {'retcode': 0, 'err': '', 'out': ''}}}

        #data_result = self.nas._call_mco(action, args)
        #self.assertEqual(data_result, {'retcode': 1, 'err': '', 'out': ''})
        self.assertRaises(NasCmdApiException, self.nas._call_mco, action, args)
        self.assertEquals(log.trace.error.call_args_list, [
            mock.call("Failure to execute command: \"mco rpc nas mount_ipv4 export_path=/cluster mount_point=/cluster ipv6=3ffe:1a05:510:1111:0:5efe:836b:8107 -I ['node1']\" Reason: Expected 1 response, received 2"),
            ])

    def test_get_kwargs(self):
        mock_dict = {"ipv4": "192.168.56.111",
                     "ipv6": "3ffe:1a05:510:1111:0:5efe:836b:8107",
                     "export_path": "/cluster",
                     "mount_point": "/cluster",
                    }
        get_kwargs = self.nas.get_kwargs("192.168.56.111", "3ffe:1a05:510:1111:0:5efe:836b:8107",
                "/cluster", "/cluster")
        self.assertEquals(mock_dict, get_kwargs)

    def test_gen_err_str(self):
        action = "mount_ipv4"
        args = {'export_path' : '/cluster', 'mount_point' : '/cluster'}
        expected_return_command = 'Failure to execute command: \"mco rpc nas '\
                'mount_ipv4 mount_point=/cluster export_path=/cluster -I [\'node1\']" '
        command = self.nas._gen_err_str(action, args)
        self.assertEqual(command, expected_return_command)

    def test_get_mco_nas_command(self):
        action = "mount_ipv4"
        args = {'export_path' : '/cluster', 'mount_point' : '/cluster'}
        expected_return_command = '\"mco rpc nas mount_ipv4 mount_point='\
                '/cluster export_path=/cluster -I [\'node1\']\" '
        command = self.nas._get_mco_nas_command(action, args)
        self.assertEqual(command, expected_return_command)

