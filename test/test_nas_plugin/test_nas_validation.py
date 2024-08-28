#s#############################################################################
# COPYRIGHT Ericsson AB 2013
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

import unittest
import mock

from litp.core.constants import UPGRADE_SNAPSHOT_NAME
from nas_plugin.nas_plugin import NasPlugin

from utils import TestNasPluginBase


class TestNasPlugin(TestNasPluginBase):

    def setUp(self):
        """
        Construct a model, sufficient for test cases
        that you wish to implement in this suite.
        """
        # Instantiate your plugin and register with PluginManager
        super(TestNasPlugin, self).setUp()
        self.plugin = NasPlugin()
        self.plugin_manager.add_plugin('NasPlugin', 'nas_plugin.nas_plugin',
                                       '1.0.1-SNAPSHOT', self.plugin)

    def setup_sfs_virtual_server(self, managed=False, applied=True, pool_name=None):
        self.node1 = self.create_node()
        self.sfs_service1 = self.create_sfs_service(managed=managed)
        self.sfs_virt1 = self.create_virtual_server(self.sfs_service1, name="vsvr1")
        created_items = [self.node1, self.sfs_service1, self.sfs_virt1]
        if managed:
            self.pool1 = self.create_pool(self.sfs_service1, name=pool_name)
            self.pool2 = self.create_pool(self.sfs_service1, name=pool_name)
            created_items.extend([self.pool1, self.pool2])
        if applied:
            for item in created_items:
                item.set_applied()

    def setup_sfs_managed_model1(self):
        self.sfs_service1 = self.create_sfs_service(managed=True)
        self.sfs_virtual_server1 = self.create_virtual_server(self.sfs_service1)
        self.pool = self.create_pool(self.sfs_service1)
        self.node1 = self.create_node()
        nfs_mount = self.create_nfs_mount(export_path="/vx/abcde-fs1")
        self.create_inherited_mount(self.node1, nfs_mount)
        self.filesystem = self.create_filesystem(self.pool)

    def setup_nfs_service(self, ipv6=False, ipv4=False):
        params = {}
        if ipv6:
            params["ipv6address"] = "2001::100"
        if ipv4:
            params["ipv4address"] = "10.10.10.100"
        self.create_nfs_service(name="vsvr1", **params)

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

    def setup_non_sfs_unmanaged_model_no_ip(self):
        # network storage does not have an ip
        self.node1 = self.create_node()
        self.eth0 = self.create_network_interface(self.node1, network_name="storage")
        self.eth1 = self.create_network_interface(self.node1, network_name="fake")
        self.setup_nfs_service(ipv4=True, ipv6=True)
        nfs_mount = self.create_nfs_mount(export_path="/vx/abcde-fs1")
        self.create_inherited_mount(self.node1, nfs_mount)

    def setup_invalid_ipv4_non_sfs_unmanaged_model(self):

        self.node1 = self.create_node()
        self.eth0 = self.create_network_interface(self.node1, network_name="storage", ipaddress="10.10.10.101")
        self.eth1 = self.create_network_interface(self.node1, network_name="fake", ipaddress="192.168.100.1")
        self.setup_nfs_service(ipv6=True)
        nfs_mount = self.create_nfs_mount(export_path="/vx/abcde-fs1")
        self.create_inherited_mount(self.node1, nfs_mount)

    def setup_invalid_ipv6_non_sfs_unmanaged_model(self):

        self.node1 = self.create_node()
        self.eth0 = self.create_network_interface(self.node1, network_name="storage", ipv6address="2001:cdba::3257:9652")
        self.eth1 = self.create_network_interface(self.node1, network_name="fake", ipv6address="2002::1")
        self.setup_nfs_service(ipv4=True)
        nfs_mount = self.create_nfs_mount(export_path="/vx/abcde-fs1")
        self.create_inherited_mount(self.node1, nfs_mount)

    def setup_storage_profile_model(self, mount_point1, mount_point2):
        # Setup two node model containing two storage-profiles
        # And two nfs-filesystems per node
        sfs_service = self.create_sfs_service()
        sfs_virt = self.create_virtual_server(sfs_service)

        nfs_mount = self.create_nfs_mount(export_path="/vx/abcde-fs1",
                                               provider=sfs_virt.name,
                                               mount_point=mount_point1)
        nfs_mount2 = self.create_nfs_mount(export_path="/vx/abcde-fs1",
                                                provider=sfs_virt.name,
                                                mount_point=mount_point2)
        nodes = [self.create_node(), self.create_node()]
        # Storage profile for node1 and node2
        for node in nodes:
            sp = self.create_storage_profile()
            vg = self.create_volume_group(sp, volume_group_name="vg_root")
            self.create_filesystem_item(vg, type="ext4",
                                                   mount_point="/var/test1",
                                                   size="16G")
            self.create_filesystem_item(vg, type="ext4",
                                                   mount_point="/var/test2",
                                                   size="16G")

            # Link storage profile to node1 and node2
            self.create_inherited(sp.get_vpath(),
                                  "%s/storage_profile" % node.get_vpath())

            self.create_inherited_mount(node, nfs_mount)
            self.create_inherited_mount(node, nfs_mount2)

    def setup_networking_model2(self, network_name):
        self.node1 = self.create_node()
        self.eth0 = self.create_network_interface(self.node1, network_name="mgmt",
                                                  ipaddress="10.10.10.101",
                                                  ipv6address="fe80::baca:3aff:fe96:8da4/64")

        self.eth1 = self.create_network_interface(self.node1, network_name="fake", ipaddress="192.168.100.1")
        sfs_service1 = self.create_sfs_service(managed=True, management_ipv4="10.10.10.10")

        self.sfs_virtual_server1 = self.create_virtual_server(sfs_service1, name="vsvr1",
                                                              ipv4address="10.10.10.100")

        sfs_pool = self.create_pool(sfs_service1)
        self.sfs_filesystem = self.create_filesystem(sfs_pool, size="20M")

        sfs_export = self.create_export(self.sfs_filesystem, clients="10.10.10.103,10.10.10.102",
                                        options="rw,no_root_squash")

        nfs_mount = self.create_nfs_mount(export_path=self.sfs_filesystem.path,
                                          provider=self.sfs_virtual_server1.name,
                                          mount_options="soft",
                                          network_name=network_name)
        self.create_inherited_mount(self.node1, nfs_mount)

    def setup_networking_model(self, network_name,  false_clientaddr=False):
        self.setup_networking_model2(network_name)

        sfs_export3 = self.create_export(self.sfs_filesystem,
                                         clients="10.10.10.101,10.10.10.111,10.10.10.113,10.10.10.112",
                                         options="rw,no_root_squash")

        nfs_mount = self.create_nfs_mount(export_path=self.sfs_filesystem.path,
                                          provider=self.sfs_virtual_server1.name,
                                          mount_options="soft,clientaddr=10.10.10.109"
                                          if false_clientaddr else "soft,clientaddr=10.10.10.101",
                                          network_name=network_name)
        self.create_inherited_mount(self.node1, nfs_mount)

    def query(self, item_type=None, **kwargs):
        return self.api.query(item_type, **kwargs)

    def test_create_mount_with_invalid_provider(self):
        self.node1 = self.create_node()
        self.eth0 = self.create_network_interface(self.node1, network_name="storage",
                                                  ipaddress="10.10.10.101",
                                                  ipv6address="fe80::baca:3aff:fe96:8da4/64")

        nfs_mount = self.create_nfs_mount(provider="invalid_provider", export_path="/vx/dummy-1",
                                          network_name=self.eth0.network_name,)
        self.create_inherited_mount(self.node1, nfs_mount)
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 2)
        self.assertEquals(errors[0].error_message,
           'Value "invalid_provider" for property "provider" does not'
           ' reference any defined sfs-virtual-server or nfs-service items.')
        self.assertEquals(errors[1].error_message,
           'Value "invalid_provider" for property "provider" does not'
           ' reference any defined sfs-virtual-server or nfs-service items.')

    def test_update_mount_with_valid_provider_nfs_service(self):
        #Update provider from nfs-service to nfs-service
        self.node1 = self.create_node()
        self.eth0 = self.create_network_interface(self.node1, network_name="storage",
                                                  ipaddress="10.10.10.101",
                                                  ipv6address="fe80::baca:3aff:fe96:8da4/64")
        nfs1 = self.create_nfs_service(ipv4address="10.10.10.15", name="foo")
        nfs2 = self.create_nfs_service(ipv4address="10.10.10.16", name ="bar")
        nfs1.set_applied()
        nfs2.set_applied()
        nfs_mount = self.create_nfs_mount(provider="foo", export_path="/vx/dummy-1",
                                          network_name=self.eth0.network_name,)
        mount_node = self.create_inherited_mount(self.node1, nfs_mount)
        nfs_mount.set_applied()
        mount_node.set_applied()
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        nfs_mount.set_property('provider', "bar")
        nfs_mount.set_updated()
        sfses = self.api.query('sfs-service')
        nfses = self.api.query('nfs-service')
        mounts = self.api.query('nfs-mount')
        errors = self.plugin._validate_nfs_mount_providers_updated(mounts, sfses, nfses,
                self.api)
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 1)

    def test_update_mount_with_invalid_provider(self):
        self.node1 = self.create_node()
        self.eth0 = self.create_network_interface(self.node1, network_name="storage",
                                                  ipaddress="10.10.10.101",
                                                  ipv6address="fe80::baca:3aff:fe96:8da4/64")
        nfs1 = self.create_nfs_service(ipv4address="10.10.10.15", name="foo")
        nfs2 = self.create_nfs_service(ipv4address="10.10.10.16", name ="bar")
        nfs1.set_applied()
        nfs2.set_applied()
        nfs_mount = self.create_nfs_mount(provider="foo", export_path="/vx/dummy-1",
                                          network_name=self.eth0.network_name,)
        mount_node = self.create_inherited_mount(self.node1, nfs_mount)
        nfs_mount.set_applied()
        mount_node.set_applied()
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        nfs_mount.set_property('provider', "bas")
        nfs_mount.set_updated()
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 2) # we get one on the source and inherited item

    def test_update_mount_with_valid_provider_different_service_types_1(self):
        #Update provider from nfs-service to sfs-service
        self.node1 = self.create_node()
        self.eth0 = self.create_network_interface(self.node1, network_name="storage",
                                                  ipaddress="10.10.10.101",
                                                  ipv6address="fe80::baca:3aff:fe96:8da4/64")
        nfs1 = self.create_nfs_service(ipv4address="10.10.10.15", name="foo")
        nfs2 = self.create_nfs_service(ipv4address="10.10.10.16", name ="bar")
        sfs_service1 = self.create_sfs_service(managed=True, management_ipv4="10.10.10.10")
        vip = self.sfs_virtual_server1 = self.create_virtual_server(sfs_service1, name="vsvr1",
                                                              ipv4address="10.10.10.100")
        sfs_service1.set_applied()
        vip.set_applied()
        nfs1.set_applied()
        nfs2.set_applied()
        nfs_mount = self.create_nfs_mount(provider="foo", export_path="/vx/dummy-1",
                                          network_name=self.eth0.network_name,)
        mount_node = self.create_inherited_mount(self.node1, nfs_mount)
        nfs_mount.set_applied()
        mount_node.set_applied()
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        nfs_mount.set_property('provider', "vsvr1")
        nfs_mount.set_updated()
        sfses = self.api.query('sfs-service')
        nfses = self.api.query('nfs-service')
        mounts = self.api.query('nfs-mount')
        errors = self.plugin._validate_nfs_mount_providers_updated(mounts, sfses, nfses,
                self.api)
        self.assertErrorCount(errors, 1)
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 1)
        self.assertEquals(errors[0].error_message,
        'The "provider" property of an "nfs-mount" cannot be updated'
        ' from an "nfs-service" to an "sfs-virtual-server".')

    def test_update_mount_with_valid_provider_different_service_types_2(self):
        #Update provider from sfs-service to nfs-service
        self.node1 = self.create_node()
        self.eth0 = self.create_network_interface(self.node1, network_name="storage",
                                                  ipaddress="10.10.10.101",
                                                  ipv6address="fe80::baca:3aff:fe96:8da4/64")
        nfs1 = self.create_nfs_service(ipv4address="10.10.10.15", name="foo")
        sfs_service1 = self.create_sfs_service(managed=True, management_ipv4="10.10.10.10")
        vip = self.sfs_virtual_server1 = self.create_virtual_server(sfs_service1, name="vsvr1",
                                                              ipv4address="10.10.10.100")
        sfs_service1.set_applied()
        vip.set_applied()
        nfs1.set_applied()
        nfs_mount = self.create_nfs_mount(provider="vsvr1", export_path="/vx/dummy-1",
                                          network_name=self.eth0.network_name,)
        mount_node = self.create_inherited_mount(self.node1, nfs_mount)
        nfs_mount.set_applied()
        mount_node.set_applied()
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
        nfs_mount.set_property('provider', "foo")
        nfs_mount.set_updated()
        sfses = self.api.query('sfs-service')
        nfses = self.api.query('nfs-service')
        mounts = self.api.query('nfs-mount')
        errors = self.plugin._validate_nfs_mount_providers_updated(mounts, sfses, nfses,
                self.api)
        self.assertErrorCount(errors, 1)
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 1)
        self.assertEquals(errors[0].error_message,
        'The "provider" property of an "nfs-mount" cannot be updated'
        ' from an "sfs-virtual-server" to an "nfs-service".')


    def test_update_mount_with_valid_provider_different_service_types_3(self):
        # Update provider from sfs-service to nfs-service
        # on node item not source in infrastructure
        # Story bug LITPCDS-12308
        self.node1 = self.create_node()
        self.eth0 = self.create_network_interface(self.node1, network_name="storage",
                                                  ipaddress="10.10.10.101",
                                                  ipv6address="fe80::baca:3aff:fe96:8da4/64")
        nfs1 = self.create_nfs_service(ipv4address="10.10.10.15", name="foo")
        sfs_service1 = self.create_sfs_service(managed=True, management_ipv4="10.10.10.10")
        vip = self.sfs_virtual_server1 = self.create_virtual_server(sfs_service1, name="vsvr1",
                                                              ipv4address="10.10.10.100")
        sfs_service1.set_applied()
        vip.set_applied()
        nfs1.set_applied()
        nfs_mount = self.create_nfs_mount(provider="vsvr1", export_path="/vx/dummy-1",
                                          network_name=self.eth0.network_name,)
        mount_node = self.create_inherited_mount(self.node1, nfs_mount)
        self.node1.set_applied()
        nfs_mount.set_applied()
        mount_node.set_applied()
        mount_node.set_property('provider', "foo")
        mount_node.set_updated()
        nodes = self.api.query('node')
        node_mounts = nodes[0].query('nfs-mount')
        sfses = self.api.query('sfs-service')
        nfses = self.api.query('nfs-service')
        mounts = self.api.query('nfs-mount')
        # pass infra and node mounts to validator
        mounts.extend(node_mounts)
        errors = self.plugin._validate_nfs_mount_providers_updated(mounts, sfses, nfses,
                self.api)
        self.assertErrorCount(errors, 1)
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 1)
        self.assertEquals(errors[0].error_message,
        'The "provider" property of an "nfs-mount" cannot be updated'
        ' from an "sfs-virtual-server" to an "nfs-service".')

    def test_update_mount_with_valid_provider_on_node_mount(self):
        # Update provider from sfs-virtual-server to sfs-virtual-server
        # on node item not source in infrastructure
        # Story bug LITPCDS-12308
        self.node1 = self.create_node()
        self.eth0 = self.create_network_interface(self.node1, network_name="storage",
                                                  ipaddress="10.10.10.101",
                                                  ipv6address="fe80::baca:3aff:fe96:8da4/64")
        sfs_service1 = self.create_sfs_service(managed=True, management_ipv4="10.10.10.10")
        vip1 = self.sfs_virtual_server1 = self.create_virtual_server(sfs_service1, name="vsvr1",
                                                              ipv4address="10.10.10.100")
        vip2 = self.sfs_virtual_server1 = self.create_virtual_server(sfs_service1, name="vsvr2",
                                                              ipv4address="10.10.10.101")

        sfs_service1.set_applied()
        vip1.set_applied()
        vip2.set_applied()
        nfs_mount = self.create_nfs_mount(provider="vsvr1", export_path="/vx/dummy-1",
                                          network_name=self.eth0.network_name,)
        mount_node = self.create_inherited_mount(self.node1, nfs_mount)
        self.node1.set_applied()
        nfs_mount.set_applied()
        mount_node.set_applied()
        mount_node.set_property('provider', "vsvr2")
        mount_node.set_updated()
        nodes = self.api.query('node')
        node_mounts = nodes[0].query('nfs-mount')
        sfses = self.api.query('sfs-service')
        nfses = self.api.query('nfs-service')
        mounts = self.api.query('nfs-mount')
        # pass infra and node mounts to validator
        mounts.extend(node_mounts)
        errors = self.plugin._validate_nfs_mount_providers_updated(mounts, sfses, nfses,
                self.api)
        self.assertErrorCount(errors, 0)
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)

    def test_export_update_remove_with_mount_fail(self):
        self.setup_sfs_virtual_server(managed=True)
        self.pool2.set_for_removal()
        self.eth0 = self.create_network_interface(self.node1, network_name="storage",
                                                  ipaddress="10.10.10.12")
        fs1 = self.create_filesystem(self.pool1, size="20M")
        fs2 = self.create_filesystem(self.pool2, size="20M")
        export = self.create_export(fs1, clients="10.10.10.11,10.10.10.12")
        self.update_item(export, ipv4allowed_clients="10.10.10.11")
        nfs_mount = self.create_nfs_mount(export_path=fs1.path)
        self.create_inherited_mount(self.node1, nfs_mount)
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 1)
        self.assertIn('The IP address for the network "storage" must be included in the property "ipv4allowed_clients"' \
             ' of an sfs-export which is defined under an sfs-filesystem which has a property "path"' \
             ' defined as "/vx/path-1"', str(errors))

    def test_validate_model(self):
        self.setup_sfs_virtual_server(managed=False)
        self.eth0 = self.create_network_interface(self.node1, network_name="storage", ipaddress="10.10.10.101")
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)
         ## self.assertIn('ValidationError - An sfs-service with only property
         ## "name" defined should have no related sfs-pool items defined.', str(errors))

    def test_duplicate_sfs_service_ipv4(self):
        self.create_sfs_service(managed=True, management_ipv4="10.10.10.10")
        self.create_sfs_service(managed=True, management_ipv4="10.10.10.10")
        self.create_nfs_service(ipv4address="10.10.10.15")
        self.create_nfs_service(ipv4address="10.10.10.16")
        sfs_services = self.api.query("sfs-service")
        errors = self.plugin._validate_unique_sfs_mgmt_ipv4(sfs_services)
        self.assertErrorCount(errors, 1)

    def test_no_duplicate_sfs_service_ipv4(self):
        self.create_sfs_service(managed=True, management_ipv4="10.10.10.10")
        self.create_sfs_service(managed=True, management_ipv4="10.10.10.11")
        self.create_nfs_service(ipv4address="10.10.10.15")
        self.create_nfs_service(ipv4address="10.10.10.16")
        sfs_services = self.api.query("sfs-service")
        errors = self.plugin._validate_unique_sfs_mgmt_ipv4(sfs_services)
        self.assertErrorCount(errors, 0)

    def test_duplicate_nfs_service_ipv4(self):
        self.create_sfs_service(managed=True, management_ipv4="10.10.10.10")
        self.create_sfs_service(managed=True, management_ipv4="10.10.10.11")
        self.create_nfs_service(ipv4address="10.10.10.15")
        self.create_nfs_service(ipv4address="10.10.10.15")
        nfs_services = self.api.query("nfs-service")
        errors = self.plugin._validate_unique_nfs_ipv4address(nfs_services)
        self.assertErrorCount(errors, 1)

    def test_no_duplicate_nfs_service_ipv4(self):
        self.create_sfs_service(managed=True, management_ipv4="10.10.10.10")
        self.create_sfs_service(managed=True, management_ipv4="10.10.10.11")
        self.create_nfs_service(ipv4address="10.10.10.15")
        self.create_nfs_service(ipv4address="10.10.10.16")
        nfs_services = self.api.query("nfs-service")
        errors = self.plugin._validate_unique_nfs_ipv4address(nfs_services)
        self.assertErrorCount(errors, 0)

    def test_duplicate_nfs_service_ipv6(self):
        self.create_nfs_service(ipv6address="FE80:0000:0000:0000:0202:B3FF:FE1E:8329")
        self.create_nfs_service(ipv6address="FE80:0000:0000:0000:0202:B3FF:FE1E:8329")
        nfs_services = self.api.query("nfs-service")
        errors = self.plugin._validate_unique_nfs_ipv6address(nfs_services)
        self.assertErrorCount(errors, 1)

    def test_duplicate_sfs_virtserver_ipv4(self):
        sfs_service1 = self.create_sfs_service(managed=False)
        self.create_virtual_server(sfs_service1, ipv4address="10.10.10.10")
        sfs_service2 = self.create_sfs_service(managed=False)
        self.create_virtual_server(sfs_service2, ipv4address="10.10.10.10")
        sfs_services = self.api.query("sfs-service")
        errors = self.plugin._validate_virt_server_ipv4_is_unique(sfs_services)
        self.assertErrorCount(errors, 1)

    def test_duplicate_sfs_service_names(self):
        self.create_sfs_service(name="sfs")
        self.create_sfs_service(name="sfs")
        sfs_services = self.api.query("sfs-service")
        errors = self.plugin._validate_service_name_is_unique(sfs_services)
        self.assertErrorCount(errors, 1)

    def test_no_duplicate_sfs_service_names(self):
        self.create_sfs_service(name="sfs1")
        self.create_sfs_service(name="sfs2")
        sfs_services = self.api.query("sfs-service")
        errors = self.plugin._validate_service_name_is_unique(sfs_services)
        self.assertErrorCount(errors, 0)

    def test_managed_sfs_with_pool_success(self):
        self.setup_sfs_managed_model()
        sfs_services = self.api.query("sfs-service")
        errors = self.plugin._validate_sfs_properties(sfs_services)
        self.assertErrorCount(errors, 0)

    def test_managed_sfs_with_pool(self):
        self.setup_sfs_virtual_server(managed=False)
        self.create_pool(self.sfs_service1)
        sfs_services = self.api.query("sfs-service")
        errors = self.plugin._validate_sfs_properties(sfs_services)
        self.assertErrorCount(errors, 1)
        self.assertIn('ValidationError - An sfs-service with only property "name" defined should have no related sfs-pool items defined.', str(errors))

    def test_validate_unique_mount_point_in_model(self):
        self.setup_storage_profile_model(mount_point1='/tmp1',
                                         mount_point2='/tmp2')
        errors = []
        nodes = self.api.query('node')
        for node in nodes:
            errors += self.plugin._validate_mount_point_in_model(node)
        self.assertErrorCount(errors, 0)

    def test_validate_unique_mount_point_in_model2(self):
        first_network = "net1"

        second_network = "net2"

        self.setup_networking_model2(first_network)

        nfs_mount2 = self.create_nfs_mount(export_path=self.sfs_filesystem.path,
                                          provider=self.sfs_virtual_server1.name,
                                          mount_options="soft",
                                          network_name=second_network)
        self.create_inherited_mount(self.node1, nfs_mount2)

        errors = []

        nodes = self.api.query('node')
        for node in nodes:
            errors += self.plugin._validate_nfs_mount_network_names(node)
        self.assertErrorCount(errors, 1)

    def test_validate_two_duplicate_mount_point_in_model(self):
        self.setup_storage_profile_model(mount_point1='/var/test1',
                                         mount_point2='/tmp2')
        errors = []
        nodes = self.api.query('node')
        for node in nodes:
            errors += self.plugin._validate_mount_point_in_model(node)
        self.assertErrorCount(errors, 2)

    def test_validate_mount_for_removal_and_new_mount_same_mount_point(self):
        nodes = [self.create_node(), self.create_node()]
        nfs_mount = self.create_nfs_mount(export_path="/vx/abcde-fs1",
                                               provider="vsvr1",
                                               mount_point='/some-point')
        # Storage profile for node1 and node2
        for node in nodes:
            self.create_inherited_mount(node, nfs_mount)
        errors = []
        nodes = self.api.query('node')
        for node in nodes:
            errors += self.plugin._validate_mount_point_in_model(node)
        self.assertErrorCount(errors, 0)
        mounts = nodes[0].query('nfs-mount')
        mount1 = mounts[0]
        # apply the mounts
        mount1._model_item.set_applied()
        # mark for removal
        from litp.core.model_item import ModelItem
        mount1._set_state(ModelItem.ForRemoval)
        nfs_mount = self.create_nfs_mount(export_path="/vx/abcde-fs1",
                                               provider=mount1.provider,
                                               mount_point=mount1.mount_point)
        self.create_inherited_mount(nodes[0], nfs_mount)
        errors = []
        nodes = self.api.query('node')
        for node in nodes:
            errors += self.plugin._validate_mount_point_in_model(node)
        self.assertErrorCount(errors, 1)

    def test_no_duplicate_filesystems_in_model(self):
        sfs1 = self.create_sfs_service(managed=True, management_ipv4="10.10.10.16")
        self.create_virtual_server(sfs1, ipv4address="10.10.10.20")
        pool11 = self.create_pool(sfs1)
        fs11 = self.create_filesystem(pool11)
        fs12 = self.create_filesystem(pool11)
        fs13 = self.create_filesystem(pool11)
        pool12 = self.create_pool(sfs1)
        # second service
        sfs2 = self.create_sfs_service(managed=True, management_ipv4="10.10.10.17")
        pool21 = self.create_pool(sfs2)
        pool22 = self.create_pool(sfs2)
        self.create_virtual_server(sfs2, ipv4address="10.10.10.21")
        fs21 = self.create_filesystem(pool11)
        fs22 = self.create_filesystem(pool11)
        fs23 = self.create_filesystem(pool11)

        services = self.api.query("sfs-service")
        errors = self.plugin._validate_no_duplicate_filesystems_per_service(services)
        self.assertErrorCount(errors, 0)

    def test_duplicate_filesystems_in_model_in_same_service_same_pools(self):
        sfs1 = self.create_sfs_service(managed=True, management_ipv4="10.10.10.16")
        self.create_virtual_server(sfs1, ipv4address="10.10.10.20")
        pool1 = self.create_pool(sfs1)
        fs_p1 = self.create_filesystem(pool1)
        fs_p2 = self.create_filesystem(pool1)
        fs_p3 = self.create_filesystem(pool1, path=fs_p1.path) # duplicate

        sfs_services = self.api.query("sfs-service")
        errors = self.plugin._validate_no_duplicate_filesystems_per_service(sfs_services)
        self.assertErrorCount(errors, 1)
        self.assertIn('ValidationError - Value "%s" for property "path" is'
                      ' already defined on path: '
                      '"/infrastructure/storage/storage_providers/sfs_service1/pools/pool1/file_systems/fs1"' % fs_p1.path,
                      str(errors))

    def test_duplicate_filesystems_in_model_in_same_service_diff_pools(self):
        sfs1 = self.create_sfs_service(managed=True, management_ipv4="10.10.10.16")
        self.create_virtual_server(sfs1, ipv4address="10.10.10.20")
        pool1 = self.create_pool(sfs1)
        fs_p11 = self.create_filesystem(pool1)
        fs_p12 = self.create_filesystem(pool1)
        fs_p13 = self.create_filesystem(pool1)
        pool2 = self.create_pool(sfs1)
        fs_p21 = self.create_filesystem(pool2)
        fs_p22 = self.create_filesystem(pool2)
        fs_p23 = self.create_filesystem(pool2, path=fs_p11.path) # duplicate

        sfs_services = self.api.query("sfs-service")
        errors = self.plugin._validate_no_duplicate_filesystems_per_service(sfs_services)
        self.assertErrorCount(errors, 1)
        self.assertIn('ValidationError - Value "%s" for property "path" is'
                      ' already defined on path: '
                      '"/infrastructure/storage/storage_providers/sfs_service1/pools/pool2/file_systems/fs3"' % fs_p11.path,
                      str(errors))

    def test_no_duplicate_filesystems_in_model_in_diff_services(self):
        sfs1 = self.create_sfs_service(managed=True, management_ipv4="10.10.10.16")
        self.create_virtual_server(sfs1, ipv4address="10.10.10.20")
        pool1 = self.create_pool(sfs1)
        fs_p11 = self.create_filesystem(pool1)
        fs_p12 = self.create_filesystem(pool1)
        fs_p13 = self.create_filesystem(pool1)
        # second service
        sfs2 = self.create_sfs_service(managed=True, management_ipv4="10.10.10.17")
        pool21 = self.create_pool(sfs2)
        fs_p21 = self.create_filesystem(pool21)
        fs_p22 = self.create_filesystem(pool21)
        fs_p23 = self.create_filesystem(pool21, path=fs_p13.path) # not dup different service
        self.create_virtual_server(sfs2, ipv4address="10.10.10.21")

        sfs_services = self.api.query("sfs-service")
        errors = self.plugin._validate_no_duplicate_filesystems_per_service(sfs_services)
        self.assertErrorCount(errors, 0)

    def test_no_duplicate_pools_in_model(self):
        self.setup_sfs_managed_model()
        self.create_pool(self.sfs_service1)
        services = self.api.query("sfs-service")
        errors = self.plugin._validate_no_duplicate_pool_names_in_service(services)
        self.assertErrorCount(errors, 0)

    def test_duplicate_pools_in_model(self):
        # TODO will be reconsidered

        # pool1 = Mock(is_for_removal=lambda: False,
        #            item_type_id='sfs-pool',
        #            get_vpath=lambda: '/pool1',)
        # pool1.name = 'pool1'
        # pool2 = Mock(is_for_removal=lambda: False,
        #            item_type_id='sfs-pool',
        #            get_vpath=lambda: '/pool2',)
        # pool2.name = 'pool1'
        # service = Mock(is_for_removal=lambda: False,
        #               managed=True,
        #               item_type_id='sfs-service',
        #               get_vpath=lambda: '/service1',
        #               pools=[pool1, pool2])
        # services = [service]

        self.setup_sfs_managed_model()
        pool2 = self.create_pool(self.sfs_service1, name='pool1')
        services = self.api.query("sfs-service")

        errors = self.plugin._validate_no_duplicate_pool_names_in_service(services)
        self.assertErrorCount(errors, 1)
        self.assertIn('ValidationError - Value "pool1" for property "name" is already defined on path: "%s"' % pool2.get_vpath(), str(errors))
        self.update_item(pool2, name='pool2')

        # #--- Multiple sfs-service items
        # pool3 = Mock(is_for_removal=lambda: False,
        #            item_type_id='sfs-pool',
        #            get_vpath=lambda: '/pool3',)
        # pool3.name = 'pool3'
        #
        # serllvice2 = Mock(is_for_removal=lambda: False,
        #               managed=True,
        #               item_type_id='sfs-service',
        #               get_vpath=lambda: '/service2',
        #               pools=[pool3])
        #
        # service.pools=[pool1]
        # services = [service, service2]
        # errors = self.plugin._validate_no_duplicate_pool_names_in_service(services)
        # self.assertErrorCount(errors, 0)

        # --- Multiple sfs-service items
        sfs_service2 = self.create_sfs_service(managed=True)
        pool3 = self.create_pool(sfs_service2, name='pool1')
        services = self.api.query("sfs-service")

        errors = self.plugin._validate_no_duplicate_pool_names_in_service(services)
        self.assertErrorCount(errors, 0)

    def test_validate_model_with_duplicate_exports_duplicate_ips(self):
        self.setup_sfs_managed_model()
        self.create_export(self.sfs_filesystem, clients="10.10.10.10")
        errors = self.plugin._validate_no_duplicate_exports(self.api)
        self.assertErrorCount(errors, 1)
        self.assertIn('ValidationError - IP address "10.10.10.10" in value "10.10.10.10" for property "ipv4allowed_clients" is a duplicate of an IP address on path: "/infrastructure/storage/storage_providers/sfs_service1/pools/pool1/file_systems/fs1/exports/ex1"',
                str(errors))

    def test_validate_model_with_duplicate_exports_duplicate_subnets(self):
        self.setup_sfs_managed_model()
        self.create_export(self.sfs_filesystem, clients="10.10.20.0/24")
        self.create_export(self.sfs_filesystem, clients="10.10.20.0/24")
        errors = self.plugin._validate_no_duplicate_exports(self.api)
        self.assertErrorCount(errors, 1)
        self.assertIn('ValidationError - Subnet "10.10.20.0/24" in value "10.10.20.0/24" for property "ipv4allowed_clients" is a duplicate of a subnet on path: "/infrastructure/storage/storage_providers/sfs_service1/pools/pool1/file_systems/fs1/exports/ex3"',
                str(errors))

    def test_validate_model_with_duplicate_exports2(self):
        self.setup_sfs_managed_model()
        self.create_export(self.sfs_filesystem, clients="10.10.10.0/24")
        errors = self.plugin._validate_no_duplicate_exports(self.api)
        self.assertErrorCount(errors, 1)
        self.assertIn('ValidationError - IP address "10.10.10.10" in value "10.10.10.10" for property "ipv4allowed_clients" overlaps with subnet "10.10.10.0/24" on path: "/infrastructure/storage/storage_providers/sfs_service1/pools/pool1/file_systems/fs1/exports/ex2"',
                str(errors))

    def test_validate_model_with_duplicate_exports3(self):
        self.setup_sfs_managed_model()
        self.create_export(self.sfs_filesystem, clients="20.20.20.1")
        self.create_export(self.sfs_filesystem, clients="20.20.20.0/24")
        errors = self.plugin._validate_no_duplicate_exports(self.api)
        self.assertErrorCount(errors, 1)
        self.assertIn('ValidationError - IP address "20.20.20.1" in value "20.20.20.1" for property "ipv4allowed_clients" overlaps with subnet "20.20.20.0/24" on path: "/infrastructure/storage/storage_providers/sfs_service1/pools/pool1/file_systems/fs1/exports/ex3',
                str(errors))

    def test_validate_model_with_duplicate_exports4(self):
        self.setup_sfs_managed_model()
        self.create_export(self.sfs_filesystem, clients="20.20.20.0/24")
        self.create_export(self.sfs_filesystem, clients="20.20.20.1")
        self.create_export(self.sfs_filesystem, clients="20.20.20.1")
        self.create_export(self.sfs_filesystem, clients="20.20.20.0/25")
        self.create_export(self.sfs_filesystem, clients="20.20.20.2")
        fs2 = self.create_filesystem(self.pool1)
        self.create_export(fs2, clients="20.20.20.2")
        self.create_export(fs2, clients="20.20.10.0/24")
        errors = self.plugin._validate_no_duplicate_exports(self.api)
        self.assertErrorCount(errors, 8)

    def test_validate_model_with_duplicate_exports5(self):
        self.setup_sfs_managed_model()
        fs2 = self.create_filesystem(self.pool1)
        self.create_export(fs2, clients="10.10.10.0/24")
        self.create_export(fs2, clients="10.10.10.10")
        self.create_export(fs2, clients="20.20.20.20")
        self.create_export(fs2, clients="10.10.10.11")
        self.create_export(fs2, clients="20.20.20.0/24")
        self.create_export(fs2, clients="10.10.10.12")
        errors = self.plugin._validate_no_duplicate_exports(self.api)
        self.assertErrorCount(errors, 4)

    def test_validate_model_no_duplicate_exports1(self):
        self.setup_sfs_managed_model()
        self.create_export(self.sfs_filesystem, clients="10.10.10.11")
        errors = self.plugin._validate_no_duplicate_exports(self.api)
        self.assertErrorCount(errors, 0)

    def test_validate_model_no_duplicate_exports2(self):
        self.setup_sfs_managed_model()
        self.create_export(self.sfs_filesystem, clients="10.10.10.15,10.10.10.16,10.10.10.17")
        errors = self.plugin._validate_no_duplicate_exports(self.api)
        self.assertErrorCount(errors, 0)

    def test_validate_model_no_duplicate_exports3(self):
        self.setup_sfs_managed_model()
        fs = self.create_filesystem(self.pool1)
        self.create_export(fs)
        errors = self.plugin._validate_no_duplicate_exports(self.api)
        self.assertErrorCount(errors, 0)

    def test_validate_model_no_duplicate_exports_subnet_overlap(self):
        self.setup_sfs_managed_model()
        fs = self.create_filesystem(self.pool1)
        self.create_export(fs, clients="10.10.10.10")
        self.create_export(fs, clients="10.10.10.0/24")
        self.create_export(fs, clients="20.20.20.0/24")
        self.create_export(fs, clients="20.20.20.20")
        errors = self.plugin._validate_no_duplicate_exports(self.api)
        self.assertErrorCount(errors, 2)

    def test_validate_network_name_on_interface_on_node_in_the_model(self):
        self.setup_networking_model(network_name="mgmt")
        errors = []
        nodes = self.api.query("node")
        for node in nodes:
            errors += self.plugin._validate_mounts(self.api, node)
        self.assertErrorCount(errors, 0)

    def test_validate_clientaddr_is_valid_with_valid_clientaddr(self):
        self.setup_networking_model(network_name="mgmt")
        errors = []
        nodes = self.api.query("node")
        for node in nodes:
            errors += self.plugin._validate_mounts(self.api, node)
        self.assertErrorCount(errors, 0)

    def test_validate_clientaddr_is_valid_with_invalid_clientaddr(self):
        self.setup_networking_model(network_name="mgmt", false_clientaddr=True)
        errors = []
        nodes = self.api.query("node")
        for node in nodes:
            errors += self.plugin._validate_mounts(self.api, node)
        self.assertErrorCount(errors, 1)

    def test_validate_two_mounts_network_name_on_interface_on_node_not_in_the_model(self):
        self.setup_networking_model(network_name="fooBar")
        errors = []
        nodes = self.api.query("node")
        for node in nodes:
            errors += self.plugin._validate_mounts(self.api, node)
        self.assertErrorCount(errors, 2)

    def validate_mount_ip_in_one_allowed_clients(self, subnet=False):
        self.setup_networking_model2(network_name="mgmt")
        nodes = self.api.query("node")
        self.create_export(self.sfs_filesystem,
                                         clients="10.10.10.101" if not subnet else "10.10.10.0/24")
        errors = []
        for node in nodes:
            errors += self.plugin._validate_mounts(self.api, node)
        self.assertErrorCount(errors, 0)

    def test_validate_mount_ip_in_one_allowed_clients(self):
        self.validate_mount_ip_in_one_allowed_clients(subnet=False)

    def test_validate_mount_ip_in_one_allowed_clients_subnet(self):
        self.validate_mount_ip_in_one_allowed_clients(subnet=True)

    def test_validate_mount_with_unmanaged_fs_under_managed_sfs(self):
        node1 = self.create_node()
        eth0 = self.create_network_interface(node1, network_name="storage", ipaddress="10.10.10.10")
        sfs_service1 = self.create_sfs_service(managed=True, name="sfs")
        virtual_server1 = self.create_virtual_server(sfs_service1)
        pool1 = self.create_pool(sfs_service1)

        fs = self.create_filesystem(pool1, path="/vx/unmanaged-fs1", size="20M")
        self.create_export(fs, clients="10.10.10.111")
        nfs_mount = self.create_nfs_mount(export_path="/vx/abcde-fs1", provider=virtual_server1.name,
                                          network_name=eth0.network_name)
        self.create_inherited_mount(node1, nfs_mount)
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)

    def validate_mount_ip_not_in_any_allowed_clients_list(self, subnet=False):
        self.setup_networking_model2(network_name="mgmt")
        nodes = self.api.query("node")
        self.create_export(
            self.sfs_filesystem, clients="10.10.10.201" if not subnet else "10.10.10.0/28")
        errors = []
        for node in nodes:
            errors += self.plugin._validate_mounts(self.api, node)
        self.assertErrorCount(errors, 1)
        self.assertIn('The IP address for the network "mgmt" must be included '
                      'in the property "ipv4allowed_clients" of an sfs-export '
                      'which is defined under an sfs-filesystem which has a '
                      'property "path" defined as "%s"' % self.sfs_filesystem.path,
                      str(self.plugin._validate_mounts(self.api, node)))

    def test_validate_mount_ip_not_in_any_allowed_clients_list(self):
        self.validate_mount_ip_not_in_any_allowed_clients_list(subnet=False)

    def test_validate_mount_ip_not_in_any_allowed_clients_list_subnet(self):
        self.validate_mount_ip_not_in_any_allowed_clients_list(subnet=True)

    def test_valid_nfs_mount_provider(self):
        errors = []
        self.setup_sfs_virtual_server(managed=False)
        self.eth0 = self.create_network_interface(self.node1, network_name="storage", ipaddress="10.10.10.101")
        nodes = self.api.query("node")
        for node in nodes:
            errors += self.plugin._validate_mounts(self.api, node)
        self.assertErrorCount(errors, 0)

    def test_valid_nfs_mount_provider2(self):
        errors = []
        self.setup_sfs_managed_model()
        nodes = self.api.query("node")
        for node in nodes:
            errors += self.plugin._validate_mounts(self.api, node)
        self.assertErrorCount(errors, 0)

    def test_valid_nfs_mount_provider3(self):
        errors = []
        self.setup_non_sfs_unmanaged_model(ipv4=True)
        nfs_mount = self.create_nfs_mount(export_path="/vx/abcde-fs1")
        self.create_inherited_mount(self.node1, nfs_mount)
        nodes = self.api.query("node")
        for node in nodes:
            errors += self.plugin._validate_mounts(self.api, node)
        self.assertErrorCount(errors, 0)

    def test_invalid_nfs_mount_provider(self):
        errors = []
        self.setup_non_sfs_unmanaged_model(ipv4=True)
        sfs_service1 = self.create_sfs_service(managed=False)
        self.create_virtual_server(sfs_service1, name="vsvr1")
        sfs_pool = self.create_pool(sfs_service1)
        self.sfs_filesystem = self.create_filesystem(sfs_pool)
        self.create_export(self.sfs_filesystem, clients="10.10.10.10")

        nfs_mount = self.create_nfs_mount(export_path="/vx/abcde-fs1")
        self.create_inherited_mount(self.node1, nfs_mount)

        nfs_mount2 = self.create_nfs_mount(export_path=self.sfs_filesystem.path,
                                           provider="incorrect",
                                           network_name=self.eth0.network_name)
        self.create_inherited_mount(self.node1, nfs_mount2)

        nodes = self.api.query("node")
        for node in nodes:
            errors += self.plugin._validate_mounts(self.api, node)
        self.assertErrorCount(errors, 1)

    def test_invalid_nfs_mount_provider2(self):
        errors = []
        self.setup_non_sfs_unmanaged_model(ipv4=True)

        nfs_mount = self.create_nfs_mount(export_path="/vx/abcde-fs1")
        self.create_inherited_mount(self.node1, nfs_mount)

        nfs_mount2 = self.create_nfs_mount(export_path="/vx/abcde-fs2", provider="vsvr2",
                                           mount_point="/tmp2",
                                           mount_options="soft",
                                           network_name="storage")
        self.create_inherited_mount(self.node1, nfs_mount2)

        self.assertEqual("/tmp2", nfs_mount2.mount_point)
        nodes = self.api.query("node")
        for node in nodes:
            errors += self.plugin._validate_mounts(self.api, node)
        self.assertErrorCount(errors, 1)

    def setup_nfs_network(self):

        self.nfs_service1 = self.create_nfs_service(ipv4address="10.10.10.100")
        self.network1 = self.create_network(litp_management="true", name="storage")
        self.node1 = self.create_node()
        self.node1_f0 = self.create_network_interface(self.node1, network_name="storage", ipaddress="10.10.10.10")
        self.node2 = self.create_node()
        self.node2_f0 = self.create_network_interface(self.node2, network_name="storage", ipaddress="10.10.10.11")

    def test_nfs_mount_nested_mount_points(self):
        self.setup_nfs_network()
        nfs_mount1 = self.create_nfs_mount(export_path="/vx/dummy-1",
            mount_point="/tmp1", network_name=self.node1_f0.network_name, provider=self.nfs_service1.name)
        self.create_inherited_mount(self.node1, nfs_mount1)
        nfs_mount2 = self.create_nfs_mount(export_path="/vx/dummy-1",
            mount_point="/tmp1/nested", network_name=self.node1_f0.network_name, provider=self.nfs_service1.name)
        self.create_inherited_mount(self.node1, nfs_mount2)
        nfs_mount3 = self.create_nfs_mount(export_path="/vx/dummy-1",
            mount_point="/tmp", network_name=self.node1_f0.network_name, provider=self.nfs_service1.name)
        self.create_inherited_mount(self.node1, nfs_mount3)
        nfs_mount4 = self.create_nfs_mount(export_path="/vx/dummy-1",
            mount_point="/tmp1/nnn", network_name=self.node2_f0.network_name, provider=self.nfs_service1.name)
        self.create_inherited_mount(self.node2, nfs_mount4)
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 1)
        self.assertEquals(errors[0].error_message, 'Nested mount points '
            'are not allowed: "/tmp1/nested". The mount point "/tmp1" is defined '
            'on "/deployments/d1/clusters/c1/nodes/n1/file_systems/fs1".')

    def test_nfs_mount_identical_mount_points(self):
        self.setup_nfs_network()
        nfs_mount1 = self.create_nfs_mount(export_path="/vx/dummy-1",
            mount_point="/tmp1", network_name=self.node1_f0.network_name, provider=self.nfs_service1.name)
        self.create_inherited_mount(self.node1, nfs_mount1)
        nfs_mount2 = self.create_nfs_mount(export_path="/vx/dummy-1",
            mount_point="/tmp1", network_name=self.node1_f0.network_name, provider=self.nfs_service1.name)
        self.create_inherited_mount(self.node1, nfs_mount2)
        nfs_mount3 = self.create_nfs_mount(export_path="/vx/dummy-1",
            mount_point="/tmp1/nnn", network_name=self.node2_f0.network_name, provider=self.nfs_service1.name)
        self.create_inherited_mount(self.node2, nfs_mount3)
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 1)
        msg1 = 'Value "/tmp1" for property "mount_point" is already defined'
        ' on path "/deployments/d1/clusters/c1/nodes/n1/file_systems/fs1"'
        msg2 = 'Value "/tmp1" for property "mount_point" is already defined'
        ' on path "/deployments/d1/clusters/c1/nodes/n1/file_systems/fs2"'
        fs_errs = [msg1, msg2]
        self.assertTrue(any(err in errors[0].error_message for err in fs_errs))

    def test_duplicate_nfs_service_names(self):
        errors = []
        self.setup_non_sfs_unmanaged_model(ipv4=True)
        self.create_nfs_service(ipv4address="10.10.10.12", name="vsvr1")
        errors += self.plugin._validate_provider_names(self.api)
        self.assertErrorCount(errors, 1)

    def test_duplicate_nfs_service_names2(self):
        errors = []
        self.setup_non_sfs_unmanaged_model(ipv4=True)
        sfs_service = self.create_sfs_service(managed=True)
        self.create_virtual_server(sfs_service, name='vsvr1', ipv4address="20.20.20.20")
        errors += self.plugin._validate_provider_names(self.api)
        self.assertErrorCount(errors, 1)

    def _nfs_service_ip_test_setup(self, errors):
        nodes = self.api.query("node")
        for node in nodes:
            errors += self.plugin._validate_correct_interfaces_defined(
                self.api, node)

    def _success_nfs_service_ip_test(self):
        errors = []
        self._nfs_service_ip_test_setup(errors)
        self.assertErrorCount(errors, 0)

    def _fail_nfs_service_ip_test(self):
        errors = []
        self._nfs_service_ip_test_setup(errors)
        self.assertErrorCount(errors, 1)

    def test_valid_nfs_service_ip_version_ipv4(self):
        self.setup_non_sfs_unmanaged_model(ipv4=True)
        self._success_nfs_service_ip_test()

    def test_valid_nfs_service_ip_version_ipv6(self):
        self.setup_non_sfs_unmanaged_model(ipv6=True)
        self._success_nfs_service_ip_test()

    def test_valid_nfs_service_ip_version_dualstack(self):
        self.setup_non_sfs_unmanaged_model(ipv4=True, ipv6=True)
        self._success_nfs_service_ip_test()

    def test_valid_nfs_service_ip_version_noip(self):
        self.setup_non_sfs_unmanaged_model_no_ip()
        self._fail_nfs_service_ip_test()

    def test_invalid_nfs_service_ipv4(self):
        self.setup_invalid_ipv4_non_sfs_unmanaged_model()
        self._fail_nfs_service_ip_test()

    def test_invalid_nfs_service_ipv6(self):
        self.setup_invalid_ipv6_non_sfs_unmanaged_model()
        self._fail_nfs_service_ip_test()

    def setup_sfs_managed_model(self):
        self.node1= self.create_node()
        self.eth0 = self.create_network_interface(self.node1, network_name="storage", ipaddress="10.10.10.10")

        self.sfs_service1 = self.create_sfs_service(managed=True, name="sfs")
        self.create_virtual_server(self.sfs_service1)
        self.pool1 = self.create_pool(self.sfs_service1)
        self.sfs_filesystem = self.create_filesystem(self.pool1, path="/vx/abcde-fs1", size="20M")
        self.create_export(self.sfs_filesystem, clients="10.10.10.10")
        nfs_mount = self.create_nfs_mount(export_path=self.sfs_filesystem.path)
        self.create_inherited_mount(self.node1, nfs_mount)

    def test_is_managed_mount_success(self):
        self.setup_sfs_managed_model()
        fs2 = self.create_filesystem(self.pool1, path="/vx/abcde-fs2", size="20M")
        self.create_export(fs2)
        nfs_mount = self.create_nfs_mount(export_path=fs2.path)
        self.create_inherited_mount(self.node1, nfs_mount)
        self.assertTrue(self.plugin._is_managed_mount(nfs_mount, self.api))

    def test_is_managed_mount_fail(self):
        self.setup_sfs_virtual_server(managed=False)
        nfs_mount = self.create_nfs_mount(export_path="/vx/abcde-fs1")
        self.create_inherited_mount(self.node1, nfs_mount)
        self.assertFalse(self.plugin._is_managed_mount(nfs_mount, self.api))

    def test_find_ip_provider(self):
        self.setup_non_sfs_unmanaged_model(ipv4=True)
        nfs_mount = self.create_nfs_mount(export_path="/vx/abcde-fs1")
        self.create_inherited_mount(self.node1, nfs_mount)
        result = self.plugin._find_provider_ip(nfs_mount, self.api)
        self.assertEquals(result[0], "10.10.10.100")

    def _setup_sfs_service(self, create_nfs_mount=True):
        self.node1 = self.create_node()
        sfs_service = self.create_sfs_service(managed=False)
        virtual_server1 = self.create_virtual_server(sfs_service, name='vsvr1', ipv4address="10.10.10.10")
        pool1 = self.create_pool(sfs_service)
        file_system = self.create_filesystem(pool1, "/vx/abcde-fs1")
        if create_nfs_mount:
            nfs_mount = self.create_nfs_mount(export_path=file_system.path, provider=virtual_server1.name)
            self.create_inherited_mount(self.node1, nfs_mount)
        return sfs_service

    def _setup_nfs_service(self, create_nfs_mount=True):
        self.node1 = self.create_node()
        nfs_service = self.create_nfs_service(ipv4address="10.10.10.10")

        if create_nfs_mount:
            nfs_mount = self.create_nfs_mount(export_path="/vx/abcde-fs1", provider="nfs1")
            self.create_inherited_mount(self.node1, nfs_mount)
        return nfs_service

    def test_valid_no_sfs_service_removal(self):
        errors = []
        self._setup_sfs_service()
        errors += self.plugin._validate_service_dependencies(self.api)
        self.assertErrorCount(errors, 0)

    def test_valid_sfs_service_removal(self):
        errors = []
        sfs_service = self._setup_sfs_service(False)
        sfs_service.set_for_removal()
        errors += self.plugin._validate_service_dependencies(self.api)
        self.assertErrorCount(errors, 0)

    def test_invalid_sfs_service_removal(self):
        errors = []
        sfs_service = self._setup_sfs_service()
        sfs_service.set_for_removal()
        errors += self.plugin._validate_service_dependencies(self.api)
        self.assertErrorCount(errors, 1)

    def test_valid_no_nfs_service_removal(self):
        errors = []
        self._setup_nfs_service()
        errors += self.plugin._validate_service_dependencies(self.api)
        self.assertErrorCount(errors, 0)

    def test_valid_nfs_service_removal(self):
        errors = []
        nfs_service = self._setup_nfs_service(False)
        nfs_service.set_for_removal()
        errors += self.plugin._validate_service_dependencies(self.api)
        self.assertErrorCount(errors, 0)

    def test_invalid_nfs_service_removal(self):
        errors = []
        nfs_service = self._setup_nfs_service()
        nfs_service.set_for_removal()
        errors += self.plugin._validate_service_dependencies(self.api)
        self.assertErrorCount(errors, 1)

    def setup_networking_ipv4_interface(self):
        self.node1 = self.create_node()
        self.eth0 = self.create_network_interface(self.node1, network_name="mgmt", ipaddress="10.10.10.101")
        self.eth1 = self.create_network_interface(self.node1, network_name="fake", ipaddress="192.168.100.1")

        sfs_service = self.create_sfs_service()
        self.create_virtual_server(sfs_service)
        sfs_pool = self.create_pool(sfs_service)
        sfs_filesystem = self.create_filesystem(sfs_pool)
        self.create_export(sfs_filesystem, clients="10.10.10.11,10.10.10.12")
        nfs_mount = self.create_nfs_mount(export_path=sfs_filesystem.path, network_name=self.eth0.network_name)
        self.create_inherited_mount(self.node1, nfs_mount)

    def test_validate_ipv4_address_on_interface(self):
        errors =[]
        self.setup_networking_ipv4_interface()
        nodes = self.api.query("node")
        for node in nodes:
            errors += self.plugin._validate_sfs_mount_interface_has_ipv4_address(self.api, node)
        self.assertErrorCount(errors, 0)

    def setup_networking_no_interface(self):
        self.node1 = self.create_node()
        self.eth0 = self.create_network_interface(self.node1, network_name="mgmt")
        self.eth1 = self.create_network_interface(self.node1, network_name="fake", ipaddress="192.168.100.1")
        sfs_service = self.create_sfs_service()
        self.create_virtual_server(sfs_service)
        sfs_pool = self.create_pool(sfs_service)
        sfs_filesystem = self.create_filesystem(sfs_pool)
        self.create_export(sfs_filesystem, clients="10.10.10.11,10.10.10.12")
        nfs_mount = self.create_nfs_mount(export_path=sfs_filesystem.path, network_name=self.eth0.network_name)
        self.create_inherited_mount(self.node1, nfs_mount)

    def test_validate_no_address_on_interface(self):
        errors =[]
        self.setup_networking_no_interface()
        nodes = self.api.query("node")
        for node in nodes:
            errors += self.plugin._validate_sfs_mount_interface_has_ipv4_address(self.api, node)
        self.assertErrorCount(errors, 1)
        self.assertIn('ValidationError - The network "mgmt" does not have an IPv4 address defined so it cannot be used to mount network file systems.', str(errors))

    def setup_networking_no_ipv4_interface(self):
        self.node1 = self.create_node()
        self.eth0 = self.create_network_interface(self.node1, network_name="mgmt")
        self.eth1 = self.create_network_interface(self.node1, network_name="fake", ipaddress="192.168.100.1")

        sfs_service = self.create_sfs_service()
        self.create_virtual_server(sfs_service)
        sfs_pool = self.create_pool(sfs_service)
        sfs_filesystem = self.create_filesystem(sfs_pool)
        self.create_export(sfs_filesystem, clients="10.10.10.11,10.10.10.12")
        nfs_mount = self.create_nfs_mount(export_path=sfs_filesystem.path, network_name=self.eth0.network_name)
        self.create_inherited_mount(self.node1, nfs_mount)

    def test_validate_no_ip_address_on_interface(self):
        errors =[]
        self.setup_networking_no_ipv4_interface()
        nodes = self.api.query("node")
        for node in nodes:
            errors += self.plugin._validate_sfs_mount_interface_has_ipv4_address(self.api, node)
        self.assertErrorCount(errors, 1)
        self.assertIn('ValidationError - The network "mgmt" does not have an IPv4 address '
                      'defined so it cannot be used to mount network file systems.', str(errors))

    def setup_sfs_snapshot(self, create_cache=True, create_fs=True, filesystems_applied=True):
        self.setup_sfs_virtual_server(managed=True)
        if create_cache:
            self.cache = self.create_cache(self.pool1, self.sfs_service1, name="mycache1")
        if create_fs:
            self.fs1 = self.create_filesystem(
                                    self.pool1, path="/vx/enm1-stor", size="10M", snap_size='30',
                                    backup_policy="No", cache_name="mycache1")
            self.fs2 = self.create_filesystem(
                                    self.pool1, path="/vx/pm1", size="10M", snap_size='10',
                                    backup_policy="No", cache_name="mycache1")
            self.fs3 = self.create_filesystem(
                                    self.pool1, path="/vx/pmlinks1", size="10M", snap_size='0',
                                    backup_policy="No", cache_name="mycache1")
            self.fs10 = self.create_filesystem(
                                    self.pool2, path="/vx/test10", size="10M", snap_size='10',
                                    backup_policy="No", cache_name="mycache1")
            fs_list = [self.fs1, self.fs2, self.fs3]
            if filesystems_applied:
                for fs in fs_list:
                    fs.set_applied()

    def test_positive_validate_one_cache_object_per_sfs_service(self):
        errors = []
        self.setup_sfs_snapshot()
        sfs_services = self.api.query("sfs-service")
        errors += self.plugin._validate_sfs_filesystem_cachename(sfs_services)
        self.assertErrorCount(errors, 0)

    def test_negative_validate_unique_sfs_cache_name(self):
        errors = []
        self.setup_sfs_snapshot()
        self.create_cache(self.pool1, self.sfs_service1, name="mycache1")
        sfs_services = self.api.query("sfs-service")
        errors += self.plugin._validate_unique_sfs_cache_name(sfs_services)
        self.assertErrorCount(errors, 1)
        self.assertIn('ValidationError - Value "mycache1" for property "name" is already defined on sfs-cache item path: "/infrastructure/storage/storage_providers/sfs_service1/pools/pool1/cache_objects/cache1".', str(errors))

    def test_negative_validate_sfs_filesystem_cachename(self):
        errors = []
        self.setup_sfs_snapshot()
        sfs_services = self.api.query("sfs-service")
        self.fs4 = self.create_filesystem(
                                self.pool1, path="/vx/pmlinks1", size="10M", snap_size='20',
                                backup_policy="No", cache_name="mycache2")
        errors += self.plugin._validate_sfs_filesystem_cachename(sfs_services)
        self.assertErrorCount(errors, 1)
        self.assertIn('The "cache_name" property with value "mycache2" '
                      'does not reference '
                      'a defined sfs-cache item under any sfs-pool for '
                      'the sfs-service on path', str(errors))

    def test_negative_validate_sfs_filesystem_cachename_no_cache(self):
        errors = []
        self.setup_sfs_snapshot(create_cache=False)
        sfs_services = self.api.query("sfs-service")
        errors += self.plugin._validate_sfs_filesystem_cachename(sfs_services)
        self.assertErrorCount(errors, 4)

    def test_negative_validate_sfs_filesystem_cachename_no_fs(self):
        errors = []
        self.setup_sfs_snapshot(create_fs=False)
        sfs_services = self.api.query("sfs-service")
        errors += self.plugin._validate_sfs_filesystem_cachename(sfs_services)
        self.assertErrorCount(errors, 1)
        self.assertIn('ValidationError - The sfs-cache item requires a minimum '
                      'of 1 sfs-filesystem item with a property "cache_name" '
                      'value "mycache1".', str(errors))

    def test_validate_sfs_cache_dependencies(self):
        errors = []
        self.setup_sfs_snapshot()
        self.cache.set_for_removal()
        sfs_services = self.api.query("sfs-service")
        errors += self.plugin._validate_sfs_cache_dependencies(sfs_services)
        self.assertErrorCount(errors, 4)

    def test_validate_snapshot_name(self):
        self.setup_sfs_snapshot(create_fs=True)

        self.api.snapshot_action = mock.MagicMock(return_value='create')
        self.api.snapshot_name = mock.MagicMock(return_value=UPGRADE_SNAPSHOT_NAME)
        errors = self.plugin.validate_model_snapshot(self.api)
        # no errors since the name of the snapshot is set to "snapshot"
        self.assertErrorCount(errors, 0)

        self.api.snapshot_name = mock.MagicMock(return_value="snap1")
        errors = self.plugin.validate_model_snapshot(self.api)
        # correct snapshot name no errors
        self.assertErrorCount(errors, 0)

        self.api.snapshot_name = mock.MagicMock(return_value="snapsho1")
        errors = self.plugin.validate_model_snapshot(self.api)
        # incorrect name snapsho1 which is 8 characters long
        self.assertErrorCount(errors, 1)
        self.assertIn('Snapshot name tag cannot exceed 7 characters '\
                        'which is the maximum available length '
                        'for a NAS file system.', str(errors))

        self.api.snapshot_name = mock.MagicMock(return_value="snap_1")
        errors = self.plugin.validate_model_snapshot(self.api)
        # incorrect name snap_1
        self.assertErrorCount(errors, 1)
        self.assertIn('The snapshot "name" cannot include underscores.', str(errors))

    def test_validate_deployment_snapshot_model(self):
        self.setup_sfs_snapshot()

        self.api.snapshot_action = mock.MagicMock(return_value='create')
        self.api.snapshot_name = mock.MagicMock(return_value=UPGRADE_SNAPSHOT_NAME)
        errors = self.plugin.validate_model_snapshot(self.api)
        # no errors since the name of the snapshot is set to "snapshot"
        self.assertErrorCount(errors, 0)

    def test_validate_named_snapshot_model(self):
        self.setup_sfs_snapshot()
        self.api.snapshot_action = mock.MagicMock(return_value='create')
        self.api.snapshot_name = mock.MagicMock(return_value="snap1")
        errors = self.plugin.validate_model_snapshot(self.api)
        # correct snapshot name no errors
        self.assertErrorCount(errors, 0)

    def test_negative_validate_deployment_snapshot_model(self):
        self.setup_sfs_snapshot()

        self.api.snapshot_action = mock.MagicMock(return_value='create')
        self.api.snapshot_name = mock.MagicMock(return_value=UPGRADE_SNAPSHOT_NAME)
        self.fs4 = self.create_filesystem(
                                    self.pool1, path="/vx/pmlinks4", size="10M", snap_size='0',
                                    backup_policy="No", cache_name="foo")
        self.fs4.set_applied()
        errors = self.plugin.validate_model_snapshot(self.api)
        self.assertErrorCount(errors, 1)
        self.assertIn('The "cache_name" property with value "foo" '
                      'does not reference '
                      'a defined sfs-cache item under any sfs-pool for '
                      'the sfs-service on path', str(errors))

        # LITPCDS-13667
        # We should ignore FS's in state initial during snapshot plans
        self.fs4.set_initial()
        errors = self.plugin.validate_model_snapshot(self.api)
        self.assertErrorCount(errors, 0)
        self.fs4.set_applied()
        errors = self.plugin.validate_model_snapshot(self.api)
        self.assertErrorCount(errors, 1)
        self.fs4.set_for_removal()
        errors = self.plugin.validate_model_snapshot(self.api)
        self.assertErrorCount(errors, 1)
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)

        #LITPCDS-10556 bug
        self.cache.set_for_removal()
        errors = self.plugin.validate_model_snapshot(self.api)
        self.assertErrorCount(errors, 1)
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 8)
        self.cache.set_applied()

        self.fs4.set_updated()
        errors = self.plugin.validate_model_snapshot(self.api)
        self.assertErrorCount(errors, 1)

        #---
        self.cache.set_for_removal()
        self.fs1.set_for_removal()
        self.fs2.set_for_removal()
        self.fs3.set_for_removal()
        self.fs4.set_for_removal()
        errors = self.plugin.validate_model_snapshot(self.api)
        self.assertErrorCount(errors, 1)
        self.assertIn('The "cache_name" property with value "foo" does not reference a defined sfs-cache item under any sfs-pool for the sfs-service on path' \
                    ' "/infrastructure/storage/storage_providers/sfs_service1".', str(errors))
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 3)
        self.assertIn('The sfs-pool with a property "name" value of '
                      '"pool1" must contain a minimum of one '
                      'sfs-cache or sfs-filesystem.', str(errors))
        self.assertIn('sfs-cache with name "mycache1" is required by '
                      'the sfs-filesystem item on path '
                      '"/infrastructure/storage/storage_providers/sfs_service1/pools/pool2/file_systems/fs1" '
                      'to create a snapshot and cannot be removed', str(errors))
        self.assertIn('The "cache_name" property with value "mycache1" does not reference a defined sfs-cache item under any sfs-pool for the sfs-service on path '
                      '"/infrastructure/storage/storage_providers/sfs_service1".', str(errors))

    def test_negative_validate_named_snapshot_model(self):

        self.setup_sfs_snapshot()
        self.api.snapshot_action = mock.MagicMock(return_value='create')
        self.api.snapshot_name = mock.MagicMock(return_value="snap1")
        self.fs4 = self.create_filesystem(
                                    self.pool1, path="/vx/pmlinks4", size="10M", snap_size='0',
                                    backup_policy="No", cache_name="foo")
        self.fs4.set_updated()
        self.fs4._applied_properties['size'] = '10M'
        errors = self.plugin.validate_model_snapshot(self.api)
        self.assertErrorCount(errors, 1)
        self.assertIn('The "cache_name" property with value "foo" '
                      'does not reference '
                      'a defined sfs-cache item under any sfs-pool for '
                      'the sfs-service on path', str(errors))

    def test_fs_resizing(self):
        self.setup_sfs_virtual_server(managed=True)
        self.cache = self.create_cache(self.pool1, self.sfs_service1, name="foo")
        self.fs4 = self.create_filesystem(
                                    self.pool1, path="/vx/pmlinks4", size="10M", snap_size='0',
                                    backup_policy="No", cache_name="foo")
        self.fs2 = self.create_filesystem(self.pool2, size="20M")
        self.update_item(self.fs4, size="20M")
        self.assertErrorCount(self.plugin.validate_model(self.api), 0)
        self.fs4.set_applied()
        #---
        self.update_item(self.fs4, size="10M")
        self.assertErrorCount(self.plugin.validate_model(self.api), 1)
        self.fs4.set_applied()

    def test_fs_resizing_post_snapshot(self):

        self.setup_sfs_snapshot()
        self.create_item("snapshot-base", "/snapshots/" + 'snapshot', timestamp=None)
        self.update_item(self.fs1, size="30M")
        self.assertErrorCount(self.plugin.validate_model(self.api), 1)
        self.fs1.set_applied()

        #---
        self.update_item(self.fs1, size="5M")
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 2)
        self.assertIn('Decreasing the "size" property'
                       ' of an sfs-filesystem is not supported.', str(errors))
        self.assertIn('Changing the "size" property of any sfs-filesystem '
                      'while a snapshot exists is not supported', str(errors))

    def test_fs_resizing_during_snapshot(self):

        self.setup_sfs_snapshot()
        self.api.snapshot_action = mock.MagicMock(return_value='create')
        self.update_item(self.fs1, size="30M")
        self.update_item(self.fs2, size="30M")
        errors = self.plugin.validate_model_snapshot(self.api)
        self.assertIn('</infrastructure/storage/storage_providers/sfs_service1/pools/pool1/file_systems/fs1'
                      ' - ValidationError - A snapshot may not be created while an sfs-filesystem "size"'
                      ' property update is pending.>', str(errors))
        self.assertIn('</infrastructure/storage/storage_providers/sfs_service1/pools/pool1/file_systems/fs2'
                      ' - ValidationError - A snapshot may not be created while an sfs-filesystem "size"'
                      ' property update is pending.>', str(errors))
        self.assertErrorCount(errors, 2)

    def test_one_pool_and_multiple_caches_during_snapshot(self):
        # If all fs point to one cache and we have more than one we should not fail create snapshot
        self.setup_sfs_snapshot()
        self.api.snapshot_action = mock.MagicMock(return_value='create')
        self.create_cache(self.pool1, self.sfs_service1, name="mycache2")
        self.create_cache(self.pool1, self.sfs_service1, name="mycache3")
        errors = self.plugin.validate_model_snapshot(self.api)
        self.assertErrorCount(errors, 0)

    def test_negative_validate_all_fs_point_to_one_cache(self):
        # If more one or more fs points at a different cache fail the create snapshot
        self.setup_sfs_snapshot()
        self.api.snapshot_action = mock.MagicMock(return_value='create')
        self.api.snapshot_name = mock.MagicMock(return_value="snap1")
        self.cache2 = self.create_cache(self.pool1, self.sfs_service1, name="foo")
        self.cache3 = self.create_cache(self.pool1, self.sfs_service1, name="bar")
        self.fs4 = self.create_filesystem(
                                    self.pool1, path="/vx/pmlinks4", size="10M", snap_size='20',
                                    backup_policy="No", cache_name="foo")
        self.fs5 = self.create_filesystem(
                                    self.pool1, path="/vx/pmlinks5", size="10M", snap_size='20',
                                    backup_policy="No", cache_name="bar")

        error_msg = 'All file systems under every sfs-pool for the ' \
                    'sfs-service item on path "/infrastructure/storage/' \
                    'storage_providers/sfs_service1" must have the same ' \
                    '"cache_name" property value.'

        # simulating the normal validate model
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 3)
        self.assertIn(error_msg, str(errors))

        # simulating file systems not applied, for the validate_model_snapshot
        errors = self.plugin.validate_model_snapshot(self.api)
        self.assertErrorCount(errors, 0)

        # simulating applied file systems now, for the validate_model_snapshot
        self.fs4.set_applied()
        self.fs5.set_applied()
        errors = self.plugin.validate_model_snapshot(self.api)
        self.assertErrorCount(errors, 1)
        self.assertIn(error_msg, str(errors))

        # simulating updated file systems now, for the validate_model_snapshot
        self.fs4.set_updated()
        self.fs5.set_updated()
        errors = self.plugin.validate_model_snapshot(self.api)
        self.assertErrorCount(errors, 1)
        self.assertIn(error_msg, str(errors))

    def test_no_validation_on_cache_name_with_more_than_one_pool(self):
        self.setup_sfs_snapshot()
        self.api.snapshot_action = mock.MagicMock(return_value='create')
        self.api.snapshot_name = mock.MagicMock(return_value="snap1")
        self.pool2 = self.create_pool(self.sfs_service1, name=None)
        self.fs4 = self.create_filesystem(self.pool2, path="/vx/pmlinks4", size="10M")
        self.pool3 = self.create_pool(self.sfs_service1, name=None)
        self.fs5 = self.create_filesystem(self.pool3, path="/vx/pmlinks5", size="10M")
        self.pool4 = self.create_pool(self.sfs_service1, name=None)
        self.fs6 = self.create_filesystem(self.pool4, path="/vx/pmlinks6", size="10M")
        errors = self.plugin.validate_model_snapshot(self.api)
        self.assertErrorCount(errors, 0)
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)

    def test_validation_on_removed_service_while_snapshotting(self):
        self.setup_sfs_snapshot()
        self.api.snapshot_action = mock.MagicMock(return_value='create')
        self.api.snapshot_name = mock.MagicMock(return_value="snap1")
        self.update_item(self.fs1, cache_name="cache_NA")
        self.sfs_service1.set_for_removal()
        self.pool1.set_for_removal()
        self.fs1.set_for_removal()
        self.fs2.set_for_removal()
        self.fs3.set_for_removal()
        self.cache.set_for_removal()
        errors = self.plugin.validate_model_snapshot(self.api)
        self.assertErrorCount(errors, 1)
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)

    def test_validate_only_one_cache_per_sfs(self):
        """
        Note: In snapshot validation the presence alone
        of two caches does not raise an error.
        There is another validator to ensure all filesystems are pointing at one cache
        object. If this is not the case then an error will be raised by that validator.
        """
        self.setup_sfs_snapshot()
        self.api.snapshot_action = mock.MagicMock(return_value='create')
        self.create_cache(self.pool2, self.sfs_service1, name="mycache_1")
        errors = self.plugin.validate_model_snapshot(self.api)
        self.assertErrorCount(errors, 0)

        # --- Model validation
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 1)
        self.assertIn('Only one sfs-cache is allowed per sfs-service. '
                      'An sfs-cache with a "name" property value of '
                      '"mycache1" is already defined for the sfs-service on '
                      'path "/infrastructure/storage/storage_providers/sfs_service1/pools/pool1/cache_objects/cache1"',
                      str(errors))

    def test_each_pool_must_have_cache_or_filesystem(self):
        self.setup_sfs_snapshot(create_fs=False)
        self.fs1 = self.create_filesystem(
                     self.pool1, path="/vx/enm1-stor", size="10M", snap_size='30',
                     backup_policy="No", cache_name="mycache1")

        # --- Pool 2 is empty and so an error is raised
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 1)
        self.assertIn('The sfs-pool with a property "name" value of '
                      '"pool2" must contain a minimum of one '
                      'sfs-filesystem.', str(errors))

        # --- Pool 2 has a file system and so no error is raised
        self.fs2 = self.create_filesystem(self.pool2, path="/vx/test", size="10M")
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)

        # --- If last FS or Cache is for removal in a pool, an error should be raised
        self.fs2.set_for_removal()
        self.cache.set_for_removal()
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 3)
        self.assertIn('The sfs-pool with a property "name" value of '
                      '"pool2" must contain a minimum of one '
                      'sfs-cache or sfs-filesystem.', str(errors))
        self.assertIn('sfs-cache with name "mycache1" is required by the '
                      'sfs-filesystem item on path '
                      '"/infrastructure/storage/storage_providers/sfs_service1/pools/pool1/file_systems/fs1"',
                      str(errors))
        self.assertIn('The "cache_name" property with value "mycache1" does not reference '
                      'a defined sfs-cache item under any sfs-pool for the sfs-service on path '
                      '"/infrastructure/storage/storage_providers/sfs_service1"', str(errors))

    def test_multiple_pools_and_one_cache(self):
        self.setup_sfs_snapshot()
        self.api.snapshot_action = mock.MagicMock(return_value='create')
        self.pool2 = self.create_pool(self.sfs_service1, name=None)
        self.fs4 = self.create_filesystem(
                   self.pool2, path="/vx/pmlinks4", size="10M", snap_size='20',
                   backup_policy="No", cache_name="mycache1")
        # ---
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 0)

        # ---
        errors = self.plugin.validate_model_snapshot(self.api)
        self.assertErrorCount(errors, 0)

    def test_one_pool_empty_pool(self):
        self.setup_sfs_virtual_server(managed=True)
        self.pool2.set_for_removal()
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 1)
        self.assertIn('The sfs-pool with a property "name" value of '
                      '"pool1" must contain a minimum of one '
                      'sfs-filesystem.', str(errors))

    def test_two_pools_empty_pools(self):
        self.setup_sfs_virtual_server(managed=True)
        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 2)
        self.assertIn('The sfs-pool with a property "name" value of '
                      '"pool1" must contain a minimum of one sfs-cache or '
                      'sfs-filesystem.', str(errors))

    def test_two_pools_one_filesystem(self):
        self.setup_sfs_virtual_server(managed=True)
        self.fs4 = self.create_filesystem(
                   self.pool1, path="/vx/pmlinks4", size="10M")

        errors = self.plugin.validate_model(self.api)
        self.assertErrorCount(errors, 1)
        self.assertIn('The sfs-pool with a property "name" value of '
                      '"pool2" must contain a minimum of one sfs-cache or '
                      'sfs-filesystem.', str(errors))

    def test_multiple_pools_and_one_cache_no_filesystems(self):
        self.setup_sfs_snapshot()
        self.fs1.set_for_removal()
        self.fs2.set_for_removal()
        self.fs3.set_for_removal()
        self.fs10.set_for_removal()
        self.api.snapshot_action = mock.MagicMock(return_value='create')

        # ---
        errors = self.plugin.validate_model(self.api)

        self.assertErrorCount(errors, 2)
        self.assertIn('The sfs-pool with a property "name" value of '
                      '"pool2" must contain a minimum of one '
                      'sfs-filesystem.', str(errors))



        # ---
        errors = self.plugin.validate_model_snapshot(self.api)
        self.assertErrorCount(errors, 0)



if __name__ == '__main__':
    unittest.main()
