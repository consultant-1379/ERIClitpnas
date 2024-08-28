class task_node1__nas_3a_3aconfig___2fdeployments_2flocal_2fclusters_2fcluster1_2fnodes_2fnode1_2ffile__systems_2fnm1(){
    nas::config { "/deployments/local/clusters/cluster1/nodes/node1/file_systems/nm1":
        mount_options => "soft,intr,timeo=30,noexec,nosuid",
        mount_point => "/cluster_ro",
        mount_status => "remount",
        path => "12.12.12.12:/nas_shared/ro_unmanaged"
    }
}

class task_node1__network_3a_3aconfig__eth0(){
    network::config { "eth0":
        bootproto => "static",
        broadcast => "10.10.10.255",
        ensure => "present",
        hwaddr => "80:C1:6E:7A:09:C0",
        ipaddr => "10.10.10.110",
        is_mgmt_if => "true",
        netmask => "255.255.255.0",
        nozeroconf => "yes",
        onboot => "yes",
        userctl => "no"
    }
}


node "node1" {

    class {'litp::mn_node':
        ms_hostname => "ms1",
        cluster_type => "NON-CMW"
        }


    class {'task_node1__nas_3a_3aconfig___2fdeployments_2flocal_2fclusters_2fcluster1_2fnodes_2fnode1_2ffile__systems_2fnm1':
        require => [Class["task_node1__network_3a_3aconfig__eth0"]]
    }


    class {'task_node1__network_3a_3aconfig__eth0':
    }


}