
class task_node2__firewalls_3a_3aconfig____node2__fw__config(){
    firewalls::config { "_node2_fw_config":
        action => "create",
        drop_all => "true"
    }
}

class task_node2__firewalls_3a_3arules____node2__fw__nfstcp(){
    firewalls::rules { "_node2_fw_nfstcp":
rule1 => {
        name => "001 nfstcp ipv4",
        chain => "INPUT",
        proto => "tcp",
        title => "001_nfstcp_ipv4",
dport => [
        "111",
        "2049",
        "4001"
        ]
,
state => [
        "NEW"
        ]
,
        ensure => "present",
        provider => "iptables",
        action => "accept"
        },
rule2 => {
        name => "1001 nfstcp ipv4",
        chain => "OUTPUT",
        proto => "tcp",
        title => "1001_nfstcp_ipv4",
dport => [
        "111",
        "2049",
        "4001"
        ]
,
state => [
        "NEW"
        ]
,
        ensure => "present",
        provider => "iptables",
        action => "accept"
        },
rule3 => {
        name => "001 nfstcp ipv6",
        chain => "INPUT",
        proto => "tcp",
        title => "001_nfstcp_ipv6",
dport => [
        "111",
        "2049",
        "4001"
        ]
,
state => [
        "NEW"
        ]
,
        ensure => "present",
        provider => "ip6tables",
        action => "accept"
        },
rule4 => {
        name => "1001 nfstcp ipv6",
        chain => "OUTPUT",
        proto => "tcp",
        title => "1001_nfstcp_ipv6",
dport => [
        "111",
        "2049",
        "4001"
        ]
,
state => [
        "NEW"
        ]
,
        ensure => "present",
        provider => "ip6tables",
        action => "accept"
        }
    }
}

class task_node2__firewalls_3a_3arules____node2__fw__nfsudp(){
    firewalls::rules { "_node2_fw_nfsudp":
rule1 => {
        name => "011 nfsudp ipv4",
        chain => "INPUT",
        proto => "udp",
        title => "011_nfsudp_ipv4",
dport => [
        "111",
        "2049",
        "4001"
        ]
,
state => [
        "NEW"
        ]
,
        ensure => "present",
        provider => "iptables",
        action => "accept"
        },
rule2 => {
        name => "1011 nfsudp ipv4",
        chain => "OUTPUT",
        proto => "udp",
        title => "1011_nfsudp_ipv4",
dport => [
        "111",
        "2049",
        "4001"
        ]
,
state => [
        "NEW"
        ]
,
        ensure => "present",
        provider => "iptables",
        action => "accept"
        },
rule3 => {
        name => "011 nfsudp ipv6",
        chain => "INPUT",
        proto => "udp",
        title => "011_nfsudp_ipv6",
dport => [
        "111",
        "2049",
        "4001"
        ]
,
state => [
        "NEW"
        ]
,
        ensure => "present",
        provider => "ip6tables",
        action => "accept"
        },
rule4 => {
        name => "1011 nfsudp ipv6",
        chain => "OUTPUT",
        proto => "udp",
        title => "1011_nfsudp_ipv6",
dport => [
        "111",
        "2049",
        "4001"
        ]
,
state => [
        "NEW"
        ]
,
        ensure => "present",
        provider => "ip6tables",
        action => "accept"
        }
    }
}

class task_node2__nas_3a_3aconfig___2fdeployments_2flocal_2fclusters_2fcluster1_2fnodes_2fnode2_2ffile__systems_2ffs1(){
    nas::config { "/deployments/local/clusters/cluster1/nodes/node2/file_systems/fs1":
        mount_options => "soft",
        mount_point => "/tmp1",
        mount_status => "mounted",
        path => "10.10.10.11:/vx/exports/xyz-fs1"
    }
}


node "node2" {

    class {'litp::mn_node':
        ms_hostname => "ms1",
        cluster_type => "NON-CMW"
        }


    class {'task_node2__firewalls_3a_3aconfig____node2__fw__config':
    }


    class {'task_node2__firewalls_3a_3arules____node2__fw__nfstcp':
    }


    class {'task_node2__firewalls_3a_3arules____node2__fw__nfsudp':
    }


    class {'task_node2__nas_3a_3aconfig___2fdeployments_2flocal_2fclusters_2fcluster1_2fnodes_2fnode2_2ffile__systems_2ffs1':
        require => [Class["task_node2__firewalls_3a_3aconfig____node2__fw__config"]]
    }


}