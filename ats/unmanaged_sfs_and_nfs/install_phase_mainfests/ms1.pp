
class task_ms1__firewalls_3a_3aconfig____ms__fw__config(){
    firewalls::config { "_ms_fw_config":
        action => "create",
        drop_all => "true"
    }
}

class task_ms1__firewalls_3a_3arules____ms__fw__nfstcp(){
    firewalls::rules { "_ms_fw_nfstcp":
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

class task_ms1__firewalls_3a_3arules____ms__fw__nfsudp(){
    firewalls::rules { "_ms_fw_nfsudp":
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

class task_ms1__nas_3a_3aconfig___2fms_2ffile__systems_2ffs1(){
    nas::config { "/ms/file_systems/fs1":
        mount_options => "soft",
        mount_point => "/tmp1",
        mount_status => "mounted",
        path => "10.10.10.11:/vx/exports/xyz-fs1"
    }
}


node "ms1" {

    class {'litp::ms_node':}


    class {'task_ms1__firewalls_3a_3aconfig____ms__fw__config':
    }


    class {'task_ms1__firewalls_3a_3arules____ms__fw__nfstcp':
    }


    class {'task_ms1__firewalls_3a_3arules____ms__fw__nfsudp':
    }


    class {'task_ms1__nas_3a_3aconfig___2fms_2ffile__systems_2ffs1':
        require => [Class["task_ms1__firewalls_3a_3aconfig____ms__fw__config"]]
    }


}