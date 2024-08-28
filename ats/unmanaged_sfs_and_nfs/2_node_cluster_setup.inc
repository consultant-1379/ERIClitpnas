litp create -t os-profile -p /software/profiles/rhel -o name='sample-profile' path='/profiles/node-iso/'

litp create -t system -p /infrastructure/systems/system1 -o system_name='SYS1'
litp create -t system -p /infrastructure/systems/system2 -o system_name='SYS2'

litp create -t network -p /infrastructure/networking/networks/ms_network -o name='nodes' subnet='10.10.10.0/24' litp_management=true


litp create -p /ms/network_interfaces/if0 -t eth -o network_name=nodes ipaddress="10.10.10.100" macaddress="80:C1:6E:7A:09:C3" device_name=eth0


litp create -t storage-profile-base -p /infrastructure/storage/storage_profiles/profile_1

litp create -t deployment -p /deployments/local
litp create -t cluster    -p /deployments/local/clusters/cluster1

litp create -t node  -p /deployments/local/clusters/cluster1/nodes/node1        -o hostname='node1'
litp inherit -p /deployments/local/clusters/cluster1/nodes/node1/system -s /infrastructure/systems/system1
litp inherit -p /deployments/local/clusters/cluster1/nodes/node1/os -s /software/profiles/rhel

litp create -t eth -p /deployments/local/clusters/cluster1/nodes/node1/network_interfaces/if0 -o network_name=nodes ipaddress=10.10.10.101 device_name=eth0 macaddress=80:C1:6E:7A:09:C0

litp inherit -p /deployments/local/clusters/cluster1/nodes/node1/storage_profile -s /infrastructure/storage/storage_profiles/profile_1

litp create -t node -p /deployments/local/clusters/cluster1/nodes/node2        -o hostname='node2'
litp inherit -p /deployments/local/clusters/cluster1/nodes/node2/system -s /infrastructure/systems/system2
litp inherit -p /deployments/local/clusters/cluster1/nodes/node2/os -s /software/profiles/rhel

litp create -t eth -p /deployments/local/clusters/cluster1/nodes/node2/network_interfaces/if0 -o network_name=nodes ipaddress=10.10.10.102 device_name=eth0 macaddress=80:C1:6E:7A:09:C1

litp inherit -p /deployments/local/clusters/cluster1/nodes/node2/storage_profile -s /infrastructure/storage/storage_profiles/profile_1
