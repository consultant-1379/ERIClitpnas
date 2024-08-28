litp create -t os-profile -p /software/profiles/rhel_6_4 -o name=sample-profile version=rhel6 path=/profiles/node-iso/ arch=x86_64 breed=redhat

litp create -t storage-profile-base -p /infrastructure/storage/storage_profiles/profile_1

litp create -t network -p /infrastructure/networking/networks/nodes -o subnet='192.168.0.0/24' litp_management='true' name='mgmt'

litp create -t deployment -p /deployments/d1
litp create -t cluster -p /deployments/d1/clusters/c1

litp create -t system -p /infrastructure/systems/s1 -o system_name=MN1
litp create -t system -p /infrastructure/systems/s2 -o system_name=MN2

litp create -t node -p /deployments/d1/clusters/c1/nodes/n1 -o hostname=node1
litp create -t node -p /deployments/d1/clusters/c1/nodes/n2 -o hostname=node2

litp inherit -p /deployments/d1/clusters/c1/nodes/n1/system -s /infrastructure/systems/s1
litp inherit -p /deployments/d1/clusters/c1/nodes/n2/system -s /infrastructure/systems/s2

litp inherit -p /deployments/d1/clusters/c1/nodes/n1/os -s /software/profiles/rhel_6_4
litp inherit -p /deployments/d1/clusters/c1/nodes/n2/os -s /software/profiles/rhel_6_4

litp inherit -p /deployments/d1/clusters/c1/nodes/n1/storage_profile -s /infrastructure/storage/storage_profiles/profile_1
litp inherit -p /deployments/d1/clusters/c1/nodes/n2/storage_profile -s /infrastructure/storage/storage_profiles/profile_1

litp create -t eth -p /deployments/d1/clusters/c1/nodes/n1/network_interfaces/eth9 -o device_name=eth9 macaddress=00:00:00:00:00:01 network_name=mgmt ipaddress=192.168.0.1
litp create -t eth -p /deployments/d1/clusters/c1/nodes/n2/network_interfaces/eth9 -o device_name=eth9 macaddress=00:00:00:00:00:02 network_name=mgmt ipaddress=192.168.0.2

litp create -t eth -p /ms/network_interfaces/if0 -o device_name=eth0 macaddress=DE:AD:BE:EF:13:39 ipaddress=192.168.0.111 network_name=mgmt
