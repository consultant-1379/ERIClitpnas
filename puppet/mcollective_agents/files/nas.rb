module MCollective
    module Agent
        class Nas<RPC::Agent
            action "mount_ipv4" do
                cmd = "mkdir -p #{request[:mount_point]}; /bin/mount -t nfs #{request[:ipv4]}:#{request[:export_path]} #{request[:mount_point]}"
                reply[:retcode] = run("#{cmd}",
                                     :stdout => :out,
                                     :stderr => :err,
                                     :chomp => true)
            end

            action "umount_ipv4" do
                cmd = "/bin/umount -f #{request[:mount_point]}"
                reply[:retcode] = run("#{cmd}",
                                     :stdout => :out,
                                     :stderr => :err,
                                     :chomp => true)
            end

            action "mount_ipv6" do
                cmd = "mkdir -p #{request[:mount_point]}; /bin/mount -t nfs #{request[:ipv6]}:#{request[:export_path]} #{request[:mount_point]}"
                reply[:retcode] = run("#{cmd}",
                                     :stdout => :out,
                                     :stderr => :err,
                                     :chomp => true)
            end

            action "unmount" do
                cmd = "/bin/umount -f #{request[:mount_point]}"
                reply[:retcode] = run("#{cmd}",
                                     :stdout => :out,
                                     :stderr => :err,
                                     :chomp => true)
            end

        end
    end
end


