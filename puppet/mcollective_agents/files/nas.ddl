metadata :name        => "nas",
         :description => "Agent to handle nas operations",
         :author      => "Ericsson AB",
         :license     => "Ericsson",
         :version     => "1.0",
         :url         => "http://ericsson.com",
         :timeout     => 600

action "mount_ipv4", :description => "Attempt to mount over ipv4" do
    display :always

    input :ipv4,
          :prompt      => "ipv4",
          :description => "Attempt to mount over ipV4",
          :type        => :string,
          :validation  => '^.*$',
          :optional    => true,
          :maxlength   => 1000

    input :mount_point,
          :prompt      => "mount_point",
          :description => "Mount point on node",
          :type        => :string,
          :validation  => '^.*$',
          :optional    => true,
          :maxlength   => 1000

    input :export_path,
          :prompt      => "export_path",
          :description => "Export to mount",
          :type        => :string,
          :validation  => '^.*$',
          :optional    => true,
          :maxlength   => 1000

    output :retcode,
           :description => "The output of the command",
           :display_as  => "Command result",
           :default     => "no output"
end

action "mount_ipv6", :description => "Attempt to mount over ipV6" do
    display :always

    input :ipv6,
          :prompt      => "ipv6",
          :description => "Attempt to mount over ipV46",
          :type        => :string,
          :validation  => '^.*$',
          :optional    => true,
          :maxlength   => 1000

    input :mount_point,
          :prompt      => "mount_point",
          :description => "Mount point on node",
          :type        => :string,
          :validation  => '^.*$',
          :optional    => true,
          :maxlength   => 1000

    input :export_path,
          :prompt      => "export_path",
          :description => "Export to mount",
          :type        => :string,
          :validation  => '^.*$',
          :optional    => true,
          :maxlength   => 1000

    output :retcode,
           :description => "The output of the command",
           :display_as  => "Command result",
           :default     => "no output"
end


action "unmount", :description => "Attempt to unmount previously mounted export" do
    display :always

    input :mount_point,
          :prompt      => "mount_point",
          :description => "Attempt to unmount previously mounted export",
          :type        => :string,
          :validation  => '^.*$',
          :optional    => true,
          :maxlength   => 1000

    output :retcode,
           :description => "The output of the command",
           :display_as  => "Command result",
           :default     => "no output"
end

