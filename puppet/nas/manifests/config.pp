# Mount and unmount nfs based file systems
define nas::config ($mount_point, $mount_options, $path, $mount_status) {

  if $mount_status =='mounted' {

      exec {"Creating ${mount_point}":
        command => "/bin/mkdir -m 755 -p '${mount_point}'",
        creates => $mount_point,
        path    => ['/bin', '/usr/bin', '/usr/sbin', '/sbin'],
      }

      mount { $mount_point:
        ensure  => $mount_status,
        device  => $path,
        fstype  => 'nfs',
        name    => $mount_point,
        options => $mount_options,
        atboot  => true,
        require => Exec["Creating ${mount_point}"],
      }
  }

  elsif $mount_status == 'absent' {

      mount { $mount_point:
        ensure  => $mount_status,
        device  => $path,
        fstype  => 'nfs',
        name    => $mount_point,
        options => $mount_options,
        atboot  => true,
      }
      exec {"Removing ${mount_point}":
        command => "/bin/rm -fr '${mount_point}'",
        path    => ['/bin', '/usr/bin', '/usr/sbin', '/sbin'],
        require => Mount[$mount_point]
      }
  }

  elsif $mount_status == 'remount' {
      exec {"Unmount ${mount_point}":
        command => "/bin/umount -f '${mount_point}'",
        path    => ['/bin', '/usr/bin', '/usr/sbin', '/sbin'],
        unless  => "/usr/bin/timeout 3s ls '${mount_point}'"
      }
      exec {"Wait for ${mount_point}":
        command     => '/bin/sleep 1',
        path        => ['/bin', '/usr/bin', '/usr/sbin', '/sbin'],
        subscribe   => Exec["Unmount ${mount_point}"],
        refreshonly => true
      }
      mount { $mount_point:
        ensure   => mounted,
        device   => $path,
        fstype   => 'nfs',
        name     => $mount_point,
        options  => $mount_options,
        atboot   => true,
        remounts => false,
        require  => Exec["Wait for ${mount_point}"]
      }
  }

}
