if session.type.to_s.eql? 'meterpreter'
  # Reinstate /etc/passwd root ownership
  session.sys.process.execute '/bin/sh', "-c \"chown root:root #{@chown_file}\""

  # Remove new user
  session.sys.process.execute '/bin/sh', "-c \"sed -i 's/^#{@username}:.*$//g' #{@chown_file}\""

  # Wait for clean up
  Rex.sleep 5

  # Check root ownership
  passwd_stat = session.fs.file.stat(@chown_file).stathash
  if passwd_stat['st_uid'] == 0 && passwd_stat['st_gid'] == 0
    root_owns_passwd = true
  end

  # Check for new user in /etc/passwd
  passwd_contents = session.fs.file.open(@chown_file).read.to_s
  unless passwd_contents.include? "#{@username}:"
    new_user_removed = true
  end
elsif session.type.to_s.eql? 'shell'
  # Reinstate /etc/passwd root ownership
  session.shell_command_token "chown root:root #{@chown_file}"

  # Remove new user
  session.shell_command_token "sed -i 's/^#{@username}:.*$//g' #{@chown_file}"

  # Check root ownership
  passwd_owner = session.shell_command_token "ls -l #{@chown_file}"
  if passwd_owner.to_s.include? 'root'
    root_owns_passwd = true
  end

  # Check for new user in /etc/passwd
  passwd_user = session.shell_command_token "grep '#{@username}:' #{@chown_file}"
  unless passwd_user.to_s.include? "#{@username}:"
    new_user_removed = true
  end
end
