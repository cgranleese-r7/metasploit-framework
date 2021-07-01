passwd_stat = session.fs.file.stat(@chown_file).stathash

def fooo
  passwd_stat = session.fs.file.stat(@chown_file).stathash
end

class Foo
end
