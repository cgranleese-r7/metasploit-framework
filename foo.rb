
def without
  session.fs.file.stat(@chown_file).stathash
end

def with(session)
  session.fs.file.stat(@chown_file).stathash
end
