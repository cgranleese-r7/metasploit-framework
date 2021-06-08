def initialize(info = {})
  super(
    update_info(
      info,
      'Compat' => {
        'Meterpreter' => {
          'Commands' => %w[
stdapi_fs_ls
stdapi_fs_rm
        ]
      }
    }
  )
)
  end


client.fs.file.rm
client.fs.file.ls
client.fs.file.rm
client.fs.file.rm
client.fs.file.rm
client.fs.file.rm
