require 'spec_helper'
require 'rubocop/cop/lint/meterpreter_commands_dependencies'

RSpec.describe RuboCop::Cop::Lint::MeterpreterCommandDependencies, :config do
  subject(:cop) { described_class.new(config) }
  let(:config) { RuboCop::Config.new }

  it 'accepts a valid command list' do
    expect_no_offenses(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_rm
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verifies that meterpreter method calls are matched and added to the commands array' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                  ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_rm
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verifies that if `update_info(` is missing that the method calls are matched and added to the commands array ' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                ]
              }
            }
          )
        end
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                  stdapi_fs_rm
                ]
              }
            }
          )
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verifies that if `update_info(` is missing but initialize has `(info={})` that the method calls are matched and added to the commands array ' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info={})
          super
          ^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          register_options([])
        end
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info={})
          super
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                  stdapi_fs_rm
                ]
              }
            }
          register_options([])
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verifies that if there are two classes, that it will successfully iterate over them and match the method calls in the appropriate class and generate a commands list' do
    expect_offense(<<~RUBY)
      class DummyModule
        class HelperClass
          def initialize
            @foo = 123
          end
        end

        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                ]
              }
            }
          )
        end

        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        class HelperClass
          def initialize
            @foo = 123
          end
        end

        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                  stdapi_fs_rm
                ]
              }
            }
          )
        end

        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verifies that if no compat node is present and no method calls that it will not generate anything/alter the file' do
    expect_no_offenses(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
          )
        end
        def run
        end
      end
    RUBY
  end

  it 'verifies that is the command list has a command present but no corresponding call, the command should be removed' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                  stdapi_fs_rm
                  ^^^^^^^^^^^^ Compatibility command does not have an associated method call.
                ]
              }
            }
          )
          register_options([])
        end
        def run
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                ]
              }
            }
          )
          register_options([])
        end
        def run
        end
      end
    RUBY
  end

  it 'generates a list of meterpreter command dependencies based off meterpreter api calls in modules that currently have an empty commands array' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                ]
              }
            }
          )
          register_options([])
        end
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize
          super(
            'Name' => 'Simple module name',
            'Description' => 'Lorem ipsum dolor sit amet',
            'Author' => [ 'example1', 'example2' ],
            'License' => MSF_LICENSE,
            'Platform' => 'win',
            'Arch' => ARCH_X86,
            'DisclosureDate' => 'January 5',
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                  stdapi_fs_rm
                ]
              }
            }
          )
          register_options([])
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verfies that the cop will also work with modules' do
    expect_offense(<<~RUBY)
      module Msf::Post::Process
             ^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        def meterpreter_get_processes
          begin
            return session.sys.process.get_processes.map { |p| p.slice('name', 'pid') }
                   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          rescue Rex::Post::Meterpreter::RequestError
            shell_get_processes
          end
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      module Msf::Post::Process
        def initialize(info = {})
          super(
            update_info(
              info,
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_sys_get_processes
                  ]
                }
              }
            )
          )
        end

        def meterpreter_get_processes
          begin
            return session.sys.process.get_processes.map { |p| p.slice('name', 'pid') }
          rescue Rex::Post::Meterpreter::RequestError
            shell_get_processes
          end
        end
      end
    RUBY
  end

  it 'removes a redundant command from the list of meterpreter command dependencies based off meterpreter api calls in modules that currently have a command that is no longer required' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                  ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                    stdapi_fs_ls
                    ^^^^^^^^^^^^ Compatibility command does not have an associated method call.
                    stdapi_fs_rm
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_rm
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verifies that the commands arrays contents are unique as well as being sorted alphabetically' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                  ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                    stdapi_fs_rm
                    ^^^^^^^^^^^^ Command duplicated.
                    stdapi_fs_rm
                    ^^^^^^^^^^^^ Command duplicated.
                    stdapi_fs_ls
                    ^^^^^^^^^^^^ Command duplicated.
                    stdapi_fs_ls
                    ^^^^^^^^^^^^ Command duplicated.
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
          session.fs.file.ls("some_file")
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
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
        def run
          session.fs.file.rm("some_file")
          session.fs.file.ls("some_file")
        end
      end
    RUBY
  end

  it 'ensures there are not duplicate entries in the commands list' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                  ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                    stdapi_fs_ls
                    ^^^^^^^^^^^^ Command duplicated.
                    stdapi_fs_ls
                    ^^^^^^^^^^^^ Command duplicated.
                    stdapi_fs_ls
                    ^^^^^^^^^^^^ Command duplicated.
                  ]
                }
              }
            )
          )
        end
        def run
         session.fs.file.ls("some_file")
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_ls
                  ]
                }
              }
            )
          )
        end
        def run
         session.fs.file.ls("some_file")
        end
      end
    RUBY
  end

  it 'handles when there are two or more identical method calls ' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                  ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_rm
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verifies if a commands array is not present within a module it will be generated and appended appropriately' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                ^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_rm
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verifies if a meterpreter hash and a commands array is present within the module, if not it should be generated and appended appropriately' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
              ^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_rm
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end


  it 'handles two classes being in the same file' do
    expect_offense(<<~RUBY)
      class DummyModuleOne
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
              ^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end

      class DummyModuleTwo
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
              ^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
              }
            )
          )
        end
        def run
         session.fs.file.ls("some_file")
         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModuleOne
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_rm
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
        end
      end

      class DummyModuleTwo
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_ls
                  ]
                }
              }
            )
          )
        end
        def run
         session.fs.file.ls("some_file")
        end
      end
    RUBY
  end

  it 'verifies if a compat hash, meterpreter hash and a commands array is present within the module, if not it should be generated and appended appropriately' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5'
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Name' => 'Simple module name',
              'Description' => 'Lorem ipsum dolor sit amet',
              'Author' => [ 'example1', 'example2' ],
              'License' => MSF_LICENSE,
              'Platform' => 'win',
              'Arch' => ARCH_X86,
              'DisclosureDate' => 'January 5',
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_rm
                  ]
                }
              }
            )
          )
        end
        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verifies if a there is no initialise method, that it should be generated and appended appropriately' do
    expect_offense(<<~RUBY)
      class DummyModule
            ^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_rm
                  ]
                }
              }
            )
          )
        end

        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'verfies that if compat has another value, that the meterpreter hash will be appended onto it, not replace it' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Payload'        => {
                'Compat'       =>
                ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                {
                  'PayloadType' => 'cmd'
                }
              }
            )
          )
        end

        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(
            update_info(
              info,
              'Payload'        => {
                'Compat'       =>
                {
                  'PayloadType' => 'cmd'
                  'Meterpreter' => {
                    'Commands' => %w[
                      stdapi_fs_rm
                    ]
                  }
                }
              }
            )
          )
        end

        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'handles `abrt_raceabrt_priv_esc.rb` edge cases that were not being matched for unknown reasons' do
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
            super(update_info(info,
              'Name'           => 'ABRT raceabrt Privilege Escalation',
              'Description'    => %q{
                This module attempts to gain root privileges on Linux systems with
                a vulnerable version of Automatic Bug Reporting Tool (ABRT) configured
                as the crash handler.
        
                A race condition allows local users to change ownership of arbitrary
                files (CVE-2015-3315). This module uses a symlink attack on
                `/var/tmp/abrt/*/maps` to change the ownership of `/etc/passwd`,
                then adds a new user with UID=0 GID=0 to gain root privileges.
                Winning the race could take a few minutes.
        
                This module has been tested successfully on:
        
                abrt 2.1.11-12.el7 on RHEL 7.0 x86_64;
                abrt 2.1.5-1.fc19 on Fedora Desktop 19 x86_64;
                abrt 2.2.1-1.fc19 on Fedora Desktop 19 x86_64;
                abrt 2.2.2-2.fc20 on Fedora Desktop 20 x86_64;
                abrt 2.3.0-3.fc21 on Fedora Desktop 21 x86_64.
              },
              'License'        => MSF_LICENSE,
              'Author'         =>
                [
                  'Tavis Ormandy', # Discovery and C exploit
                  'bcoles' # Metasploit
                ],
              'DisclosureDate' => '2015-04-14',
              'Platform'       => [ 'linux' ],
              'Arch'           => [ ARCH_X86, ARCH_X64 ],
              'SessionTypes'   => [ 'shell', 'meterpreter' ],
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                  ^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                    stdapi_sys_process_*
                    ^^^^^^^^^^^^^^^^^^^^ Compatibility command does not have an associated method call.
                  ]
                }
              }
            )
          )
        end
        def run
          session.sys.process.execute 'shell', "command"
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          passwd_stat = session.fs.file.stat(@chown_file).stathash
                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
            super(update_info(info,
              'Name'           => 'ABRT raceabrt Privilege Escalation',
              'Description'    => %q{
                This module attempts to gain root privileges on Linux systems with
                a vulnerable version of Automatic Bug Reporting Tool (ABRT) configured
                as the crash handler.
        
                A race condition allows local users to change ownership of arbitrary
                files (CVE-2015-3315). This module uses a symlink attack on
                `/var/tmp/abrt/*/maps` to change the ownership of `/etc/passwd`,
                then adds a new user with UID=0 GID=0 to gain root privileges.
                Winning the race could take a few minutes.
        
                This module has been tested successfully on:
        
                abrt 2.1.11-12.el7 on RHEL 7.0 x86_64;
                abrt 2.1.5-1.fc19 on Fedora Desktop 19 x86_64;
                abrt 2.2.1-1.fc19 on Fedora Desktop 19 x86_64;
                abrt 2.2.2-2.fc20 on Fedora Desktop 20 x86_64;
                abrt 2.3.0-3.fc21 on Fedora Desktop 21 x86_64.
              },
              'License'        => MSF_LICENSE,
              'Author'         =>
                [
                  'Tavis Ormandy', # Discovery and C exploit
                  'bcoles' # Metasploit
                ],
              'DisclosureDate' => '2015-04-14',
              'Platform'       => [ 'linux' ],
              'Arch'           => [ ARCH_X86, ARCH_X64 ],
              'SessionTypes'   => [ 'shell', 'meterpreter' ],
              'Compat' => {
                'Meterpreter' => {
                  'Commands' => %w[
                    stdapi_fs_stat
                    stdapi_sys_execute
                  ]
                }
              }
            )
          )
        end
        def run
          session.sys.process.execute 'shell', "command"
          passwd_stat = session.fs.file.stat(@chown_file).stathash
        end
      end
    RUBY
  end

  it 'handles `abrt_raceabrt_priv_esc.rb` edge cases that were not being matched for unknown reasons' do
    skip("not working yet")
    expect_offense(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(update_info(info,
            'Name'                 => "Windows Run Command As User",
            'Description'          => %q{
              This module will login with the specified username/password and execute the
              supplied command as a hidden process. Output is not returned by default.
              Unless targeting a local user either set the DOMAIN, or specify a UPN user
              format (e.g. user@domain). This uses the CreateProcessWithLogonW WinAPI function.
      
              A custom command line can be sent instead of uploading an executable.
              APPLICAITON_NAME and COMMAND_LINE are passed to lpApplicationName and lpCommandLine
              respectively. See the MSDN documentation for how these two values interact.
            },
            'License'              => MSF_LICENSE,
            'Platform'             => ['win'],
            'SessionTypes'         => ['meterpreter'],
            'Author'               => ['Kx499', 'Ben Campbell'],
            'Targets'              => [
              [ 'Automatic', { 'Arch' => [ ARCH_X86, ARCH_X64 ] } ]
            ],
            'DefaultTarget'        => 0,
            'References'           =>
              [
                [ 'URL', 'https://msdn.microsoft.com/en-us/library/windows/desktop/ms682431' ]
              ],
            'DisclosureDate' => '1999-01-01' # Same as psexec -- a placeholder date for non-vuln 'exploits'
            ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          ))
      
          register_options(
            [
              OptString.new('DOMAIN', [false, 'Domain to login with' ]),
              OptString.new('USER', [true, 'Username to login with' ]),
              OptString.new('PASSWORD', [true, 'Password to login with' ]),
              OptString.new('APPLICATION_NAME', [false, 'Application to be executed (lpApplicationName)', nil ]),
              OptString.new('COMMAND_LINE', [false, 'Command line to execute (lpCommandLine)', nil ]),
              OptBool.new('USE_CUSTOM_COMMAND', [true, 'Specify custom APPLICATION_NAME and COMMAND_LINE', false ])
            ])
        end

        def run
          session.fs.file.rm("some_file")
          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        end
      end
    RUBY

    expect_correction(<<~RUBY)
      class DummyModule
        def initialize(info = {})
          super(update_info(info,
            'Name'                 => "Windows Run Command As User",
            'Description'          => %q{
              This module will login with the specified username/password and execute the
              supplied command as a hidden process. Output is not returned by default.
              Unless targeting a local user either set the DOMAIN, or specify a UPN user
              format (e.g. user@domain). This uses the CreateProcessWithLogonW WinAPI function.
      
              A custom command line can be sent instead of uploading an executable.
              APPLICAITON_NAME and COMMAND_LINE are passed to lpApplicationName and lpCommandLine
              respectively. See the MSDN documentation for how these two values interact.
            },
            'License'              => MSF_LICENSE,
            'Platform'             => ['win'],
            'SessionTypes'         => ['meterpreter'],
            'Author'               => ['Kx499', 'Ben Campbell'],
            'Targets'              => [
              [ 'Automatic', { 'Arch' => [ ARCH_X86, ARCH_X64 ] } ]
            ],
            'DefaultTarget'        => 0,
            'References'           =>
              [
                [ 'URL', 'https://msdn.microsoft.com/en-us/library/windows/desktop/ms682431' ]
              ],
            'DisclosureDate' => '1999-01-01' # Same as psexec -- a placeholder date for non-vuln 'exploits'
            'Compat' => {
              'Meterpreter' => {
                'Commands' => %w[
                  stdapi_fs_rm
                ]
              }
            }
          ))
      
          register_options(
            [
              OptString.new('DOMAIN', [false, 'Domain to login with' ]),
              OptString.new('USER', [true, 'Username to login with' ]),
              OptString.new('PASSWORD', [true, 'Password to login with' ]),
              OptString.new('APPLICATION_NAME', [false, 'Application to be executed (lpApplicationName)', nil ]),
              OptString.new('COMMAND_LINE', [false, 'Command line to execute (lpCommandLine)', nil ]),
              OptBool.new('USE_CUSTOM_COMMAND', [true, 'Specify custom APPLICATION_NAME and COMMAND_LINE', false ])
            ])
        end

        def run
          session.fs.file.rm("some_file")
        end
      end
    RUBY
  end

  it 'handles lots of examples' do
    %w[sesion client].each do |keyword|
      code_snippet_with_errors = <<-EOF
        session.fs.file.rm(
        ^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
            "some_file"
        )
        session.sys.process.get_processes
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.file.ls("file")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.registry.splitkey(key)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.registry.load_key(root_key, base_key, file)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.registry.unload_key(root_key,base_key)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.config.getprivs()
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.registry.create_key(root_key, base_key, perms)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.registry.open_key(root_key, base_key, perms)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.registry.delete_key(root_key, base_key, perms)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.registry.enum_key_direct(root_key, base_key, perms)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.registry.enum_value_direct(root_key, base_key, perms)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.registry.query_value_direct(root_key, base_key, valname, perms)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.registry.set_value_direct(root_key, base_key, valname, session.sys.registry.type2str(type), data, perms)
                                                                           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.registry.check_key_exists(root_key, base_key)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.dir.getwd
        ^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.appapi.app_install(out_apk)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.process.execute
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.file.stat(@chown_file)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.config.sysinfo["Computer"]
        ^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.process.get_processes
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.config.getenv('TEMP')
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.railgun.memread(@addresses['AcroRd32.exe'] + target['AdobeCollabSyncTrigger'], target['AdobeCollabSyncTriggerSignature'].length)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.process.open
        ^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.net.socket.create
        ^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.config.getprivs
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.config.getenv('windir')
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.file.copy("C:\\Windows\\System32\\WSReset.exe", exploit_file)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.config.getdrivers
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.file.md5(d[:filename])
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.dir.mkdir(share_dir)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.power.reboot
        ^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.config.getuid
        ^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.file.new(taskfile, "wb")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.file.stat(@chown_file).stathash
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.android.activity_start('intent:#Intent;launchFlags=0x8000;component=com.android.settings/.ChooseLockGeneric;i.lockscreen.password_type=0;B.confirm_credentials=false;end')
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.net.resolve.resolve_host(name)[:ip]
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.file.separator
        ^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.file.exist?(@paths['ff'] + temp_file) && !session.fs.file.exist?(@paths['ff'] + org_file)
                                                             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.file.upload_file(@paths['ff'] + new_file, tmp)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.file.search(path, "config.xml", true, -1)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.android.wlan_geolocate
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.net.config.respond_to?(:each_route)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.webcam.record_mic(datastore['DURATION'])
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.espia.espia_image_get_dev_screen
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.android.set_wallpaper(File.binread(file))
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.config.steal_token(pid)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.config.revert_to_self
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.net.config.each_route
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.net.config.each_interface
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.dir.foreach(program_files)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.dir.pwd
        ^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.priv.getsystem(technique)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.kiwi.golden_ticket_create(ticket)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.kiwi.kerberos_ticket_use(ticket)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.priv.sam_hashes
        ^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.incognito.incognito_list_tokens(0)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.dir.entries(v)
        ^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.kiwi.get_debug_privilege
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.kiwi.creds_all
        ^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.config.is_system?
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.extapi.wmi.query("SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering")
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.registry.open_remote_key(datastore['RHOST'], root_key)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.priv.getsystem
        ^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.extapi.adsi.domain_query(domain, adsi_filter, 255, 255, adsi_fields)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.priv.fs.get_file_mace(datastore['FILE'])
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.priv.fs.set_file_mace(datastore['FILE'], mace["Modified"], mace["Accessed"], mace["Created"], mace["Entry Modified"])
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.extapi.pageant.forward(socket_request_data.first, socket_request_data.first.size)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.lanattacks.dhcp.reset
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.lanattacks.dhcp.load_options(datastore)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.lanattacks.tftp.start
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.lanattacks.dhcp.start
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.lanattacks.tftp.stop
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.lanattacks.dhcp.stop
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.webcam.webcam_start(datastore['INDEX'])
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.webcam.webcam_get_frame(datastore['QUALITY'])
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.webcam.webcam_stop
        ^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.webcam.webcam_list
        ^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.incognito.incognito_impersonate_token(domain_user)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.file.expand_path(path)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.peinjector.add_thread_x64(raw)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.peinjector.inject_shellcode(param)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.lanattacks.dhcp.load_options(datastore)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.config.getenvs('SYSTEMDRIVE', 'HOMEDRIVE', 'ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432')
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.file.exist?(net_sarang_path_5)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.peinjector.add_thread_x86(raw)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.lanattacks.dhcp.log.each
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.dir.rmdir(datastore['PATH'])
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.process.open.name
        ^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.process.get_processes
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.process.getpid
        ^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.process.open(pid, PROCESS_ALL_ACCESS)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.process.get_processes()
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.process.kill(process['pid'])
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.process.execute(cmd, nil, {'Hidden' => true})
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.process.each_process.find
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.process.open.pid
        ^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.process.execute 'script', "command"
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.file.stat(@chown_file).stathash
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.file.download_file("test", "file", opts)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.lanattacks.tftp.add_file("update_test",contents)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.fs.file.download_file("local_path/img", "f_path/img", opts)
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
        session.sys.process.execute '/bin/sh', "-c \\"chown root:root \#{@chown_file}\\""
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
      EOF

      code_snippet_without_error_lines = code_snippet_with_errors.lines.reject { |line| line.lstrip.start_with?("^^^^") }.join

      expect_offense(<<~RUBY)
        class DummyModule
              ^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          def run
  #{code_snippet_with_errors}
          end
        end
      RUBY

      expect_correction(<<~RUBY)
        class DummyModule
          def initialize(info = {})
            super(
              update_info(
                info,
                'Compat' => {
                  'Meterpreter' => {
                    'Commands' => %w[
                      android_activity_start
                      android_set_wallpaper
                      android_wlan_geolocate
                      appapi_app_install
                      espia_espia_image_get_dev_screen
                      extapi_adsi_domain_query
                      extapi_pageant_forward
                      extapi_wmi_query
                      incognito_incognito_impersonate_token
                      incognito_incognito_list_tokens
                      kiwi_creds_all
                      kiwi_get_debug_privilege
                      kiwi_golden_ticket_create
                      kiwi_kerberos_ticket_use
                      lanattacks_*
                      lanattacks_dhcp_load_options
                      lanattacks_dhcp_log
                      lanattacks_dhcp_start
                      lanattacks_dhcp_stop
                      lanattacks_tftp_add_file
                      lanattacks_tftp_start
                      lanattacks_tftp_stop
                      net_socket_create
                      peinjector_add_thread_x64
                      peinjector_add_thread_x86
                      peinjector_inject_shellcode
                      priv_get_file_mace
                      priv_getsystem
                      priv_sam_hashes
                      priv_set_file_mace
                      stdapi_fs_copy
                      stdapi_fs_download_file
                      stdapi_fs_entries
                      stdapi_fs_exist?
                      stdapi_fs_expand_path
                      stdapi_fs_foreach
                      stdapi_fs_getwd
                      stdapi_fs_ls
                      stdapi_fs_md5
                      stdapi_fs_mkdir
                      stdapi_fs_new
                      stdapi_fs_pwd
                      stdapi_fs_rm
                      stdapi_fs_rmdir
                      stdapi_fs_search
                      stdapi_fs_separator
                      stdapi_fs_stat
                      stdapi_fs_upload_file
                      stdapi_net_each_interface
                      stdapi_net_each_route
                      stdapi_net_resolve_host
                      stdapi_net_respond_to
                      stdapi_railgun_*
                      stdapi_registry_check_key_exists
                      stdapi_registry_config_getprivs
                      stdapi_registry_create_key
                      stdapi_registry_delete_key
                      stdapi_registry_enum_key_direct
                      stdapi_registry_enum_value_direct
                      stdapi_registry_load_key
                      stdapi_registry_open_key
                      stdapi_registry_query_value_direct
                      stdapi_registry_set_value_direct
                      stdapi_registry_splitkey
                      stdapi_registry_type2str
                      stdapi_registry_unload_key
                      stdapi_sys_config_getenv
                      stdapi_sys_config_sysinfo
                      stdapi_sys_each_process
                      stdapi_sys_execute
                      stdapi_sys_get_processes
                      stdapi_sys_getdrivers
                      stdapi_sys_getenvs
                      stdapi_sys_getpid
                      stdapi_sys_getuid
                      stdapi_sys_is_system
                      stdapi_sys_kill
                      stdapi_sys_open
                      stdapi_sys_open_remote_key
                      stdapi_sys_power_reboot
                      stdapi_sys_reverevert_to_self
                      stdapi_sys_steal_token
                      stdapi_webcam_*
                    ]
                  }
                }
              )
            )
          end
  
          def run
  #{code_snippet_without_error_lines}
          end
        end
      RUBY
    end
  end
end

