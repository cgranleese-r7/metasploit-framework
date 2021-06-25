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

  it 'generates a list of meterpreter command dependencies based off meterpreter api calls in modules that currently have an empty commands array' do
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

  it 'generates a list of meterpreter command dependencies based off meterpreter api calls in modules that currently have an empty commands array' do
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

  it 'generates a list of meterpreter command dependencies based off meterpreter api calls in modules that currently have an empty commands array' do
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

  it 'works with modules' do
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
                    stdapi_sys_process_*
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

  it 'verifies if a commands array is present within the module' do
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

  it 'verifies if a meterpreter hash and a commands array is present within the module' do
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

  it 'verifies if a compat hash, meterpreter hash and a commands array is present within the module' do
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

  it 'verifies if a meterpreter hash and a commands array is present within the module' do
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

  it 'handles lots of examples' do
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
      client.sys.config.getprivs()
      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
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
                    stdapi_fs_ls
                    stdapi_fs_rm
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
                    stdapi_sys_process_*
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

