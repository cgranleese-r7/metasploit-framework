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
        def run_module
          session.fs.file.rm
        end 
      end
    RUBY
  end

  # it 'adds the compat, meterpreter and commands data when they arent present within the module' do
  #   expect_offense(<<~RUBY)
  #     class DummyModule
  #       def initialize(info = {})
  #         super(
  #           update_info(
  #             info,
  #             'Name' => 'Simple module name',
  #             'Description' => 'Lorem ipsum dolor sit amet',
  #             'Author' => [ 'example1', 'example2' ],
  #             'License' => MSF_LICENSE,
  #             'Platform' => 'win',
  #             'Arch' => ARCH_X86,
  #             'DisclosureDate' => 'January 5'
  #           )
  #         )
  #       end
  #       def run_module
  #         session.fs.file.rm
  #         ^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
  #       end
  #     end
  #   RUBY
  #
  #
  #   expect_correction(<<~RUBY)
  #     class DummyModule
  #       def initialize(info = {})
  #         super(
  #           update_info(
  #             info,
  #             'Name' => 'Simple module name',
  #             'Description' => 'Lorem ipsum dolor sit amet',
  #             'Author' => [ 'example1', 'example2' ],
  #             'License' => MSF_LICENSE,
  #             'Platform' => 'win',
  #             'Arch' => ARCH_X86,
  #             'DisclosureDate' => 'January 5',
  #             'Compat' => {
  #               'Meterpreter' => {
  #                 'Commands' => %w[
  #                   stdapi_fs_rm
  #                 ]
  #               }
  #             }
  #           )
  #         )
  #       end
  #       def run_module
  #         session.fs.file.rm
  #       end
  #     end
  #   RUBY
  # end


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
        def run_module
          session.fs.file.rm
          ^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
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
        def run_module
          session.fs.file.rm
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
                    stdapi_fs_rm
                  ]
                }
              }
            )
          )
        end
        def run_module
          session.fs.file.rm
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
        def run_module
          session.fs.file.rm
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
                    stdapi_fs_rm
                    stdapi_fs_ls
                    stdapi_fs_ls
                  ]
                }
              }
            )
          )
        end
        def run_module
          session.fs.file.rm
          session.fs.file.ls
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
        def run_module
          session.fs.file.rm
          session.fs.file.ls
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
        def run_module
          session.fs.file.rm
          ^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
          session.fs.file.rm
          ^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
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
        def run_module
          session.fs.file.rm
          session.fs.file.rm
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
        def run_module
          session.fs.file.rm
          ^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
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
        def run_module
          session.fs.file.rm
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
        def run_module
          session.fs.file.rm
          ^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
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
        def run_module
          session.fs.file.rm
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
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
            )
          )
        end
        def run_module
          session.fs.file.rm
          ^^^^^^^^^^^^^^^^^^ Convert meterpreter api calls into meterpreter command dependencies.
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
        def run_module
          session.fs.file.rm
        end 
      end
    RUBY
  end
end

