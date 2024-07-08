require 'rex'

lib = File.join(Msf::Config.install_root, "test", "lib")
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

class MetasploitModule < Msf::Post
  include Msf::ModuleTest::PostTest
  include Msf::Post::File

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Meterpreter cmd_exec test',
        'Description' => %q( This module will test the meterpreter cmd_exec API ),
        'License' => MSF_LICENSE,
        'Platform' => [ 'windows', 'linux', 'unix', 'java', 'osx' ],
        'SessionTypes' => ['meterpreter', 'shell', 'powershell']
      )
    )
  end

  def test_cmd_exec
    # we are inconsistent reporting windows session types
    windows_strings = ['windows', 'win']
    vprint_status("Starting cmd_exec tests")

    it "should return the result of echo" do
      test_string = Rex::Text.rand_text_alpha(4)
      if windows_strings.include? session.platform and session.type.eql? 'meterpreter'
        vprint_status("meterpreter?")
        output = cmd_exec('cmd.exe', "/c echo #{test_string}")
      else
        output = cmd_exec("echo #{test_string}")
      end
      output == test_string
    end

    # Powershell supports this, but not windows meterpreter (unsure about windows shell)
    if not windows_strings.include? session.platform or session.type.eql? 'powershell'
      it "should return the full response after sleeping" do
        test_string = Rex::Text.rand_text_alpha(4)
        output = cmd_exec("sleep 1; echo #{test_string}")
        output == test_string
      end
      it "should return the full response after sleeping" do
        test_string = Rex::Text.rand_text_alpha(4)
        test_string2 = Rex::Text.rand_text_alpha(4)
        output = cmd_exec("echo #{test_string}; sleep 1; echo #{test_string2}")
        output.delete("\r") == "#{test_string}\n#{test_string2}"
      end

      it "should return the result of echo 10 times" do
        10.times do
          test_string = Rex::Text.rand_text_alpha(4)
          output = cmd_exec("echo #{test_string}")
          return false unless output == test_string
        end
        true
      end
    else
      vprint_status("Session does not support sleep, skipping sleep tests")
    end
    vprint_status("Finished cmd_exec tests")
  end

  def test_cmd_exec_quotes
    vprint_status("Starting cmd_exec quote tests")

    it "should return the result of echo with single quotes" do
      test_string = Rex::Text.rand_text_alpha(4)
      if session.platform.eql? 'windows' and session.arch == ARCH_PYTHON
        output = cmd_exec("cmd.exe", "/c echo \"#{test_string}\"")
        output == test_string
      elsif session.platform.eql? 'windows'
        output = cmd_exec("cmd.exe", "/c echo '#{test_string}'")
        output == "'" + test_string + "'"
      else
        output = cmd_exec("echo '#{test_string}'")
        output == test_string
      end
    end

    it "should return the result of echo with double quotes" do
      test_string = Rex::Text.rand_text_alpha(4)
      if session.platform.eql? 'windows' and session.arch == ARCH_PYTHON
        output = cmd_exec("cmd.exe", "/c echo \"#{test_string}\"")
        output == test_string
      elsif session.platform.eql? 'windows'
        output = cmd_exec("cmd.exe", "/c echo \"#{test_string}\"")
        output == "\"" + test_string + "\""
      else
        output = cmd_exec("echo \"#{test_string}\"")
        output == test_string
      end
    end
  end

  def test_cmd_exec_stderr
    vprint_status("Starting cmd_exec stderr tests")

    it "should return the stderr output" do
      test_string = Rex::Text.rand_text_alpha(4)
      if session.platform.eql? 'windows'
        output = cmd_exec("cmd.exe", "/c echo #{test_string} 1>&2")
        output.rstrip == test_string
      else
        output = cmd_exec("echo #{test_string} 1>&2")
        output == test_string
      end
    end
  end

  def upload_create_process_precompiled_binaries
    print_status 'Uploading precompiled binaries'
    if session.platform.eql? 'linux'
      upload_file('show_args', 'data/cmd_exec/show_args')
      upload_file('show_args file', 'data/cmd_exec/show_args')
      upload_file('~!@#$%^&*(){}', 'data/cmd_exec/show_args')
    end

    if session.platform.eql? 'windows'
      upload_file('show_args.exe', 'data/cmd_exec/show_args.exe')
      upload_file('show_args file.exe', 'data/cmd_exec/show_args.exe')
      upload_file('~!@#$%^&(){}.exe', 'data/cmd_exec/show_args.exe')
    end

    if session.platform.eql? 'osx'
      upload_file('show_args', 'data/cmd_exec/show_args_macos')
      upload_file('show_args file', 'data/cmd_exec/show_args_macos')
      upload_file('~!@#$%^&*(){}', 'data/cmd_exec/show_args_macos')
    end

    if session.platform.eql?('linux') || session.platform.eql?('osx')
      chmod('show_args')
      chmod('show_args file')
      chmod('~!@#$%^&*(){}')
    end
  end

  def test_create_process
    upload_create_process_precompiled_binaries

    test_string = Rex::Text.rand_text_alpha(4)

    it 'should accept blank strings and return the create_process output' do
      if session.platform.eql? 'windows'
        output = create_process('./show_args.exe', args: [test_string, '', test_string, '', test_string])
        if session.type.eql? 'powershell'
          output.rstrip == "#{pwd}\\show_args.exe\r\n#{test_string}\r\n\r\n#{test_string}\r\n\r\n#{test_string}"
        elsif session.type.eql? 'shell'
          output = create_process('show_args.exe', args: [test_string, '', test_string, '', test_string])
          output.rstrip == "show_args.exe\r\n#{test_string}\r\n\r\n#{test_string}\r\n\r\n#{test_string}"
        elsif session.type.eql?('meterpreter') && session.arch.eql?('java')
          output.rstrip == ".\\show_args.exe\r\n#{test_string}\r\n\r\n#{test_string}\r\n\r\n#{test_string}"
        else
          output.rstrip == "./show_args.exe\r\n#{test_string}\r\n\r\n#{test_string}\r\n\r\n#{test_string}"
        end
      else
        output = create_process('./show_args', args: [test_string, '', test_string, '', test_string])
        output.rstrip == "./show_args\n#{test_string}\n\n#{test_string}\n\n#{test_string}"
      end
    end

    it 'should accept multiple args and return the create_process output' do
      if session.platform.eql? 'windows'
        output = create_process('./show_args.exe', args: [test_string, test_string])
        if session.type.eql? 'powershell'
          output.rstrip == "#{pwd}\\show_args.exe\r\n#{test_string}\r\n#{test_string}"
        elsif session.type.eql? 'shell'
          output = create_process('show_args.exe', args: [test_string, test_string])
          output.rstrip == "show_args.exe\r\n#{test_string}\r\n#{test_string}"
        elsif session.type.eql?('meterpreter') && session.arch.eql?('java')
          output.rstrip == ".\\show_args.exe\r\n#{test_string}\r\n#{test_string}"
        else
          output.rstrip == "./show_args.exe\r\n#{test_string}\r\n#{test_string}"
        end
      else
        output = create_process('./show_args', args: [test_string, test_string])
        output.rstrip == "./show_args\n#{test_string}\n#{test_string}"
      end
    end

    it 'should accept spaces and return the create_process output' do
      if session.platform.eql? 'windows'
        output = create_process('./show_args.exe', args: ['with spaces'])
        if session.type.eql? 'powershell'
          output.rstrip == "#{pwd}\\show_args.exe\r\nwith spaces"
        elsif session.type.eql? 'shell'
          output = create_process('show_args.exe', args: ['with spaces'])
          output.rstrip == "show_args.exe\r\nwith spaces"
        elsif session.type.eql?('meterpreter') && session.arch.eql?('java')
          output.rstrip == ".\\show_args.exe\r\nwith spaces"
        else
          output.rstrip == "./show_args.exe\r\nwith spaces"
        end
      else
        output = create_process('./show_args', args: ['with spaces'])
        output.rstrip == "./show_args\nwith spaces"
      end
    end

    it 'should accept environment variables and return the create_process output' do
      if session.platform.eql? 'windows'
        output = create_process('./show_args.exe', args: ['$PATH'])
        if session.type.eql? 'powershell'
          output.rstrip == "#{pwd}\\show_args.exe\r\n$PATH"
        elsif session.type.eql? 'shell'
          output = create_process('show_args.exe', args: ['$PATH'])
          output.rstrip == "show_args.exe\r\n$PATH"
        elsif session.type.eql?('meterpreter') && session.arch.eql?('java')
          output.rstrip == ".\\show_args.exe\r\n$PATH"
        else
          output.rstrip == "./show_args.exe\r\n$PATH"
        end
      else
        output = create_process('./show_args', args: ['$PATH'])
        output.rstrip == "./show_args\n$PATH"
      end
    end

    it 'should accept environment variables within a string and return the create_process output' do
      if session.platform.eql? 'windows'
        output = create_process('./show_args.exe', args: ["it's $PATH"])
        if session.type.eql? 'powershell'
          output.rstrip == "#{pwd}\\show_args.exe\r\nit's $PATH"
        elsif session.type.eql? 'shell'
          output = create_process('show_args.exe', args: ["it's $PATH"])
          output.rstrip == "show_args.exe\r\nit's $PATH"
        elsif session.type.eql?('meterpreter') && session.arch.eql?('java')
          output.rstrip == ".\\show_args.exe\r\nit's $PATH"
        else
          output.rstrip == "./show_args.exe\r\nit's $PATH"
        end
      else
        output = create_process('./show_args', args: ["it's $PATH"])
        output.rstrip == "./show_args\nit's $PATH"
      end
    end

    it 'should accept special characters and return the create_process output' do
      if session.platform.eql? 'windows'
        output = create_process('./show_args.exe', args: ['~!@#$%^&*(){`1234567890[]",.\'<>'])
        if session.type.eql? 'powershell'
          output.rstrip == "#{pwd}\\show_args.exe\r\n~!@#$%^&*(){`1234567890[]\",.\'<>"
        elsif session.type.eql? 'shell'
          output = create_process('show_args.exe', args: ['~!@#$%^&*(){`1234567890[]",.\'<>'])
          output.rstrip == "show_args.exe\r\n~!@#$%^&*(){`1234567890[]\",.\'<>"
        elsif session.type.eql?('meterpreter') && session.arch.eql?('java')
          output.rstrip == ".\\show_args.exe\r\n~!@#$%^&*(){`1234567890[]\",.\'<>"
        else
          output.rstrip == "./show_args.exe\r\n~!@#$%^&*(){`1234567890[]\",.\'<>"
        end
      else
        output = create_process('./show_args', args: ['~!@#$%^&*(){`1234567890[]",.\'<>'])
        output.rstrip == "./show_args\n~!@#$%^&*(){`1234567890[]\",.\'<>"
      end
    end

    it 'should accept command line commands and return the create_process output' do
      if session.platform.eql? 'windows'
        output = create_process('./show_args.exe', args: ['run&echo'])
        if session.type.eql? 'powershell'
          output.rstrip == "#{pwd}\\show_args.exe\r\nrun&echo"
        elsif session.type.eql? 'shell'
          output = create_process('show_args.exe', args: ['run&echo'])
          output.rstrip == "show_args.exe\r\nrun&echo"
        elsif session.type.eql?('meterpreter') && session.arch.eql?('java')
          output.rstrip == ".\\show_args.exe\r\nrun&echo"
        else
          output.rstrip == "./show_args.exe\r\nrun&echo"
        end
      else
        output = create_process('./show_args', args: ['run&echo'])
        output.rstrip == "./show_args\nrun&echo"
      end
    end

    it 'should accept semicolons to separate multiple command on a single line and return the create_process output' do
      if session.platform.eql? 'windows'
        output = create_process('./show_args.exe', args: ['run&echo;test'])
        if session.type.eql? 'powershell'
          output.rstrip == "#{pwd}\\show_args.exe\r\nrun&echo;test"
        elsif session.type.eql? 'shell'
          output = create_process('show_args.exe', args: ['run&echo;test'])
          output.rstrip == "show_args.exe\r\nrun&echo;test"
        elsif session.type.eql?('meterpreter') && session.arch.eql?('java')
          output.rstrip == ".\\show_args.exe\r\nrun&echo;test"
        else
          output.rstrip == "./show_args.exe\r\nrun&echo;test"
        end
      else
        output = create_process('./show_args', args: ['run&echo;test'])
        output.rstrip == "./show_args\nrun&echo;test"
      end
    end

    it 'should accept spaces in the filename and return the create_process output' do
      if session.platform.eql? 'windows'
        output = create_process('./show_args file.exe', args: [test_string, test_string])
        if session.type.eql? 'powershell'
          output.rstrip == "#{pwd}\\show_args file.exe\r\n#{test_string}\r\n#{test_string}"
        elsif session.type.eql? 'shell'
          output = create_process('show_args file.exe', args: [test_string, test_string])
          output.rstrip == "show_args file.exe\r\n#{test_string}\r\n#{test_string}"
        elsif session.type.eql?('meterpreter') && session.arch.eql?('java')
          output.rstrip == ".\\show_args file.exe\r\n#{test_string}\r\n#{test_string}"
        else
          output.rstrip == "./show_args file.exe\r\n#{test_string}\r\n#{test_string}"
        end
      else
        output = create_process('./show_args file', args: [test_string, test_string])
        output.rstrip == "./show_args file\n#{test_string}\n#{test_string}"
      end
    end

    it 'should accept special characters in the filename and return the create_process output' do
      if session.platform.eql? 'windows'
        output = create_process('./~!@#$%^&(){}.exe', args: [test_string, test_string])
        if session.type.eql? 'powershell'
          output.rstrip == "#{pwd}\\~!@#$%^&(){}.exe\r\n#{test_string}\r\n#{test_string}"
        elsif session.type.eql? 'shell'
          output = create_process('~!@#$%^&(){}.exe', args: [test_string, test_string])
          output.rstrip == "~!@#$%^&(){}.exe\r\n#{test_string}\r\n#{test_string}"
        elsif session.type.eql?('meterpreter') && session.arch.eql?('java')
          output.rstrip == ".\\~!@#$%^&(){}.exe\r\n#{test_string}\r\n#{test_string}"
        else
          output.rstrip == "./~!@#$%^&(){}.exe\r\n#{test_string}\r\n#{test_string}"
        end
      else
        output = create_process('./~!@#$%^&*(){}', args: [test_string, test_string])
        output.rstrip == "./~!@#$%^&*(){}\n#{test_string}\n#{test_string}"
      end
    end

    # TODO: These files will need added for each environment as well
    #   ./show_args file
    #   ./~!@#$%^&*(){}

    # TODO: Runtimes
    #   Linux - Passed: 17; Failed: 0; Skipped: 0
    #   Windows - Passed: 14; Failed: 0; Skipped: 0 (Not sure why I have 3 less here)
    #   Java - Passed: 17; Failed: 0; Skipped: 0
    #   Python - Passed: 17; Failed: 0; Skipped: 0
    #   PHP - Passed: 17; Failed: 0; Skipped: 0
    #   Powershell - Passed: 14; Failed: 3; Skipped: 0 (Three existing tests - ', ", stderr"') NEEDS TESTED ON MASTER - Github jobs changes as Powershell doesnt run there
    #   Linux, Command shell - Passed: 17; Failed: 0; Skipped: 0
    #   Windows, Command shell - Passed: 14; Failed: 0; Skipped: 0 ("show_args.exe\r\nbasic\r\nargs")
  end
end
