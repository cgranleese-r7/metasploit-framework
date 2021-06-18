module RuboCop
  module Cop
    module Lint
      class MeterpreterCommandDependencies < Base
        extend AutoCorrector
        include Alignment

        MSG = 'Convert meterpreter api calls into meterpreter command dependencies.'.freeze

        def_node_matcher :find_update_info_node, <<~PATTERN
          (def :initialize _args (begin (super $(send nil? {:update_info :merge_info} (lvar :info) (hash ...))) ...))
        PATTERN

        def_node_matcher :find_nested_update_info_node, <<~PATTERN
          (def :initialize _args (super $(send nil? {:update_info :merge_info} (lvar :info) (hash ...)) ...))
        PATTERN

        # Matchers for identifying if the code already has an initialise etc.
        # TODO: Create matchers to identify where I can add my list of requirements
        def_node_matcher :find_command_array_node, <<~PATTERN
          (hash
            (pair
              (str "Commands")
              $(array ...)))
        PATTERN

        def_node_matcher :initialize_present?, <<~PATTERN
          (send nil? :initialize)
        PATTERN

        # Matchers for meterpreter API calls
        def_node_matcher :file_rm_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :file) :rm)
        PATTERN

        def_node_matcher :file_ls_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :file) :ls)
        PATTERN

        def on_new_investigation
          super
          @current_commands = [] # TODO: Needed for when the cop has been ran against modules with no offenses && if the list has commands that dont have a corresponding function call
          @identified_commands = []
          @command_array_node = nil

          @state = :none
        end

        def on_def(node)
          return unless @state == :none

          update_info_node = find_update_info_node(node) || find_nested_update_info_node(node)
          return if update_info_node.nil?

          @state = :looking_for_hash_keys
        end

        def after_def(_node)
          # require "pry"; binding.pry
          @state = :none
        end

        def on_pair(node)
          return unless @state == :looking_for_hash_keys
          # require "pry"; binding.pry
          if node.key.value == 'Compat'
            @compat_node = node
          elsif node.key.value == 'Meterpreter'
            @meterpreter_node = node
          elsif node.key.value == 'Commands'
            @command_node = node # TODO: Grab these children again like before.
            node.value.each_child_node {|command| @current_commands << command.value}
            # require "pry"; binding.pry
          end
        end

        def hash_arg?(node)
          node.type == :hash
        end

        # def on_hash(node)
        #   require "pry"; binding.pry
        #   command_array_node = find_command_array_node(node)
        #   return unless command_array_node
        #
        #   require "pry"; binding.pry
        #   @command_array_node = command_array_node
        #   require "pry"; binding.pry
        #   # @command_list_node.each_pair { |_key, value| value.each_child_node { |node_type, _values| @current_commands << node_type.value}}
        #
        #   require "pry"; binding.pry
        # end

        def on_send(node)
          if file_rm_call?(node)
            @identified_commands << 'stdapi_fs_rm' unless @identified_commands.include?('stdapi_fs_rm')
            # Add an offense, but don't provide an autocorrect. There will be a final autocorrect to fix all issues
            add_offense(node) unless @current_commands.include?('stdapi_fs_rm')
          end

          if file_ls_call?(node)
            @identified_commands << 'stdapi_fs_ls' unless @identified_commands.include?('stdapi_fs_ls')
            # Add an offense, but don't provide an autocorrect. There will be a final autocorrect to fix all issues
            add_offense(node) unless @current_commands.include?('stdapi_fs_ls')

          end
        end

        def on_investigation_end
          # TODO: Add offenses for when the list just needs sorted.
          super
          # Ensure commands are sorted and unique
          @identified_commands = @identified_commands.uniq.sort

          # TODO: Need better logic here for scenarios where nodes could be nil, as they may not be present
          if @compat_node && @meterpreter_node && @command_node && @identified_commands != @current_commands
            add_offense(@command_node, &autocorrector)
          elsif @compat_node && @meterpreter_node && @command_node && @identified_commands == @current_commands
            # TODO: Handle this
          elsif @compat_node && @meterpreter_node && @command_node.nil?
            add_offense(@meterpreter_node, &autocorrector)
          elsif @compat_node && @meterpreter_node.nil? && @command_node.nil?
            add_offense(@compat_node, &autocorrector)
          else
            raise 'Fix this dummy'
          end
        end

        def autocorrector
          lambda do |corrector|
            # Handles scenario where we have both compat & meterpreter hashes
            # but no commands array present within a module
            if @compat_node && @meterpreter_node && @command_node.nil?
              meterpreter_hash_node = @meterpreter_node.children[1]

              # White spacing handling based of node offsets
              meterpreter_whitespace = offset(@meterpreter_node)
              commands_whitespace = meterpreter_whitespace + "  "
              array_content_whitespace = commands_whitespace + "  "

              # Formatting to add missing commands node when the method has a compat node & meterpreter node present
              new_hash =
                "{\n" \
                "#{commands_whitespace}'Commands' => %w[" \
                "\n#{array_content_whitespace}#{@identified_commands.join("\n#{array_content_whitespace}")}\n" \
                "#{commands_whitespace}]\n" \
                "#{meterpreter_whitespace}}"

              corrector.replace(meterpreter_hash_node, new_hash)

            # Handles scenario when we have a compats hash, but no meterpreter hash
            # and compats array present within the array
            elsif @compat_node && @meterpreter_node.nil? && @command_node.nil?
              compat_hash_node = @compat_node.children[1]

              # White spacing handling based of node offsets
              compat_whitespace = offset(@compat_node)
              meterpreter_whitespace = compat_whitespace + "  "
              commands_whitespace = meterpreter_whitespace + "  "
              array_content_whitespace = commands_whitespace + "  "

              # Formatting to add missing commands node when the method has a compat node & meterpreter node present
              new_hash =
                "{\n" \
                "#{meterpreter_whitespace}'Meterpreter' => {\n" \
                "#{commands_whitespace}'Commands' => %w[" \
                "\n#{array_content_whitespace}#{@identified_commands.join("\n#{array_content_whitespace}")}\n" \
                "#{commands_whitespace}]\n" \
                "#{meterpreter_whitespace}}\n" \
                "#{compat_whitespace}}"

              corrector.replace(compat_hash_node, new_hash)

            elsif @compat_node.nil? && @meterpreter_node.nil? && @command_node.nil?
              require "pry"; binding.pry
              info_node = @compat_node.children[1]

              # White spacing handling based of node offsets
              info_whitespace = offset(@compat_node)
              compat_whitespace = offset(@compat_node)
              meterpreter_whitespace = compat_whitespace + "  "
              commands_whitespace = meterpreter_whitespace + "  "
              array_content_whitespace = commands_whitespace + "  "

              # Formatting to add missing commands node when the method has a compat node & meterpreter node present
              new_hash =
                "{\n" \
                "#{meterpreter_whitespace}'Meterpreter' => {\n" \
                "#{commands_whitespace}'Commands' => %w[" \
                "\n#{array_content_whitespace}#{@identified_commands.join("\n#{array_content_whitespace}")}\n" \
                "#{commands_whitespace}]\n" \
                "#{meterpreter_whitespace}}\n" \
                "#{compat_whitespace}}"

              corrector.replace(compat_hash_node, new_hash)

            else
              # TODO: Need to build out the formatting for adding the full method and another for just the compat section
              method_start = <<~EOS
                def initialize(info = {})
                  super(
                    update_info(
                      info,
                      'Compat' => {
                        'Meterpreter' => {
                          'Commands' => %w[
              EOS
              # We will add the command list for the method via the corrector below
              method_end = <<~EOS
                          ]
                        }
                      }
                    )
                  )
              EOS

              # TODO: Need logic to handle if we need to add full method or just compat list
              require "pry"; binding.pry
              array_node = @command_node.children[1]
              commands_whitespace = offset(@command_node)
              array_whitespace = commands_whitespace + "  "

              new_array = "%w[\n#{array_whitespace}#{@identified_commands.join("\n#{array_whitespace}")}\n#{commands_whitespace}]"
              corrector.replace(array_node, new_array)
            end
          end
        end
      end
    end
  end
end





# module RuboCop
#   module Cop
#     module Lint
#       class MeterpreterCommandsDependencies < Base
#         extend AutoCorrector
#
#         MSG = 'Scans modules for meterpreter commands, adds new method to define these commands to each corresponding module: '.freeze
#
#         # TODO: calls can be made by either `client.` or `session.`, need to handle both
#         def_node_matcher :config_sysinfo_call?, <<~PATTERN
#           (send (send (send (send nil? ...) :sys) :config) :sysinfo)
#         PATTERN

        # def_node_matcher :railgun_call?, <<~PATTERN
        #   (send (send (send nil? ...) :railgun) ...)
        # PATTERN
        #
        # def_node_matcher :fs_dir_getwd_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :fs) :dir) :getwd)
        # PATTERN
        #
        # def_node_matcher :fs_file_rm_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :fs) :file) :rm)
        # PATTERN
        #
        # def_node_matcher :appapi_app_install_call?, <<~PATTERN
        #   (send (send (send nil? ...) :appapi) :app_install)
        # PATTERN
        #
        # def_node_matcher :process_execute_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :sys) :process) :execute)
        # PATTERN
        #
        # def_node_matcher :fs_file_stat_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :fs) :file) :stat)
        # PATTERN
        #
        # def_node_matcher :get_processes_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :sys) :process) :get_processes)
        # PATTERN
        #
        # def_node_matcher :config_getenv_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :sys) :config) :getenv)
        # PATTERN
        #
        # def_node_matcher :process_open_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :sys) :process) :open)
        # PATTERN
        #
        # def_node_matcher :config_getprivs_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :sys) :config) :getprivs)
        # PATTERN
        #
        # def_node_matcher :process_getpid_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :sys) :process) :getpid)
        # PATTERN
        #
        # def_node_matcher :process_kill_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :sys) :process) :kill)
        # PATTERN
        #
        # def_node_matcher :fs_dir_rmdir_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :fs) :dir) :rmdir)
        # PATTERN
        #
        # def_node_matcher :fs_dir_mkdir_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :fs) :dir) :mkdir)
        # PATTERN
        #
        # def_node_matcher :fs_file_copy_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :fs) :file) :copy)
        # PATTERN
        #
        # def_node_matcher :config_getdrivers_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :sys) :config) :getdrivers)
        # PATTERN
        #
        # def_node_matcher :config_getuid_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :sys) :config) :getuid)
        # PATTERN
        #
        # def_node_matcher :config_getsid_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :sys) :config) :getsid)
        # PATTERN
        #
        # def_node_matcher :config_is_system_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :sys) :config) :is_system)
        # PATTERN
        #
        # def_node_matcher :fs_file_md5_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :fs) :file) :md5)
        # PATTERN
        #
        # def_node_matcher :powershell_execute_string_call?, <<~PATTERN
        #   (send (send (send nil? ...) :powershell) :execute_string)
        # PATTERN
        #
        # def_node_matcher :power_reboot_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :sys) :power) :reboot)
        # PATTERN
        #
        # def_node_matcher :processes_call?, <<~PATTERN
        #   (send (send (send (send nil? ...) :sys) :process) :processes)
        # PATTERN
        #
        # def_node_matcher :lanattacks_dhcp_reset_call?, <<~PATTERN
        #   (send (send (send nil? ...) :lanattacks) ...)
        # PATTERN


        # def on_send(node)
        #
        #   # TODO: I think an array here that just gets appended too would be the right call
        #   #   then just loop over it at the end.
        #   expression = config_sysinfo_call?(node)
        #   return unless expression
        #
        #   add_offense(node) do |corrector|
        #     corrector.replace(node, "stdapi_sys_config_sysinfo")
        #   end

          # if raligun_call?(node)
          #   dependencies_list << 'stdapi_ralilgun_*'
          # end
          #
          # if fs_dir_getwd_call?(node)
          #   dependencies_list << 'stdapi_fs_getwd'
          # end
          #
          # if fs_file_rm_call?(node)
          #   dependencies_list << 'stdapi_fs_rm'
          # end
          #
          # if appapi_app_install_call?(node)
          #   dependencies_list << 'appapi_app_install'
          # end
          #
          # if process_execute_call?(node)
          #   dependencies_list << 'stdapi_sys_process_execute'
          # end
          #
          # if fs_file_stat_call?(node)
          #   dependencies_list << 'stdapi_fs_stat'
          # end
          #
          # if get_processes_call?(node)
          #   dependencies_list << 'stdapi_sys_process_get_processes'
          # end
          #
          # if config_getenv_call?(node)
          #   dependencies_list << 'stdapi_sys_config_getenv'
          # end
          #
          # if process_open_call?(node)
          #   dependencies_list << 'stdapi_sys_process_open'
          # end
          #
          # if net_socket_create_call?(node)
          #   dependencies_list << 'stdapi_net_create'
          # end
          #
          # if config_getprivs_call?(node)
          #   dependencies_list << 'sys_config_getprivs'
          # end
          #
          # if process_getpid_call?(node)
          #   dependencies_list << 'stdapi_sys_process_getpid'
          # end
          #
          # if process_kill_call?(node)
          #   dependencies_list << 'stdapi_sys_process_kill'
          # end
          #
          # if fs_dir_rmdir_call?(node)
          #   dependencies_list << 'stdapi_fs_rmdir'
          # end
          #
          # if fs_dir_mkdir_call?(node)
          #   dependencies_list << 'stdapi_fs_mkdir'
          # end
          #
          # if fs_file_copy_call?(node)
          #   dependencies_list << 'stdapi_fs_cp'
          # end
          #
          # if config_getdrivers_call?(node)
          #   dependencies_list << 'sys_config_getdrivers'
          # end
          #
          # if config_getuid_call?(node)
          #   dependencies_list << 'sys_config_getuid'
          # end
          #
          # if config_getsid_call?(node)
          #   dependencies_list << 'sys_config_getsid'
          # end
          #
          # if config_is_system_call?(node)
          #   dependencies_list << 'sys_config_is_system'
          # end
          #
          # if fs_file_md5_call?(node)
          #   dependencies_list << 'stdapi_fs_md5'
          # end
          #
          # if powershell_execute_string_call?(node)
          #   dependencies_list << 'powershell_execute_string'
          # end
          #
          # if power_reboot_call?(node)
          #   dependencies_list << 'stdapi_sys_power_reboot'
          # end
          #
          # if processes_call?(node)
          #   dependencies_list << 'stdapi_sys_processes'
          # end
          #
          # if lanattacks_dhcp_reset_call?(node)
          #   dependencies_list << 'lanattacks_*'
          # end


          # add_offense(node) do |corrector|
          #   corrector.replace(node, "#{dependencies_list}")
          # end
#         end
#       end
#     end
#   end
# end

# TODO: Code needs to identify what the module currenlty has:
#       IF modulde has an initialise method and info already in place, add the following code
# ```
# 'Compat' => {
#           'Meterpreter' => {
#             'Commands' => %w[
#               core_channel_*
#               stdapi_fs_stat
#               stdapi_fs_rm
#               stdapi_fs_rmdir
#               stdapi_fs_pwd
#               stdapi_fs_shell_command_token
#             ]
# ```
#
# OR
#
# TODO: IF modulde has an NO initialise method add the following code -- SORTED AND UNIQUE list
# ```
#   def initialize(info = {})
#     super(
#       update_info(
#         info,
#         'Compat' => {
#           'Meterpreter' => {
#             'Commands' => %w[
#               core_channel_*
#               stdapi_fs_stat
#               stdapi_fs_rm
#               stdapi_fs_rmdir
#               stdapi_fs_pwd
#               stdapi_fs_shell_command_token
#             ]
#           }
#         }
#       )
#     )

# TODO: List of calls I'm unsure what api needs to be called/I dont believe need to be called :
#   - session.core.load_library
#   - session.ext.aliases.include
#   - session.fs.file.open
#   - session.type.eql
#   - session.ext.aliases.include
#   - client.core.use
#   - session.fs.file.new
#   - session.tunnel_peer.split
