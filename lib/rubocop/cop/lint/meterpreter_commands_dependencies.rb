module RuboCop
  module Cop
    module Lint
      class MeterpreterCommandDependencies < Base
        extend AutoCorrector
        include Alignment

        # TODO:
        #   - reorder tests so they gradually build up in complexity
        #   - test for when there is no method calls being made, so nothing is added in that case
        #   - scenario where a module has no method calls but the compat was already present within the module
        #   - handle stripping of whitespace if calls have been removed
        #   - Make test to handle modules - lib/msf/core/post/process.rb
        #   - implement a stack to handle multiple instance where we have multiple classes/modules , big hint Array
        #   - fix matcher for file stat - currently have two variations, one for with and without a trailing method call
        #   - fix matcher for process with a method call without parenthesis
        #   - ** Fix issues where some commas && comments are being added after compat hash
        #
        #   - add tests for modules without info
        #   - add tests for modules/exploits/linux/local/abrt_raceabrt_priv_esc.rb - calls not being added to compat - ** Working on tests **
        #   - add tests for modules/exploits/linux/local/bash_profile_persistence.rb - removing an option instead off appending
        #
        #  - Potenial problem child - fileformat/mswin_tiff_overflow.rb
        #

        MSG = 'Convert meterpreter api calls into meterpreter command dependencies.'.freeze
        MISSING_METHOD_CALL_FOR_COMMAND_MSG = 'Compatibility command does not have an associated method call.'
        COMMAND_DUPLICATED_MSG = 'Command duplicated.'

        def_node_matcher :find_nested_update_info_node, <<~PATTERN
          (def :initialize _args (begin (super (send nil? {:update_info :merge_info} (lvar :info) $(hash ...))) ...))
        PATTERN

        def_node_matcher :find_update_info_node, <<~PATTERN
          (def :initialize _args (super (send nil? {:update_info :merge_info} (lvar :info) $(hash ...)) ...))
        PATTERN

        def_node_matcher :find_nested_info_node, <<~PATTERN
          (def :initialize _args (super $(hash ...) ...))
        PATTERN

        def_node_matcher :find_info_node, <<~PATTERN
          (def :initialize _args (begin (super $(hash ...)) ...))
        PATTERN

        # Matchers for identifying if the code already has an initialise etc.
        # TODO: Create matchers to identify where I can add my list of requirements
        def_node_matcher :find_command_array_node, <<~PATTERN
          (hash (pair (str "Commands") $(array ...)))
        PATTERN

        def_node_matcher :initialize_present?, <<~PATTERN
          (def :initialize __)
        PATTERN

        def_node_matcher :super_present?, <<~PATTERN
          (begin (zsuper) ...)
        PATTERN

        # Matchers for meterpreter API calls
        def_node_matcher :file_rm_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :file) :rm _)
        PATTERN

        def_node_matcher :file_ls_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :file) :ls _)
        PATTERN

        def_node_matcher :net_create_socket_call?, <<~PATTERN
          (send (send (send (send nil? ...) :net) :socket) :create)
        PATTERN

        def_node_matcher :registry_splitkey_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :registry) :splitkey _*)
        PATTERN

        def_node_matcher :registry_config_getprivs_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :config) :getprivs)
        PATTERN

        def_node_matcher :registry_load_key_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :registry) :load_key _*)
        PATTERN

        def_node_matcher :registry_unload_key_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :registry) :unload_key _*)
        PATTERN

        def_node_matcher :registry_create_key_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :registry) :create_key _*)
        PATTERN

        def_node_matcher :registry_open_key_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :registry) :open_key _*)
        PATTERN

        def_node_matcher :registry_delete_key_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :registry) :delete_key _*)
        PATTERN

        def_node_matcher :registry_enum_key_direct_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :registry) :enum_key_direct _*)
        PATTERN

        def_node_matcher :registry_enum_value_direct_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :registry) :enum_value_direct _*)
        PATTERN

        def_node_matcher :registry_query_value_direct_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :registry) :query_value_direct _*)
        PATTERN

        def_node_matcher :registry_set_value_direct_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :registry) :set_value_direct _*)
        PATTERN

        def_node_matcher :registry_type2str_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :registry) :type2str _*)
        PATTERN

        def_node_matcher :registry_check_key_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :registry) :check_key_exists _*)
        PATTERN

        def_node_matcher :fs_dir_getwd_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :dir) :getwd)
        PATTERN

        def_node_matcher :appapi_app_install_call?, <<~PATTERN
          (send (send (send nil? ...) :appapi) :app_install _*)
        PATTERN

        def_node_matcher :fs_file_stat_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :file) :stat _*)
        PATTERN

        def_node_matcher :fs_file_stat_trailing_method_call?, <<~PATTERN
          (send (send (send (send (send nil? ...) :fs) :file) :stat _*) _)
        PATTERN

        def_node_matcher :get_sysinfo_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :config) :sysinfo _*)
        PATTERN

        def_node_matcher :config_getenv_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :config) :getenv _*)
        PATTERN

        def_node_matcher :fs_file_copy_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :file) :copy _*)
        PATTERN

        def_node_matcher :railgun_call?, <<~PATTERN
          (send (send (send nil? ...) :railgun) ...)
        PATTERN

        def_node_matcher :net_socket_create_call?, <<~PATTERN
          (send (send (send (send nil? ...) :net) :socket) :create)
        PATTERN

        def_node_matcher :config_getprivs_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :config) :getprivs)
        PATTERN

        def_node_matcher :fs_dir_rmdir_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :dir) :rmdir)
        PATTERN

        def_node_matcher :fs_dir_mkdir_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :dir) :mkdir _*)
        PATTERN

        def_node_matcher :config_getdrivers_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :config) :getdrivers)
        PATTERN

        def_node_matcher :config_getuid_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :config) :getuid)
        PATTERN

        def_node_matcher :fs_file_new_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :file) :new _*)
        PATTERN

        def_node_matcher :config_getsid_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :config) :getsid)
        PATTERN

        def_node_matcher :config_is_system_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :config) :is_system)
        PATTERN

        def_node_matcher :fs_file_md5_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :file) :md5 _*)
        PATTERN

        def_node_matcher :powershell_execute_string_call?, <<~PATTERN
          (send (send (send nil? ...) :powershell) :execute_string)
        PATTERN

        def_node_matcher :power_reboot_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :power) :reboot)
        PATTERN

        def_node_matcher :lanattacks_dhcp_reset_call?, <<~PATTERN
          (send (send (send nil? ...) :lanattacks) ...)
        PATTERN

        def_node_matcher :android_activity_start_call?, <<~PATTERN
          (send (send (send nil? ...) :android) :activity_start _*)
        PATTERN

        def_node_matcher :fs_download_file_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :file) :download_file _*)
        PATTERN

        def_node_matcher :net_resolve_host_call?, <<~PATTERN
          (send (send (send (send nil? ...) :net) :resolve) :resolve_host _*)
        PATTERN

        def_node_matcher :fs_file_separator_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :file) :separator)
        PATTERN

        def_node_matcher :fs_file_exist_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :file) :exist? _*)
        PATTERN

        def_node_matcher :fs_upload_file_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :file) :upload_file _*)
        PATTERN

        def_node_matcher :fs_file_search_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :file) :search _*)
        PATTERN

        def_node_matcher :android_wlan_geolocate_call?, <<~PATTERN
          (send (send (send nil? ...) :android) :wlan_geolocate)
        PATTERN

        def_node_matcher :net_config_respond_to_call?, <<~PATTERN
          (send (send (send (send nil? ...) :net) :config) :respond_to? _*)
        PATTERN

        def_node_matcher :webcam_call?, <<~PATTERN
          (send (send (send nil? ...) :webcam) ...)
        PATTERN

        def_node_matcher :espia_image_get_dev_screen_call?, <<~PATTERN
          (send (send (send nil? ...) :espia) :espia_image_get_dev_screen)
        PATTERN

        def_node_matcher :android_set_wallpaper_call?, <<~PATTERN
          (send (send (send nil? ...) :android) :set_wallpaper _*)
        PATTERN

        def_node_matcher :sys_config_steal_token_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :config) :steal_token _*)
        PATTERN

        def_node_matcher :sys_config_revert_to_self_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :config) :revert_to_self)
        PATTERN

        def_node_matcher :net_config_each_route_call?, <<~PATTERN
          (send (send (send (send nil? ...) :net) :config) :each_route)
        PATTERN

        def_node_matcher :net_config_each_interface_call?, <<~PATTERN
          (send (send (send (send nil? ...) :net) :config) :each_interface)
        PATTERN

        def_node_matcher :fs_foreach_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :dir) :foreach _*)
        PATTERN

        def_node_matcher :fs_pwd_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :dir) :pwd)
        PATTERN

        def_node_matcher :priv_getsystem_args_call?, <<~PATTERN
          (send (send (send nil? ...) :priv) :getsystem _*)
        PATTERN

        def_node_matcher :kiwi_golden_ticket_create_call?, <<~PATTERN
          (send (send (send nil? ...) :kiwi) :golden_ticket_create _*)
        PATTERN

        def_node_matcher :kiwi_kerberos_ticket_use_call?, <<~PATTERN
          (send (send (send nil? ...) :kiwi) :kerberos_ticket_use _*)
        PATTERN

        def_node_matcher :priv_sam_hashes_call?, <<~PATTERN
          (send (send (send nil? ...) :priv) :sam_hashes)
        PATTERN

        def_node_matcher :incognito_list_tokens_call?, <<~PATTERN
          (send (send (send nil? ...) :incognito) :incognito_list_tokens _*)
        PATTERN

        def_node_matcher :fs_entries_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :dir) :entries _*)
        PATTERN

        def_node_matcher :kiwi_get_debug_privilege_call?, <<~PATTERN
          (send (send (send nil? ...) :kiwi) :get_debug_privilege)
        PATTERN

        def_node_matcher :kiwi_creds_all_call?, <<~PATTERN
          (send (send (send nil? ...) :kiwi) :creds_all)
        PATTERN

        def_node_matcher :sys_config_is_system_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :config) :is_system?)
        PATTERN

        def_node_matcher :extapi_wmi_query_call?, <<~PATTERN
          (send (send (send (send nil? ...) :extapi) :wmi) :query _*)
        PATTERN

        def_node_matcher :sys_registry_open_remote_key_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :registry) :open_remote_key _*)
        PATTERN

        def_node_matcher :priv_getsystem_call?, <<~PATTERN
          (send (send (send nil? ...) :priv) :getsystem)
        PATTERN

        def_node_matcher :extapi_adsi_domain_query_call?, <<~PATTERN
          (send (send (send (send nil? ...) :extapi) :adsi) :domain_query _*)
        PATTERN

        def_node_matcher :priv_fs_get_file_mace_call?, <<~PATTERN
        (send (send (send (send nil? ...) :priv) :fs) :get_file_mace _*)
        PATTERN

        def_node_matcher :priv_fs_set_file_mace_call?, <<~PATTERN
          (send (send (send (send nil? ...) :priv) :fs) :set_file_mace _*)
        PATTERN

        def_node_matcher :extapi_pageant_forward_call?, <<~PATTERN
          (send (send (send (send nil? ...) :extapi) :pageant) :forward _*)
        PATTERN

        def_node_matcher :lanattacks_dhcp_reset_call?, <<~PATTERN
          (send (send (send (send nil? ...) :lanattacks) :dhcp) :reset)
        PATTERN

        def_node_matcher :lanattacks_dhcp_load_options_call?, <<~PATTERN
          (send (send (send (send nil? ...) :lanattacks) :dhcp) :load_options _*)
        PATTERN

        def_node_matcher :lanattacks_tftp_add_file_call?, <<~PATTERN
          (send (send (send (send nil? ...) :lanattacks) :tftp) :add_file _*)
        PATTERN

        def_node_matcher :lanattacks_tftp_start_call?, <<~PATTERN
          (send (send (send (send nil? ...) :lanattacks) :tftp) :start)
        PATTERN

        def_node_matcher :lanattacks_dhcp_start_call?, <<~PATTERN
          (send (send (send (send nil? ...) :lanattacks) :dhcp) :start)
        PATTERN

        def_node_matcher :lanattacks_tftp_stop_call?, <<~PATTERN
          (send (send (send (send nil? ...) :lanattacks) :tftp) :stop)
        PATTERN

        def_node_matcher :lanattacks_dhcp_stop_call?, <<~PATTERN
          (send (send (send (send nil? ...) :lanattacks) :dhcp) :stop)
        PATTERN

        def_node_matcher :incognito_incognito_impersonate_token_call?, <<~PATTERN
          (send (send (send nil? ...) :incognito) :incognito_impersonate_token _*)
        PATTERN

        def_node_matcher :fs_file_expand_path_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :file) :expand_path _*)
        PATTERN

        def_node_matcher :peinjector_add_thread_x64_call?, <<~PATTERN
          (send (send (send nil? ...) :peinjector) :add_thread_x64 _*)
        PATTERN

        def_node_matcher :peinjector_add_thread_x86_call?, <<~PATTERN
          (send (send (send nil? ...) :peinjector) :add_thread_x86 _*)
        PATTERN

        def_node_matcher :peinjector_inject_shellcode_call?, <<~PATTERN
          (send (send (send nil? ...) :peinjector) :inject_shellcode _*)
        PATTERN

        def_node_matcher :sys_config_getenvs_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :config) :getenvs _*)
        PATTERN

        def_node_matcher :lanattacks_dhcp_log_each_call?, <<~PATTERN
          (send (send (send (send (send nil? ...) :lanattacks) :dhcp) :log) :each)
        PATTERN

        def_node_matcher :fs_dir_rmdir_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :dir) :rmdir _*)
        PATTERN

        def_node_matcher :sys_process_open_call?, <<~PATTERN
          (send (send (send (send (send nil? ...) :sys) :process) :open) ...)
        PATTERN

        def_node_matcher :sys_process_get_processes_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :process) :get_processes)
        PATTERN

        def_node_matcher :sys_process_getpid_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :process) :getpid)
        PATTERN

        def_node_matcher :sys_process_open_method_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :process) :open _*)
        PATTERN

        def_node_matcher :sys_process_kill_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :process) :kill _*)
        PATTERN

        def_node_matcher :sys_process_execute_call?, <<~PATTERN
          (send (send (send (send nil? ...) :sys) :process) :execute _*)
        PATTERN

        def_node_matcher :sys_process_execute_without_parentheses_call?, <<~PATTERN
        (send (send (send (send nil? ...) :sys) :process) :execute)
        PATTERN

        def_node_matcher :sys_process_each_process_call?, <<~PATTERN
          (send (send (send (send (send nil? ...) :sys) :process) :each_process) ...)
        PATTERN

        class StackFrame
          # Keeps track of nodes of interest
          attr_accessor :nodes
          # Keeps track of the visiting state, i.e. what we'll do next when we visit particular nodes
          attr_accessor :visiting_state

          # The list of commands identified in this stack frame
          attr_accessor :identified_commands

          def initialize
            @nodes = {}
            @visiting_state = :none
            @identified_commands = []
          end

          # The currently registered commands
          def current_commands
            commands = []
            return commands unless nodes[:commands_node]

            nodes[:commands_node].value.each_child_node do |command|
              commands << command.value
            end

            commands
          end
        end

        def on_module(node)
          enter_frame(node)
        end

        def after_module(node)
          leave_frame(node)
        end

        def on_class(node)
          enter_frame(node)
        end

        def after_class(node)
          leave_frame(node)
        end

        def enter_frame(node)
          # Frames can't be nested
          if @current_frame
            return
          end

          @current_frame = StackFrame.new
          nodes[:investigated_node] = node
        end

        def subtract_arrays_and_leave_duplicates(first, second)
          result = first.clone
          second.each do |value|
            index = result.index(value)
            if index
              result.delete_at(index)
            end
          end
          result
        end

        def leave_frame(node)
          unless nodes[:investigated_node] == node
            return
          end

          # Ensure commands are sorted and unique
          @current_frame.identified_commands = @current_frame.identified_commands.uniq.sort

          # Calculate invalid values, but leave duplicates around so that they can be highlighted as being invalid
          invalid_current_commands = subtract_arrays_and_leave_duplicates(@current_frame.current_commands, @current_frame.identified_commands)
          if invalid_current_commands.any? && nodes[:commands_node]
            nodes[:commands_node].value.each_child_node do |command_node|
              command = command_node.source
              is_missing_call = !@current_frame.identified_commands.include?(command)
              has_duplicate_calls = (
                @current_frame.current_commands.select { |c| c == command }.count > 1
              )
              if is_missing_call
                add_offense(command_node, message: MISSING_METHOD_CALL_FOR_COMMAND_MSG)
              elsif has_duplicate_calls
                add_offense(command_node, message: COMMAND_DUPLICATED_MSG)
              end
            end
          end

          if @current_frame.identified_commands.empty? && invalid_current_commands.empty?
            return
          elsif nodes[:compat_node] && nodes[:meterpreter_node] && nodes[:commands_node] && @current_frame.identified_commands == @current_frame.current_commands
            # TODO: Handle happy path
          elsif nodes[:compat_node] && nodes[:meterpreter_node] && nodes[:commands_node] && @current_frame.identified_commands != @current_frame.current_commands
            add_offense(nodes[:commands_node], &autocorrector)
          elsif nodes[:compat_node] && nodes[:meterpreter_node] && nodes[:commands_node].nil?
            add_offense(nodes[:meterpreter_node], &autocorrector)
          elsif nodes[:compat_node] && nodes[:meterpreter_node].nil? && nodes[:commands_node].nil?
            add_offense(nodes[:compat_node], &autocorrector)
          elsif  nodes[:initialize_node] && nodes[:super_node] && nodes[:info_node].nil?
            add_offense(nodes[:super_node].children.first, &autocorrector)
          elsif nodes[:compat_node].nil? && nodes[:meterpreter_node].nil? && nodes[:commands_node].nil? && !nodes[:initialize_node].nil?
            add_offense(nodes[:info_node].children.last, &autocorrector)
          elsif nodes[:initialize_node].nil?
            add_offense(nodes[:investigated_node].identifier, &autocorrector)
          else
            raise 'Fix this dummy'
          end

          @current_frame = nil
        end

        def on_def(node)
          return unless visiting_state == :none

          if initialize_present?(node)
            nodes[:initialize_node] = node
          end

          update_info_node = (
            find_update_info_node(node) ||
              find_nested_update_info_node(node) ||
              find_info_node(node) ||
              find_nested_info_node(node)
          )
          return if update_info_node.nil?
          nodes[:info_node] = update_info_node

          self.visiting_state = :looking_for_hash_keys
        end

        def after_def(_node)
          if visiting_state == :looking_for_hash_keys
            self.visiting_state = :finished
          end
        end

        def on_begin(node)
          if super_present?(node)
            nodes[:super_node] = node
          end
        end

        def visiting_state
          @current_frame&.visiting_state || :none
        end

        def visiting_state=(state)
          @current_frame.visiting_state = state
        end

        def nodes
          @current_frame.nodes
        end

        def on_pair(node)
          return unless visiting_state == :looking_for_hash_keys
          if node.key.value == 'Compat'
            nodes[:compat_node] = node
          elsif node.key.value == 'Meterpreter'
            nodes[:meterpreter_node] = node
          elsif node.key.value == 'Commands'
            nodes[:commands_node] = node
          end
        end

        def hash_arg?(node)
          node.type == :hash
        end

        def on_send(node)
          mappings = [
            {
              matcher: method(:file_rm_call?),
              command: 'stdapi_fs_rm'
            },
            {
              matcher: method(:file_ls_call?),
              command: 'stdapi_fs_ls'
            },
            {
              matcher: method(:net_create_socket_call?),
              command: 'net_socket_create'
            },
            {
              matcher: method(:registry_splitkey_call?),
              command: 'stdapi_registry_splitkey'
            },
            {
              matcher: method(:registry_config_getprivs_call?),
              command: 'stdapi_registry_config_getprivs'
            },
            {
              matcher: method(:registry_load_key_call?),
              command: 'stdapi_registry_load_key'
            },
            {
              matcher: method(:registry_unload_key_call?),
              command: 'stdapi_registry_unload_key'
            },
            {
              matcher: method(:registry_create_key_call?),
              command: 'stdapi_registry_create_key'
            },
            {
              matcher: method(:registry_open_key_call?),
              command: 'stdapi_registry_open_key'
            },
            {
              matcher: method(:registry_delete_key_call?),
              command: 'stdapi_registry_delete_key'
            },
            {
              matcher: method(:registry_enum_key_direct_call?),
              command: 'stdapi_registry_enum_key_direct'
            },
            {
              matcher: method(:registry_enum_value_direct_call?),
              command: 'stdapi_registry_enum_value_direct'
            },
            {
              matcher: method(:registry_query_value_direct_call?),
              command: 'stdapi_registry_query_value_direct'
            },
            {
              matcher: method(:registry_set_value_direct_call?),
              command: 'stdapi_registry_set_value_direct'
            },
            {
              matcher: method(:registry_type2str_call?),
              command: 'stdapi_registry_type2str'
            },
            {
              matcher: method(:registry_check_key_call?),
              command: 'stdapi_registry_check_key_exists'
            },
            {
              matcher: method(:fs_dir_getwd_call?),
              command: 'stdapi_fs_getwd'
            },
            {
              matcher: method(:appapi_app_install_call?),
              command: 'appapi_app_install'
            },
            {
              matcher: method(:fs_file_stat_call?),
              command: 'stdapi_fs_stat'
            },
            {
              matcher: method(:fs_file_stat_trailing_method_call?),
              command: 'stdapi_fs_stat'
            },
            {
              matcher: method(:get_sysinfo_call?),
              command: 'stdapi_sys_config_sysinfo'
            },
            {
              matcher: method(:config_getenv_call?),
              command: 'stdapi_sys_config_getenv'
            },
            {
              matcher: method(:fs_file_copy_call?),
              command: 'stdapi_fs_copy'
            },
            {
              matcher: method(:railgun_call?),
              command: 'stdapi_railgun_*'
            },
            {
              matcher: method(:net_socket_create_call?),
              command: 'stdapi_net_create'
            },
            {
              matcher: method(:config_getprivs_call?),
              command: 'stdapi_sys_getprivs'
            },
            {
              matcher: method(:fs_dir_rmdir_call?),
              command: 'stdapi_fs_rmdir'
            },
            {
              matcher: method(:fs_dir_mkdir_call?),
              command: 'stdapi_fs_mkdir'
            },
            {
              matcher: method(:config_getdrivers_call?),
              command: 'stdapi_sys_getdrivers'
            },
            {
              matcher: method(:config_getuid_call?),
              command: 'stdapi_sys_getuid'
            },
            {
              matcher: method(:fs_file_new_call?),
              command: 'stdapi_fs_new'
            },
            {
              matcher: method(:config_getsid_call?),
              command: 'stdapi_sys_config_getsid'
            },
            {
              matcher: method(:config_is_system_call?),
              command: 'stdapi_sys_is_system'
            },
            {
              matcher: method(:fs_file_md5_call?),
              command: 'stdapi_fs_md5'
            },
            {
              matcher: method(:powershell_execute_string_call?),
              command: 'powershell_execute_string'
            },
            {
              matcher: method(:power_reboot_call?),
              command: 'stdapi_sys_power_reboot'
            },
            {
              matcher: method(:lanattacks_dhcp_reset_call?),
              command: 'lanattacks_*'
            },
            {
              matcher: method(:android_activity_start_call?),
              command: 'android_activity_start'
            },
            {
              matcher: method(:fs_download_file_call?),
              command: 'stdapi_fs_download_file'
            },
            {
              matcher: method(:net_resolve_host_call?),
              command: 'stdapi_net_resolve_host'
            },
            {
              matcher: method(:fs_file_separator_call?),
              command: 'stdapi_fs_separator'
            },
            {
              matcher: method(:fs_file_exist_call?),
              command: 'stdapi_fs_exist?'
            },
            {
              matcher: method(:fs_upload_file_call?),
              command: 'stdapi_fs_upload_file'
            },
            {
              matcher: method(:fs_file_search_call?),
              command: 'stdapi_fs_search'
            },
            {
              matcher: method(:android_wlan_geolocate_call?),
              command: 'android_wlan_geolocate'
            },
            {
              matcher: method(:net_config_respond_to_call?),
              command: 'stdapi_net_respond_to'
            },
            {
              matcher: method(:webcam_call?),
              command: 'stdapi_webcam_*'
            },
            {
              matcher: method(:espia_image_get_dev_screen_call?),
              command: 'espia_espia_image_get_dev_screen'
            },
            {
              matcher: method(:android_set_wallpaper_call?),
              command: 'android_set_wallpaper'
            },
            {
              matcher: method(:sys_config_steal_token_call?),
              command: 'stdapi_sys_steal_token'
            },
            {
              matcher: method(:sys_config_revert_to_self_call?),
              command: 'stdapi_sys_reverevert_to_self'
            },
            {
              matcher: method(:net_config_each_route_call?),
              command: 'stdapi_net_each_route'
            },
            {
              matcher: method(:net_config_each_interface_call?),
              command: 'stdapi_net_each_interface'
            },
            {
              matcher: method(:fs_foreach_call?),
              command: 'stdapi_fs_foreach'
            },
            {
              matcher: method(:fs_pwd_call?),
              command: 'stdapi_fs_pwd'
            },
            {
              matcher: method(:priv_getsystem_call?),
              command: 'priv_getsystem'
            },
            {
              matcher: method(:kiwi_golden_ticket_create_call?),
              command: 'kiwi_golden_ticket_create'
            },
            {
              matcher: method(:kiwi_kerberos_ticket_use_call?),
              command: 'kiwi_kerberos_ticket_use'
            },
            {
              matcher: method(:priv_sam_hashes_call?),
              command: 'priv_sam_hashes'
            },
            {
              matcher: method(:incognito_list_tokens_call?),
              command: 'incognito_incognito_list_tokens'
            },
            {
              matcher: method(:fs_entries_call?),
              command: 'stdapi_fs_entries'
            },
            {
              matcher: method(:kiwi_get_debug_privilege_call?),
              command: 'kiwi_get_debug_privilege'
            },
            {
              matcher: method(:kiwi_creds_all_call?),
              command: 'kiwi_creds_all'
            },
            {
              matcher: method(:sys_config_is_system_call?),
              command: 'stdapi_sys_is_system'
            },
            {
              matcher: method(:extapi_wmi_query_call?),
              command: 'extapi_wmi_query'
            },
            {
              matcher: method(:sys_registry_open_remote_key_call?),
              command: 'stdapi_sys_open_remote_key'
            },
            {
              matcher: method(:priv_getsystem_args_call?),
              command: 'priv_getsystem'
            },
            {
              matcher: method(:extapi_adsi_domain_query_call?),
              command: 'extapi_adsi_domain_query'
            },
            {
              matcher: method(:priv_fs_get_file_mace_call?),
              command: 'priv_get_file_mace'
            },
            {
              matcher: method(:priv_fs_set_file_mace_call?),
              command: 'priv_set_file_mace'
            },
            {
              matcher: method(:extapi_pageant_forward_call?),
              command: 'extapi_pageant_forward'
            },
            {
              matcher: method(:lanattacks_dhcp_reset_call?),
              command: 'lanattacks_dhcp_reset'
            },
            {
              matcher: method(:lanattacks_dhcp_load_options_call?),
              command: 'lanattacks_dhcp_load_options'
            },
            {
              matcher: method(:lanattacks_tftp_add_file_call?),
              command: 'lanattacks_tftp_add_file'
            },
            {
              matcher: method(:lanattacks_tftp_start_call?),
              command: 'lanattacks_tftp_start'
            },
            {
              matcher: method(:lanattacks_dhcp_start_call?),
              command: 'lanattacks_dhcp_start'
            },
            {
              matcher: method(:lanattacks_tftp_stop_call?),
              command: 'lanattacks_tftp_stop'
            },
            {
              matcher: method(:lanattacks_dhcp_stop_call?),
              command: 'lanattacks_dhcp_stop'
            },
            {
              matcher: method(:incognito_incognito_impersonate_token_call?),
              command: 'incognito_incognito_impersonate_token'
            },
            {
              matcher: method(:fs_file_expand_path_call?),
              command: 'stdapi_fs_expand_path'
            },
            {
              matcher: method(:peinjector_add_thread_x64_call?),
              command: 'peinjector_add_thread_x64'
            },
            {
              matcher: method(:peinjector_add_thread_x86_call?),
              command: 'peinjector_add_thread_x86'
            },
            {
              matcher: method(:peinjector_inject_shellcode_call?),
              command: 'peinjector_inject_shellcode'
            },
            {
              matcher: method(:sys_config_getenvs_call?),
              command: 'stdapi_sys_getenvs'
            },
            {
              matcher: method(:lanattacks_dhcp_log_each_call?),
              command: 'lanattacks_dhcp_log'
            },
            {
              matcher: method(:fs_dir_rmdir_call?),
              command: 'stdapi_fs_rmdir'
            },
            {
              matcher: method(:sys_process_open_call?),
              command: 'stdapi_sys_open'
            },
            {
              matcher: method(:sys_process_get_processes_call?),
              command: 'stdapi_sys_get_processes'
            },
            {
              matcher: method(:sys_process_getpid_call?),
              command: 'stdapi_sys_getpid'
            },
            {
              matcher: method(:sys_process_open_method_call?),
              command: 'stdapi_sys_open'
            },
            {
              matcher: method(:sys_process_kill_call?),
              command: 'stdapi_sys_kill'
            },
            {
              matcher: method(:sys_process_execute_call?),
              command: 'stdapi_sys_execute'
            },
            {
              matcher: method(:sys_process_execute_without_parentheses_call?),
              command: 'stdapi_sys_execute'
            },
            {
              matcher: method(:sys_process_each_process_call?),
              command: 'stdapi_sys_each_process'
            },
          ]

          mappings.each do |mapping|
            matcher = mapping[:matcher]
            command = mapping[:command]
            if matcher.call(node)
              unless @current_frame.identified_commands.include?(command)
                @current_frame.identified_commands << command
              end
              # Add an offense, but don't provide an autocorrect.
              # There will be a final autocorrect to fix all issues
              unless @current_frame.current_commands.include?(command)
                add_offense(node)
              end

              break
            end
          end
        end

        # def correction_content(node)
        #   # Whitespace formatting
        #   # condition ? if_true : if_false
        #   body = node.body if node == nodes[:investigated_node]
        #   def_whitespace = offset(body) if node == nodes[:investigated_node]
        #   super_whitespace = def_whitespace + "  " if node == nodes[:investigated_node]
        #   update_info_whitespace = super_whitespace + "  " if node == nodes[:investigated_node]
        #   info_whitespace = update_info_whitespace + "  " if node == nodes[:investigated_node] || nodes[:info_node]
        #   meterpreter_whitespace = info_whitespace + "  " if node == nodes[:info_node] || nodes[:compat_node]
        #   commands_whitespace = meterpreter_whitespace + "  " if node == nodes[:meterpreter_node]
        #   array_content_whitespace = commands_whitespace + "  " if node == nodes[:commands_node]
        #
        #   new_hash = ""
        #
        #   new_hash <<= "def initialize(info = {})\n"
        #   new_hash <<= "#{super_whitespace}super(\n"
        #   new_hash <<= "#{update_info_whitespace}update_info(\n"
        #   new_hash <<= "#{info_whitespace}info,\n"
        #   new_hash <<= "#{info_whitespace}'Compat' => {\n"
        #   new_hash <<= "#{meterpreter_whitespace}'Meterpreter' => {\n"
        #   new_hash <<= "#{commands_whitespace}'Commands' => %w[\n"
        #   new_hash <<= "#{array_content_whitespace}#{@current_frame.identified_commands.join("\n#{array_content_whitespace}")}\n"
        #   new_hash <<= "#{commands_whitespace}]\n"
        #   new_hash <<= "#{meterpreter_whitespace}}\n"
        #   new_hash <<= "#{info_whitespace}}\n"
        #   new_hash <<= "#{update_info_whitespace})\n"
        #   new_hash <<= "#{super_whitespace})\n"
        #   new_hash <<= "#{def_whitespace}end\n"
        #   new_hash <<= "\n  "
        #
        #   new_hash
        # end

        def autocorrector
          lambda do |corrector|
            # Handles modules that no longer have api calls with the code but have a commands list present
            if @current_frame.identified_commands.empty? && !@current_frame.current_commands.empty?
              # White spacing handling based of node offsets
              commands_whitespace = offset(nodes[:commands_node])
              array_content_whitespace = commands_whitespace + "  "

              # Formatting to add missing commands node when the method has a compat node & meterpreter node present
              # TODO: Use this style for the other sections, by introducing a shared method
              new_hash = "'Commands' => %w[\n"
              new_hash <<= "#{array_content_whitespace}#{@current_frame.identified_commands.join("\n#{array_content_whitespace}")}\n" unless @current_frame.identified_commands.empty?
              new_hash <<= "#{commands_whitespace}]"

              corrector.replace(nodes[:commands_node], new_hash)

            # Handles scenario where we have both compat & meterpreter hashes
            # but no commands array present within a module
              elsif nodes[:compat_node] && nodes[:meterpreter_node] && nodes[:commands_node].nil?
              meterpreter_hash_node = nodes[:meterpreter_node].children[1]

              # White spacing handling based of node offsets
              meterpreter_whitespace = offset(nodes[:meterpreter_node])
              commands_whitespace = meterpreter_whitespace + "  "
              array_content_whitespace = commands_whitespace + "  "

              # Formatting to add missing commands node when the method has a compat node & meterpreter node present
              new_hash =
                "{\n" \
                "#{commands_whitespace}'Commands' => %w[" \
                "\n#{array_content_whitespace}#{@current_frame.identified_commands.join("\n#{array_content_whitespace}")}\n" \
                "#{commands_whitespace}]\n" \
                "#{meterpreter_whitespace}}"

              corrector.replace(meterpreter_hash_node, new_hash)

              # Handles scenario when we have a compat hash, but no meterpreter hash
              # and compats array present within a module
            elsif nodes[:compat_node] && nodes[:meterpreter_node].nil? && nodes[:commands_node].nil?
              # White spacing handling based of node offsets
              compat_whitespace = offset(nodes[:compat_node])
              meterpreter_whitespace = compat_whitespace + "  "
              commands_whitespace = meterpreter_whitespace + "  "
              array_content_whitespace = commands_whitespace + "  "

              # Formatting to add missing commands node when the method has a compat node & meterpreter node present
              new_hash =
                "\n" \
                "#{meterpreter_whitespace}'Meterpreter' => {\n" \
                "#{commands_whitespace}'Commands' => %w[" \
                "\n#{array_content_whitespace}#{@current_frame.identified_commands.join("\n#{array_content_whitespace}")}\n" \
                "#{commands_whitespace}]\n" \
                "#{meterpreter_whitespace}}" \

              if !nodes[:compat_node].value.children.last.nil?
                corrector.insert_after(nodes[:compat_node].value.children.last, new_hash)
              else
                alt_new_hash = "{"
                alt_new_hash << new_hash
                alt_new_hash << "\n#{compat_whitespace}}"
                corrector.replace(nodes[:compat_node].value, alt_new_hash)
              end

            elsif !nodes[:initialize_node].nil? && !nodes[:super_node].nil? && nodes[:info_node].nil?
              super_whitespace = offset(nodes[:super_node])
              compat_whitespace = super_whitespace + "  "
              meterpreter_whitespace = compat_whitespace + "  "
              commands_whitespace = meterpreter_whitespace + "  "
              array_content_whitespace = commands_whitespace + "  "

              # Formatting to add missing commands node when the method has a compat node & meterpreter node present
              new_hash =
                "\n#{compat_whitespace}'Compat' => {\n" \
                "#{meterpreter_whitespace}'Meterpreter' => {\n" \
                "#{commands_whitespace}'Commands' => %w[" \
                "\n#{array_content_whitespace}#{@current_frame.identified_commands.join("\n#{array_content_whitespace}")}\n" \
                "#{commands_whitespace}]\n" \
                "#{meterpreter_whitespace}}\n" \
                "#{compat_whitespace}}"

              corrector.insert_after(nodes[:super_node].children.first, new_hash)

              # Handles scenario when we have no compats hash, no meterpreter hash
              # and  no compats array present within the module, but we do have an initialize method present
            elsif nodes[:compat_node].nil? && nodes[:meterpreter_node].nil? && nodes[:commands_node].nil? && !nodes[:initialize_node].nil?
              # White spacing handling based of node offsets
              compat_whitespace = offset(nodes[:info_node])
              meterpreter_whitespace = compat_whitespace + "  "
              commands_whitespace = meterpreter_whitespace + "  "
              array_content_whitespace = commands_whitespace + "  "

              # Formatting to add missing commands node when the method has a compat node & meterpreter node present
              new_hash =
                ",\n#{compat_whitespace}'Compat' => {\n" \
                "#{meterpreter_whitespace}'Meterpreter' => {\n" \
                "#{commands_whitespace}'Commands' => %w[" \
                "\n#{array_content_whitespace}#{@current_frame.identified_commands.join("\n#{array_content_whitespace}")}\n" \
                "#{commands_whitespace}]\n" \
                "#{meterpreter_whitespace}}\n" \
                "#{compat_whitespace}}"

              corrector.insert_after(nodes[:info_node].children.last, new_hash)

              # Handles scenario when we have no compats hash, no meterpreter hash
              # and  no compats array present no initialize method present within the module
            elsif nodes[:compat_node].nil? && nodes[:meterpreter_node].nil? && nodes[:commands_node].nil? && nodes[:initialize_node].nil?
              # White spacing handling based of node offset
              body = nodes[:investigated_node].body
              def_whitespace = offset(body)
              super_whitespace = def_whitespace + "  "
              update_info_whitespace = super_whitespace + "  "
              info_whitespace = update_info_whitespace + "  "
              meterpreter_whitespace = info_whitespace + "  "
              commands_whitespace = meterpreter_whitespace + "  "
              array_content_whitespace = commands_whitespace + "  "

              # Formatting to add missing commands node when the method has a compat node & meterpreter node present
              new_hash =
                "def initialize(info = {})" \
                "\n#{super_whitespace}super(" \
                "\n#{update_info_whitespace}update_info(" \
                "\n#{info_whitespace}info," \
                "\n#{info_whitespace}'Compat' => {" \
                "\n#{meterpreter_whitespace}'Meterpreter' => {" \
                "\n#{commands_whitespace}'Commands' => %w[" \
                "\n#{array_content_whitespace}#{@current_frame.identified_commands.join("\n#{array_content_whitespace}")}" \
                "\n#{commands_whitespace}]" \
                "\n#{meterpreter_whitespace}}" \
                "\n#{info_whitespace}}" \
                "\n#{update_info_whitespace})" \
                "\n#{super_whitespace})" \
                "\n#{def_whitespace}end\n\n" \
                "#{def_whitespace}"
              # ^ TODO: We shouldn't need to add whitespace here to accomdoate for the subsequent run method

              corrector.insert_before(body, new_hash)

            else
              array_node = nodes[:commands_node].children[1]
              commands_whitespace = offset(nodes[:commands_node])
              array_whitespace = commands_whitespace + "  "

              new_array = "%w[\n#{array_whitespace}#{@current_frame.identified_commands.join("\n#{array_whitespace}")}\n#{commands_whitespace}]"
              corrector.replace(array_node, new_array)
            end
          end
        end
      end
    end
  end
end
