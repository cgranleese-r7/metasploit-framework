require 'rex/post/meterpreter/command_mapper'

module RuboCop
  module Cop
    module Lint
      class MeterpreterCommandDependencies < Base
        extend AutoCorrector
        include Alignment

        MSG = 'Convert meterpreter api calls into meterpreter command dependencies.'.freeze
        MISSING_METHOD_CALL_FOR_COMMAND_MSG = 'Compatibility command does not have an associated method call.'.freeze
        COMMAND_DUPLICATED_MSG = 'Command duplicated.'.freeze

        CLIENT_OR_SESSION = '{(lvar {:session :client}) (send nil? {:session :client})}'.freeze

        # Matchers for identifying what is current present in each module, so we can append required section at a later point
        def_node_matcher :find_nested_update_info_node, <<~PATTERN
          (def :initialize _args (begin (super (send nil? {:update_info :merge_info} (lvar :info) $(hash ...))) ...))
        PATTERN

        def_node_matcher :find_update_info_node, <<~PATTERN
          (def :initialize _args (super (send nil? {:update_info :merge_info} (lvaar :info) $(hash ...)) ...))
        PATTERN

        def_node_matcher :find_nested_info_node, <<~PATTERN
          (def :initialize _args (super $(hash ...) ...))
        PATTERN

        def_node_matcher :find_info_node, <<~PATTERN
          (def :initialize _args (begin (super $(hash ...)) ...))
        PATTERN

        def_node_matcher :find_command_array_node, <<~PATTERN
          (hash (pair (str "Commands") $(array ...)))
        PATTERN

        def_node_matcher :initialize_present?, <<~PATTERN
          (def :initialize __)
        PATTERN

        def_node_matcher :super_present?, <<~PATTERN
          (begin (zsuper) ...)
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

        # Allows us to handle scenarios of a module having multiple classes or modules present
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
          elsif nodes[:initialize_node] && nodes[:super_node] && nodes[:info_node].nil?
            add_offense(nodes[:super_node].children.first, &autocorrector)
          elsif nodes[:compat_node].nil? && nodes[:meterpreter_node].nil? && nodes[:commands_node].nil? && !nodes[:initialize_node].nil?
            add_offense(nodes[:info_node].children.last, &autocorrector)
          elsif nodes[:initialize_node].nil?
            add_offense(nodes[:investigated_node].identifier, &autocorrector)
          else
            raise 'Fix this dummy' # TODO: - handle this
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

        # Generates AST matchers based upon Meterpreter API calls.
        def node_matcher_for(api_call)
          api_call_split = api_call.split('.')
          node_matcher = '(send ' * (api_call_split.length - 1)

          if api_call_split.first == 'session' || 'client'
            api_call_split.shift
          end

          api_call_elements = api_call_split
          node_matcher << CLIENT_OR_SESSION

          api_call_elements.each_with_index do |element, index|
            if index == api_call_elements.size - 1
              node_matcher << ' :' + element + ' _*)'
            else
              node_matcher << ' :' + element + ')'
            end
          end

          NodePattern.new(node_matcher)
        end

        # Maps each Meterpreter API call to a command.
        def mappings
          return @mappings if @mappings

          # TODO: Not sure where to put these:
          #  - Need to figure out when to match core_channel_*
          wrong_command_ids = {
            net_socket_create: [
              'client.net.socket.create'
            ], # UNSURE
            stdapi_registry_splitkey: [
              'client.sys.registry.splitkey'
            ],
            stdapi_fs_download_file: [
              'session.fs.file.download_file'
            ],
            stdapi_fs_upload_file: [
              'session.fs.file.upload_file'
            ],
            stdapi_fs_new: [
              'session.fs.file.new'
            ],
            stdapi_registry_type2str: [
              'session.sys.registry.type2str'
            ],
          }

          stdapi_command_ids = {
            # STDAPI
            stdapi_fs_chdir: [
              'session.fs.dir.chdir'
            ],
            stdapi_fs_chmod: [
              'session.fs.file.chmod'
            ],
            stdapi_fs_delete_dir: [
              'session.fs.dir.rmdir',
              'client.fs.dir.rmdir'
            ],
            stdapi_fs_delete_file: [
              'session.fs.file.rm'
            ],
            stdapi_fs_file_copy: [
              'session.fs.file.copy'
            ],
            stdapi_fs_file_expand_path: [
              'client.fs.file.expand_path'
            ],
            stdapi_fs_file_move: [
              ''
            ],
            stdapi_fs_getwd: [
              'session.fs.dir.getwd',
              'client.fs.dir.getwd',
              'client.fs.dir.pwd'
            ],
            stdapi_fs_ls: [
              'session.fs.file.ls',
              'client.fs.dir.entries',
              'client.fs.dir.entries_with_info',
              'client.fs.dir.match'
            ],
            stdapi_fs_md5: [
              'client.fs.file.md5'
            ],
            stdapi_fs_mkdir: [
              'client.fs.dir.mkdir'
            ],
            stdapi_fs_search: [
              'client.fs.file.search'
            ],
            stdapi_fs_separator: [
              'session.fs.file.separator'
            ],
            stdapi_fs_stat: [
              'client.fs.file.exist?',
              'session.fs.file.stat',
              'session.fs.file.stat'
            ],
            stdapi_net_config_get_interfaces: [
              'session.net.config.each_interface',
              'session.net.config.respond_to?'
            ],
            stdapi_net_config_get_routes: [
              'client.net.config.each_route',
              'session.net.config.respond_to?(:each_route)'
            ],
            stdapi_net_resolve_host: [
              'client.net.resolve.resolve_host'
            ],
            stdapi_registry_check_key_exists: [
              'client.sys.registry.check_key_exists'
            ],
            stdapi_registry_create_key: [
              'session.sys.registry.create_key'
            ],
            stdapi_registry_delete_key: [
              'session.sys.registry.delete_key'
            ],
            stdapi_registry_enum_key_direct: [
              'client.sys.registry.enum_key_direct'
            ],
            stdapi_registry_enum_value_direct: [
              'session.sys.registry.enum_value_direct'
            ],
            stdapi_registry_load_key: [
              'session.sys.registry.load_key'
            ],
            stdapi_registry_open_key: [
              'client.sys.registry.open_key'
            ],
            stdapi_registry_open_remote_key: [
              'session.sys.registry.open_remote_key'
            ],
            stdapi_registry_query_value_direct: [
              'client.sys.registry.query_value_direct'
            ],
            stdapi_registry_set_value_direct: [
              'session.sys.registry.set_value_direct'
            ],
            stdapi_registry_unload_key: [
              'client.sys.registry.unload_key'
            ],
            stdapi_sys_config_driver_list: [
              'session.sys.config.getdrivers'
            ],
            stdapi_sys_config_getenv: [
              'session.sys.config.getenv',
              'client.sys.config.getenvs',
              'session.sys.config.getenv'
            ],
            stdapi_sys_config_getprivs: [
              'client.sys.config.getprivs'
            ],
            stdapi_sys_config_getsid: [
              'client.sys.config.is_system?',
              'session.sys.config.getsid'
            ],
            stdapi_sys_config_getuid: [
              'client.sys.config.getuid'
            ],
            stdapi_sys_config_rev2self: [
              'session.sys.config.revert_to_self'
            ],
            stdapi_sys_config_steal_token: [
              'client.sys.config.steal_token'
            ],
            stdapi_sys_config_sysinfo: [
              'client.sys.config.sysinfo'
            ],
            stdapi_sys_power_exitwindows: [
              'client.sys.power.reboot'
            ],
            stdapi_sys_process_attach: [
              'session.sys.process.open'
            ],
            stdapi_sys_process_execute: [
              'session.sys.process.execute',
              'session.sys.process.execute'
            ],
            stdapi_sys_process_get_processes: [
              'client.sys.process.get_processes',
              'session.sys.process.each_process.find'
            ],
            stdapi_sys_process_getpid: [
              'session.sys.process.getpid'
            ],
            stdapi_sys_process_kill: [
              'session.sys.process.kill'
            ],
            "stdapi_webcam_*": [
              'session.webcam'
            ],
          }
          COMMAND_ID_PRIV_ELEVATE_GETSYSTEM
          priv_command_ids = {
            priv_elevate_getsystem: [
              'session.priv.getsystem',
              'client.priv.getsystem'
            ],
            # priv__[: ]

            priv_fs_get_file_mace: [
              'client.priv.fs.get_file_mace'
            ],
            priv_fs_set_file_mace: [
              'session.priv.fs.set_file_mace'
            ],
            priv_passwd_get_sam_hashes: [
              'client.priv.sam_hashes'
            ]
          }

          extapi_command_ids = {
            extapi_adsi_domain_query: [
              'session.extapi.adsi.domain_query'
            ],
            extapi_pageant_send_query: [
              'client.extapi.pageant.forward'
            ],
            extapi_wmi_query: [
              'client.extapi.wmi.query'
            ]
          }

          android_command_ids = {
            android_activity_start: [
              'session.android.activity_start'
            ],
            android_set_wallpaper: [
              'session.android.set_wallpaper'
            ],
            android_wlan_geolocate: [
              'session.android.wlan_geolocate'
            ]
          }

          kiwi_command_ids = {
            kiwi_exec_cmd: [
              'session.kiwi.golden_ticket_create',
              'session.kiwi.kerberos_ticket_use',
              'client.kiwi.get_debug_privilege',
              'client.kiwi.creds_all'
            ]
          }

          appapi_app_install_command_ids = {
            appapi_app_install: [
              'client.appapi.app_install'
            ]
          }

          espia_command_ids = {
            espia_image_get_dev_screen: [
              'client.espia.espia_image_get_dev_screen'
            ]
          }

          incognito_command_ids = {
            incognito_impersonate_token: [
              'session.incognito.incognito_impersonate_token'
            ],
            incognito_list_tokens: [
              'session.incognito.incognito_list_tokens'
            ]
          }

          powershell_command_ids = {
            powershell_execute: [
              'session.powershell.execute_string'
            ]
          }

          lanattacks_command_ids = {
            lanattacks_add_tftp_file: [
              'session.lanattacks.tftp.add_file'
            ],
            lanattacks_dhcp_log: [
              'session.lanattacks.dhcp.log.each'
            ],
            lanattacks_reset_dhcp: [
              'client.lanattacks.dhcp.reset'
            ],
            lanattacks_set_dhcp_option: [
              'client.lanattacks.dhcp.load_options'
            ],
            lanattacks_start_dhcp: [
              'client.lanattacks.dhcp.start'
            ],
            lanattacks_start_tftp: [
              'client.lanattacks.tftp.start'
            ],
            lanattacks_stop_dhcp: [
              'client.lanattacks.dhcp.stop'
            ],
            lanattacks_stop_tftp: [
              'client.lanattacks.tftp.stop'
            ]
          }

          peinjector_command_ids = {
            peinjector_inject_shellcode: [
              'client.peinjector.add_thread_x64',
              'client.peinjector.add_thread_x86',
              'client.peinjector.inject_shellcode'
            ]
          }

          command_ids_to_expressions = {
            **wrong_command_ids,
            **stdapi_command_ids,
            **priv_command_ids,
            **extapi_command_ids,
            **android_command_ids,
            **kiwi_command_ids,
            **appapi_app_install_command_ids,
            **espia_command_ids,
            **incognito_command_ids,
            **powershell_command_ids,
            **lanattacks_command_ids,
            **peinjector_command_ids
          }

          @mappings = command_ids_to_expressions.flat_map do |command_id, expressions|
            expressions.map do |expression|
              {
                matcher: node_matcher_for(expression),
                command: [command_id.to_s]
              }
            end
          end

          @mappings

          # input.sort_by { |mapping| (Rex::Post::Meterpreter::CommandMapper.get_command_id(mapping['command'][0])  || - 1) rescue -1 }.each_with_object({}) { |map, acc| acc[map['ma tcher'].gsub(/node_matcher_for\('/, '').gsub(/'\)/, '').gsub('session', 'client')] = map['command'] }

          # input.each_with_object({}){|map, acc| keys = map["command"]; value = map["matcher"]; keys.each {|key| acc[key] ||= { 'expressions' => [], 'command_id' => -1 }; acc[key][
          # 'expressions'] << value; acc[key]['command_id'] = (::Rex::Post::Meterpreter::CommandMapper.get_command_id(key) rescue 'borked') }}.sort_by { |k, v| (::Rex::Post::Meterprete
          # r::CommandMapper.get_command_id(k) rescue -1) || - 1}.to_h.map { |k, v| [k, v['expressions'].map { |x| x.gsub("node_matcher_for('", '').gsub("')", '') }] }.to_h

          # aim = {
          #   "stdapi_fs_new" => [
          #     "client.fs.file.new",
          #     "client.fs.file.created",
          #
          #   ]
          # }

          # mappings = {
          #    "session.fs.file.new"=>["stdapi_fs_new", "stdsapi_fs_write"],
          #    "client.net.socket.create"=>["net_socket_create"],
          #    "client.sys.registry.splitkey"=>["stdapi_registry_splitkey"],
          #    "session.fs.file.download_file"=>["stdapi_fs_download_file"],
          #    "session.fs.file.upload_file"=>["stdapi_fs_upload_file"],
          #    "session.sys.registry.type2str"=>["stdapi_registry_type2str"],
          #    "session.webcam"=>["stdapi_webcam_*"],
          #    "client.railgun"=>["stdapi_railgun_*"],
          #    "session.fs.dir.chdir"=>["stdapi_fs_chdir"],
          #    "client.fs.dir.rmdir"=>["stdapi_fs_delete_dir"],
          #    "session.fs.dir.rmdir"=>["stdapi_fs_delete_dir"],
          #    "session.fs.file.rm"=>["stdapi_fs_delete_file"],
          #    "session.fs.file.copy"=>["stdapi_fs_file_copy"],
          #    "client.fs.file.expand_path"=>["stdapi_fs_file_expand_path"],
          #    "client.fs.dir.getwd"=>["stdapi_fs_getwd"],
          #    "session.fs.dir.getwd"=>["stdapi_fs_getwd"],
          #    "client.fs.dir.pwd"=>["stdapi_fs_getwd"],
          #    "client.fs.dir.entries"=>["stdapi_fs_ls"],
          #    "session.fs.file.ls"=>["stdapi_fs_ls"],
          #    "client.fs.file.md5"=>["stdapi_fs_md5"],
          #    "client.fs.dir.mkdir"=>["stdapi_fs_mkdir"],
          #    "client.fs.file.search"=>["stdapi_fs_search"],
          #    "session.fs.file.separator"=>["stdapi_fs_separator"],
          #    "session.fs.file.stat"=>["stdapi_fs_stat"],
          #    "client.fs.file.exist?"=>["stdapi_fs_stat"],
          #    "session.net.config.respond_to?"=>["stdapi_net_config_get_interfaces"],
          #    "session.net.config.each_interface"=>["stdapi_net_config_get_interfaces"],
          #    "client.net.config.each_route"=>["stdapi_net_config_get_routes"],
          #    "session.net.config.respond_to?(:each_route)"=>["stdapi_net_config_get_routes"],
          #    "client.net.resolve.resolve_host"=>["stdapi_net_resolve_host"],
          #    "client.sys.registry.check_key_exists"=>["stdapi_registry_check_key_exists"],
          #    "session.sys.registry.create_key"=>["stdapi_registry_create_key"],
          #    "session.sys.registry.delete_key"=>["stdapi_registry_delete_key"],
          #    "client.sys.registry.enum_key_direct"=>["stdapi_registry_enum_key_direct"],
          #    "session.sys.registry.enum_value_direct"=>["stdapi_registry_enum_value_direct"],
          #    "session.sys.registry.load_key"=>["stdapi_registry_load_key"],
          #    "client.sys.registry.open_key"=>["stdapi_registry_open_key"],
          #    "session.sys.registry.open_remote_key"=>["stdapi_registry_open_remote_key"],
          #    "client.sys.registry.query_value_direct"=>["stdapi_registry_query_value_direct"],
          #    "session.sys.registry.set_value_direct"=>["stdapi_registry_set_value_direct"],
          #    "client.sys.registry.unload_key"=>["stdapi_registry_unload_key"],
          #    "session.sys.config.getdrivers"=>["stdapi_sys_config_driver_list"],
          #    "session.sys.config.getenv"=>["stdapi_sys_config_getenv"],
          #    "client.sys.config.getenvs"=>["stdapi_sys_config_getenv"],
          #    "client.sys.config.getprivs"=>["stdapi_sys_config_getprivs"],
          #    "client.sys.config.is_system?"=>["stdapi_sys_config_getsid"],
          #    "session.sys.config.getsid"=>["stdapi_sys_config_getsid"],
          #    "client.sys.config.getuid"=>["stdapi_sys_config_getuid"],
          #    "session.sys.config.revert_to_self"=>["stdapi_sys_config_rev2self"],
          #    "client.sys.config.steal_token"=>["stdapi_sys_config_steal_token"],
          #    "client.sys.config.sysinfo"=>["stdapi_sys_config_sysinfo"],
          #    "client.sys.power.reboot"=>["stdapi_sys_power_exitwindows"],
          #    "session.sys.process.open"=>["stdapi_sys_process_attach"],
          #    "session.sys.process.execute"=>["stdapi_sys_process_execute"],
          #    "client.sys.process.get_processes"=>["stdapi_sys_process_get_processes"],
          #    "session.sys.process.each_process.find"=>["stdapi_sys_process_get_processes"],
          #    "session.sys.process.getpid"=>["stdapi_sys_process_getpid"],
          #    "session.sys.process.kill"=>["stdapi_sys_process_kill"],
          #    "session.priv.getsystem"=>["priv_elevate_getsystem"],
          #    "client.priv.getsystem"=>["priv_elevate_getsystem"],
          #    "client.priv.fs.get_file_mace"=>["priv_fs_get_file_mace"],
          #    "session.priv.fs.set_file_mace"=>["priv_fs_set_file_mace"],
          #    "client.priv.sam_hashes"=>["priv_passwd_get_sam_hashes"],
          #    "session.extapi.adsi.domain_query"=>["extapi_adsi_domain_query"],
          #    "client.extapi.pageant.forward"=>["extapi_pageant_send_query"],
          #    "client.extapi.wmi.query"=>["extapi_wmi_query"],
          #    "session.android.activity_start"=>["android_activity_start"],
          #    "session.android.set_wallpaper"=>["android_set_wallpaper"],
          #    "session.android.wlan_geolocate"=>["android_wlan_geolocate"],
          #    "session.kiwi.kerberos_ticket_use"=>["kiwi_exec_cmd"],
          #    "client.kiwi.creds_all"=>["kiwi_exec_cmd"],
          #    "session.kiwi.golden_ticket_create"=>["kiwi_exec_cmd"],
          #    "client.kiwi.get_debug_privilege"=>["kiwi_exec_cmd"],
          #    "client.appapi.app_install"=>["appapi_app_install"],
          #    "client.espia.espia_image_get_dev_screen"=>["espia_image_get_dev_screen"],
          #    "session.incognito.incognito_impersonate_token"=>["incognito_impersonate_token"],
          #    "session.incognito.incognito_list_tokens"=>["incognito_list_tokens"],
          #    "session.powershell.execute_string"=>["powershell_execute"],
          #    "session.lanattacks.tftp.add_file"=>["lanattacks_add_tftp_file"],
          #    "session.lanattacks.dhcp.log.each"=>["lanattacks_dhcp_log"],
          #    "client.lanattacks.dhcp.reset"=>["lanattacks_reset_dhcp"],
          #    "client.lanattacks.dhcp.load_options"=>["lanattacks_set_dhcp_option"],
          #    "client.lanattacks.dhcp.start"=>["lanattacks_start_dhcp"],
          #    "client.lanattacks.tftp.start"=>["lanattacks_start_tftp"],
          #    "client.lanattacks.dhcp.stop"=>["lanattacks_stop_dhcp"],
          #    "client.lanattacks.tftp.stop"=>["lanattacks_stop_tftp"],
          #    "client.peinjector.add_thread_x86"=>["peinjector_inject_shellcode"],
          #    "client.peinjector.add_thread_x64"=>["peinjector_inject_shellcode"],
          #    "client.peinjector.inject_shellcode"=>["peinjector_inject_shellcode"]
          #   }

          # @mappings = [
          #   {
          #     matcher: node_matcher_for('session.fs.file.rm'),
          #     command: ['stdapi_fs_delete_file']
          #   },
          #   {
          #     matcher: node_matcher_for('session.fs.file.ls'),
          #     command: ['stdapi_fs_ls']
          #   },
          #   {
          #     matcher: node_matcher_for('session.fs.dir.chdir'),
          #     command: ['stdapi_fs_chdir']
          #   },
          #   # {
          #   #   matcher: node_matcher_for('session.core'),
          #   #   command: ['core_channel_*']
          #   # },
          #   # {
          #   #   matcher: node_matcher_for(''),
          #   #   command: ['stdapi_sys_process_close']
          #   # },
          #   {
          #     matcher: node_matcher_for('client.fs.file.exist?'),
          #     command: ['stdapi_fs_stat']
          #   },
          #   {
          #     matcher: node_matcher_for('client.sys.config.is_system?'),
          #     command: ['stdapi_sys_config_getsid'] #UNSURE
          #   },
          #   {
          #     matcher: node_matcher_for('client.fs.dir.entries'),
          #     command: ['stdapi_fs_ls'] #UNSURE
          #   },
          #   {
          #     matcher: node_matcher_for('client.net.socket.create'),
          #     command: ['net_socket_create'] # UNSURE - https://github.com/rapid7/metasploit-framework/blob/3fa688e8db831cd363bc3e6d06d90ead20c2a6fd/lib/rex/post/meterpreter/extensions/stdapi/net/socket.rb#L86
          #   },
          #   {
          #     matcher: node_matcher_for('client.sys.registry.splitkey'),
          #     command: ['stdapi_registry_splitkey'] # UNSURE - https://github.com/rapid7/metasploit-framework/blob/3fa688e8db831cd363bc3e6d06d90ead20c2a6fd/lib/rex/post/meterpreter/extensions/stdapi/sys/registry.rb#L420
          #   },
          #   {
          #     matcher: node_matcher_for('session.sys.registry.load_key'),
          #     command: ['stdapi_registry_load_key']
          #   },
          #   {
          #     matcher: node_matcher_for('client.sys.registry.unload_key'),
          #     command: ['stdapi_registry_unload_key']
          #   },
          #   {
          #     matcher: node_matcher_for('session.sys.registry.create_key'),
          #     command: ['stdapi_registry_create_key']
          #   },
          #   {
          #     matcher: node_matcher_for('client.sys.registry.open_key'),
          #     command: ['stdapi_registry_open_key']
          #   },
          #   {
          #     matcher: node_matcher_for('session.sys.registry.delete_key'),
          #     command: ['stdapi_registry_delete_key']
          #   },
          #   {
          #     matcher: node_matcher_for('client.sys.registry.enum_key_direct'),
          #     command: ['stdapi_registry_enum_key_direct']
          #   },
          #   {
          #     matcher: node_matcher_for('session.sys.registry.enum_value_direct'),
          #     command: ['stdapi_registry_enum_value_direct']
          #   },
          #   {
          #     matcher: node_matcher_for('client.sys.registry.query_value_direct'),
          #     command: ['stdapi_registry_query_value_direct']
          #   },
          #   {
          #     matcher: node_matcher_for('session.sys.registry.set_value_direct'),
          #     command: ['stdapi_registry_set_value_direct']
          #   },
          #   {
          #     matcher: node_matcher_for('session.sys.registry.type2str'),
          #     command: ['stdapi_registry_type2str'] # UNSURE - https://github.com/rapid7/metasploit-framework/blob/3fa688e8db831cd363bc3e6d06d90ead20c2a6fd/lib/rex/post/meterpreter/extensions/stdapi/sys/registry.rb#L402
          #   },
          #   {
          #     matcher: node_matcher_for('client.sys.registry.check_key_exists'),
          #     command: ['stdapi_registry_check_key_exists']
          #   },
          #   {
          #     matcher: node_matcher_for('session.fs.dir.getwd'),
          #     command: ['stdapi_fs_getwd']
          #   },
          #   {
          #     matcher: node_matcher_for('client.appapi.app_install'),
          #     command: ['appapi_app_install']
          #   },
          #   {
          #     matcher: node_matcher_for('session.fs.file.stat'),
          #     command: ['stdapi_fs_stat']
          #   },
          #   {
          #     matcher: node_matcher_for('client.sys.config.sysinfo'),
          #     command: ['stdapi_sys_config_sysinfo']
          #   },
          #   {
          #     matcher: node_matcher_for("session.sys.config.getenv"),
          #     command: ['stdapi_sys_config_getenv']
          #   },
          #   {
          #     matcher: node_matcher_for("client.sys.config.getenvs"),
          #     command: ['stdapi_sys_config_getenv']
          #   },
          #   {
          #     matcher: node_matcher_for('session.fs.file.copy'),
          #     command: ['stdapi_fs_file_copy']
          #   },
          #   {
          #     matcher: node_matcher_for("client.railgun"),
          #     command: ['stdapi_railgun_*']
          #   },
          #   {
          #     matcher: node_matcher_for('client.sys.config.getprivs'),
          #     command: ['stdapi_sys_config_getprivs']
          #   },
          #   {
          #     matcher: node_matcher_for("session.fs.dir.rmdir"),
          #     command: ['stdapi_fs_delete_dir']
          #   },
          #   {
          #     matcher: node_matcher_for('client.fs.dir.mkdir'),
          #     command: ['stdapi_fs_mkdir']
          #   },
          #   {
          #     matcher: node_matcher_for('session.sys.config.getdrivers'),
          #     command: ['stdapi_sys_config_driver_list']
          #   },
          #   {
          #     matcher: node_matcher_for('client.sys.config.getuid'),
          #     command: ['stdapi_sys_config_getuid']
          #   },
          #   {
          #     matcher: node_matcher_for('session.fs.file.new'),
          #     command: ['stdapi_fs_new'] #UNSURE
          #   },
          #   {
          #     matcher: node_matcher_for('session.sys.config.getsid'),
          #     command: ['stdapi_sys_config_getsid']
          #   },
          #   {
          #     matcher: node_matcher_for('client.fs.file.md5'),
          #     command: ['stdapi_fs_md5']
          #   },
          #   {
          #     matcher: node_matcher_for('session.powershell.execute_string'),
          #     command: ['powershell_execute']
          #   },
          #   {
          #     matcher: node_matcher_for('client.sys.power.reboot'),
          #     command: ['stdapi_sys_power_exitwindows']
          #   },
          #   {
          #     matcher: node_matcher_for("session.android.activity_start"),
          #     command: ['android_activity_start']
          #   },
          #   {
          #     matcher: node_matcher_for('session.fs.file.download_file'), # UNSURE - https://github.com/rapid7/metasploit-framework/blob/3fa688e8db831cd363bc3e6d06d90ead20c2a6fd/lib/rex/post/meterpreter/extensions/stdapi/fs/file.rb#L349
          #     command: ['stdapi_fs_download_file']
          #   },
          #   {
          #     matcher: node_matcher_for('client.net.resolve.resolve_host'),
          #     command: ['stdapi_net_resolve_host']
          #   },
          #   {
          #     matcher: node_matcher_for('session.fs.file.separator'),
          #     command: ['stdapi_fs_separator']
          #   },
          #   {
          #     matcher: node_matcher_for('session.fs.file.stat'),
          #     command: ['stdapi_fs_stat']
          #   },
          #   {
          #     matcher: node_matcher_for("session.fs.file.upload_file"), # UNSURE - https://github.com/rapid7/metasploit-framework/blob/3fa688e8db831cd363bc3e6d06d90ead20c2a6fd/lib/rex/post/meterpreter/extensions/stdapi/fs/file.rb#L288
          #     command: ['stdapi_fs_upload_file']
          #   },
          #   {
          #     matcher: node_matcher_for('client.fs.file.search'),
          #     command: ['stdapi_fs_search']
          #   },
          #   {
          #     matcher: node_matcher_for('session.android.wlan_geolocate'),
          #     command: ['android_wlan_geolocate']
          #   },
          #   {
          #     matcher: node_matcher_for('client.net.config.each_route'),
          #     command: ['stdapi_net_config_get_routes']
          #   },
          #   {
          #     matcher: node_matcher_for('session.net.config.respond_to?(:each_route)'),
          #     command: ['stdapi_net_config_get_routes'] # UNSURE
          #   },
          #   {
          #     matcher: node_matcher_for("session.webcam"),
          #     command: ['stdapi_webcam_*']
          #   },
          #   {
          #     matcher: node_matcher_for('client.espia.espia_image_get_dev_screen'),
          #     command: ['espia_image_get_dev_screen']
          #   },
          #   {
          #     matcher: node_matcher_for('session.android.set_wallpaper'),
          #     command: ['android_set_wallpaper']
          #   },
          #   {
          #     matcher: node_matcher_for('client.sys.config.steal_token'),
          #     command: ['stdapi_sys_config_steal_token']
          #   },
          #   {
          #     matcher: node_matcher_for('session.sys.config.revert_to_self'),
          #     command: ['stdapi_sys_config_rev2self']
          #   },
          #   {
          #     matcher: node_matcher_for('session.net.config.each_interface'),
          #     command: ['stdapi_net_config_get_interfaces']
          #   },
          #   {
          #     matcher: node_matcher_for('session.net.config.respond_to?'),
          #     command: ['stdapi_net_config_get_interfaces'] #UNSURE
          #   },
          #   {
          #     matcher: node_matcher_for('client.fs.dir.getwd'),
          #     command: ['stdapi_fs_getwd']
          #   },
          #   {
          #     matcher: node_matcher_for('client.fs.dir.pwd'),
          #     command: ['stdapi_fs_getwd']
          #   },
          #   {
          #     matcher: node_matcher_for('session.priv.getsystem'),
          #     command: ['priv_elevate_getsystem']
          #   },
          #   {
          #     matcher: node_matcher_for('session.kiwi.golden_ticket_create'),
          #     command: ['kiwi_exec_cmd']
          #   },
          #   {
          #     matcher: node_matcher_for('session.kiwi.kerberos_ticket_use'),
          #     command: ['kiwi_exec_cmd']
          #   },
          #   {
          #     matcher: node_matcher_for('client.priv.sam_hashes'),
          #     command: ['priv_passwd_get_sam_hashes']
          #   },
          #   {
          #     matcher: node_matcher_for('session.incognito.incognito_list_tokens'),
          #     command: ['incognito_list_tokens']
          #   },
          #   {
          #     matcher: node_matcher_for('session.fs.file.ls'),
          #     command: ['stdapi_fs_ls']
          #   },
          #   {
          #     matcher: node_matcher_for('client.kiwi.get_debug_privilege'),
          #     command: ['kiwi_exec_cmd']
          #   },
          #   {
          #     matcher: node_matcher_for('client.kiwi.creds_all'),
          #     command: ['kiwi_exec_cmd']
          #   },
          #   {
          #     matcher: node_matcher_for('client.extapi.wmi.query'),
          #     command: ['extapi_wmi_query']
          #   },
          #   {
          #     matcher: node_matcher_for("session.sys.registry.open_remote_key"),
          #     command: ['stdapi_registry_open_remote_key']
          #   },
          #   {
          #     matcher: node_matcher_for('client.priv.getsystem'),
          #     command: ['priv_elevate_getsystem']
          #   },
          #   {
          #     matcher: node_matcher_for('session.extapi.adsi.domain_query'),
          #     command: ['extapi_adsi_domain_query']
          #   },
          #   {
          #     matcher: node_matcher_for("client.priv.fs.get_file_mace"),
          #     command: ['priv_fs_get_file_mace']
          #   },
          #   {
          #     matcher: node_matcher_for("session.priv.fs.set_file_mace"),
          #     command: ['priv_fs_set_file_mace']
          #   },
          #   {
          #     matcher: node_matcher_for('client.extapi.pageant.forward'),
          #     command: ['extapi_pageant_send_query']
          #   },
          #   {
          #     matcher: node_matcher_for('client.lanattacks.dhcp.reset'),
          #     command: ['lanattacks_reset_dhcp']
          #   },
          #   {
          #     matcher: node_matcher_for('client.lanattacks.dhcp.load_options'),
          #     command: ['lanattacks_set_dhcp_option']
          #   },
          #   {
          #     matcher: node_matcher_for('session.lanattacks.tftp.add_file'),
          #     command: ['lanattacks_add_tftp_file']
          #   },
          #   {
          #     matcher: node_matcher_for('client.lanattacks.tftp.start'),
          #     command: ['lanattacks_start_tftp']
          #   },
          #   {
          #     matcher: node_matcher_for('client.lanattacks.dhcp.start'),
          #     command: ['lanattacks_start_dhcp']
          #   },
          #   {
          #     matcher: node_matcher_for('client.lanattacks.tftp.stop'),
          #     command: ['lanattacks_stop_tftp']
          #   },
          #   {
          #     matcher: node_matcher_for('client.lanattacks.dhcp.stop'),
          #     command: ['lanattacks_stop_dhcp']
          #   },
          #   {
          #     matcher: node_matcher_for('session.incognito.incognito_impersonate_token'),
          #     command: ['incognito_impersonate_token']
          #   },
          #   {
          #     matcher: node_matcher_for('client.fs.file.expand_path'),
          #     command: ['stdapi_fs_file_expand_path']
          #   },
          #   {
          #     matcher: node_matcher_for('client.peinjector.add_thread_x64'),
          #     command: ['peinjector_inject_shellcode'] # UNSURE - https://github.com/rapid7/metasploit-framework/blob/3fa688e8db831cd363bc3e6d06d90ead20c2a6fd/lib/rex/post/meterpreter/extensions/peinjector/peinjector.rb#L34
          #   },
          #   {
          #     matcher: node_matcher_for('client.peinjector.add_thread_x86'),
          #     command: ['peinjector_inject_shellcode'] #UNSURE - https://github.com/rapid7/metasploit-framework/blob/3fa688e8db831cd363bc3e6d06d90ead20c2a6fd/lib/rex/post/meterpreter/extensions/peinjector/peinjector.rb#L34
          #   },
          #   {
          #     matcher: node_matcher_for('client.peinjector.inject_shellcode'),
          #     command: ['peinjector_inject_shellcode']
          #   },
          #   {
          #     matcher: node_matcher_for("session.sys.config.getenv"),
          #     command: ['stdapi_sys_config_getenv']
          #   },
          #   {
          #     matcher: node_matcher_for('session.lanattacks.dhcp.log.each'),
          #     command: ['lanattacks_dhcp_log']
          #   },
          #   {
          #     matcher: node_matcher_for("client.fs.dir.rmdir"),
          #     command: ['stdapi_fs_delete_dir']
          #   },
          #   {
          #     matcher: node_matcher_for('session.sys.process.open'),
          #     command: ['stdapi_sys_process_attach']
          #   },
          #   {
          #     matcher: node_matcher_for('client.sys.process.get_processes'),
          #     command: ['stdapi_sys_process_get_processes']
          #   },
          #   {
          #     matcher: node_matcher_for('session.sys.process.getpid'),
          #     command: ['stdapi_sys_process_getpid']
          #   },
          #   {
          #     matcher: node_matcher_for("session.sys.process.kill"),
          #     command: ['stdapi_sys_process_kill']
          #   },
          #   {
          #     matcher: node_matcher_for('session.sys.process.execute'),
          #     command: ['stdapi_sys_process_execute']
          #   },
          #   {
          #     matcher: node_matcher_for('session.sys.process.execute'),
          #     command: ['stdapi_sys_process_execute']
          #   },
          #   {
          #     matcher: node_matcher_for('session.sys.process.each_process.find'),
          #     command: ['stdapi_sys_process_get_processes']
          #   },
          # ]
        end

        def on_send(node)
          mappings.each do |mapping|
            matcher = mapping[:matcher]
            commands = mapping[:command]
            next unless matcher.match(node)

            commands.each do |command|
              unless @current_frame.identified_commands.include?(command)
                @current_frame.identified_commands << command
              end
            end
            # Add an offense, but don't provide an autocorrect.
            # There will be a final autocorrect to fix all issues
            commands.each do |command|
              unless @current_frame.current_commands.include?(command)
                add_offense(node)
              end
            end

            break
          end
        end

        def autocorrector
          lambda do |corrector|
            # Handles modules that no longer have api calls with the code but have a commands list present
            if @current_frame.identified_commands.empty? && !@current_frame.current_commands.empty?
              # White spacing handling based of node offsets
              commands_whitespace = offset(nodes[:commands_node])
              array_content_whitespace = commands_whitespace + '  '

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
              commands_whitespace = meterpreter_whitespace + '  '
              array_content_whitespace = commands_whitespace + '  '

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
              meterpreter_whitespace = compat_whitespace + '  '
              commands_whitespace = meterpreter_whitespace + '  '
              array_content_whitespace = commands_whitespace + '  '

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
                alt_new_hash = '{'
                alt_new_hash << new_hash
                alt_new_hash << "\n#{compat_whitespace}}"
                corrector.replace(nodes[:compat_node].value, alt_new_hash)
              end

            elsif !nodes[:initialize_node].nil? && !nodes[:super_node].nil? && nodes[:info_node].nil?
              super_whitespace = offset(nodes[:super_node])
              compat_whitespace = super_whitespace + '  '
              meterpreter_whitespace = compat_whitespace + '  '
              commands_whitespace = meterpreter_whitespace + '  '
              array_content_whitespace = commands_whitespace + '  '

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
              meterpreter_whitespace = compat_whitespace + '  '
              commands_whitespace = meterpreter_whitespace + '  '
              array_content_whitespace = commands_whitespace + '  '

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
              super_whitespace = def_whitespace + '  '
              update_info_whitespace = super_whitespace + '  '
              info_whitespace = update_info_whitespace + '  '
              meterpreter_whitespace = info_whitespace + '  '
              commands_whitespace = meterpreter_whitespace + '  '
              array_content_whitespace = commands_whitespace + '  '

              # Formatting to add missing commands node when the method has a compat node & meterpreter node present
              new_hash =
                'def initialize(info = {})' \
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
              array_whitespace = commands_whitespace + '  '

              new_array = "%w[\n#{array_whitespace}#{@current_frame.identified_commands.join("\n#{array_whitespace}")}\n#{commands_whitespace}]"
              corrector.replace(array_node, new_array)
            end
          end
        end
      end
    end
  end
end
