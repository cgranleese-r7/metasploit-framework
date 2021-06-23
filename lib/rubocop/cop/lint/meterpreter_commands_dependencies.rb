module RuboCop
  module Cop
    module Lint
      class MeterpreterCommandDependencies < Base
        extend AutoCorrector
        include Alignment

        # TODO:
        #   - reorder tests so they gradually build up in complexity
        #   - test for when there is no method calls being made, so nothing bes added in that case
        #   - scenario where a module has no method calls but the compat was already present within the module
        #   - handle stripping of whitespace if calls have been removed
        #   - Make test to handle modules - lib/msf/core/post/process.rb
        #   - implement a stack to handle multiple instance where we have multiple classes/modules , big hint Array
        #
        #  - Potenial problem child - fileformat/mswin_tiff_overflow.rb
        #
        #   List of calls I'm unsure what api needs to be called/I dont believe need to be called :
        #   - session.core.load_library
        #   - session.ext.aliases.include
        #   - session.fs.file.open
        #   - session.type.eql
        #   - session.ext.aliases.include
        #   - client.core.use
        #   - session.fs.file.new
        #   - session.tunnel_peer.split

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
          (hash (pair (str "Commands") $(array ...)))
        PATTERN

        def_node_matcher :initialize_present?, <<~PATTERN
          (def :initialize __)
        PATTERN

        # Matchers for meterpreter API calls
        def_node_matcher :file_rm_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :file) :rm)
        PATTERN

        def_node_matcher :file_ls_call?, <<~PATTERN
          (send (send (send (send nil? ...) :fs) :file) :ls)
        PATTERN

        def_node_matcher :sys_get_processes?, <<~PATTERN
          (send
            (send
              (send
                (send nil? :session) :sys) :process) :get_processes)
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
            return commands unless nodes[:command_node]

            nodes[:command_node].value.each_child_node do |command|
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
          @current_frame = StackFrame.new
          nodes[:investigated_node] = node
        end

        def leave_frame(_node)
          # Ensure commands are sorted and unique
          @current_frame.identified_commands = @current_frame.identified_commands.uniq.sort

          if nodes[:compat_node] && nodes[:meterpreter_node] && nodes[:command_node] && @current_frame.identified_commands == @current_frame.current_commands
            # TODO: Handle happy path
          elsif nodes[:compat_node] && nodes[:meterpreter_node] && nodes[:command_node] && @current_frame.identified_commands != @current_frame.current_commands
            add_offense(nodes[:command_node], &autocorrector)
          elsif nodes[:compat_node] && nodes[:meterpreter_node] && nodes[:command_node].nil?
            add_offense(nodes[:meterpreter_node], &autocorrector)
          elsif nodes[:compat_node] && nodes[:meterpreter_node].nil? && nodes[:command_node].nil?
            add_offense(nodes[:compat_node], &autocorrector)
          elsif nodes[:compat_node].nil? && nodes[:meterpreter_node].nil? && nodes[:command_node].nil? && !nodes[:initialize_node].nil?
            add_offense(nodes[:end_of_info_node], &autocorrector)
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

          update_info_node = find_update_info_node(node) || find_nested_update_info_node(node)
          return if update_info_node.nil?

          self.visiting_state = :looking_for_hash
        end

        def after_def(_node)
          @state = :finished
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

        def on_hash(node)
          return unless visiting_state == :looking_for_hash
          if node.parent.children[1] == :update_info
            nodes[:end_of_info_node] = node.children.last
            self.visiting_state = :looking_for_hash_keys
          end
        end

        def on_pair(node)
          return unless visiting_state == :looking_for_hash_keys
          if node.key.value == 'Compat'
            nodes[:compat_node] = node
          elsif node.key.value == 'Meterpreter'
            nodes[:meterpreter_node] = node
          elsif node.key.value == 'Commands'
            nodes[:command_node] = node
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
              matcher: method(:sys_get_processes?),
              command: 'stdapi_sys_process_*'
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

        def autocorrector
          lambda do |corrector|
            # Handles scenario where we have both compat & meterpreter hashes
            # but no commands array present within a module
            if nodes[:compat_node] && nodes[:meterpreter_node] && nodes[:command_node].nil?
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

              # Handles scenario when we have a compats hash, but no meterpreter hash
              # and compats array present within a module
            elsif nodes[:compat_node] && nodes[:meterpreter_node].nil? && nodes[:command_node].nil?
              compat_hash_node = nodes[:compat_node].children[1]

              # White spacing handling based of node offsets
              compat_whitespace = offset(nodes[:compat_node])
              meterpreter_whitespace = compat_whitespace + "  "
              commands_whitespace = meterpreter_whitespace + "  "
              array_content_whitespace = commands_whitespace + "  "

              # Formatting to add missing commands node when the method has a compat node & meterpreter node present
              new_hash =
                "{\n" \
                "#{meterpreter_whitespace}'Meterpreter' => {\n" \
                "#{commands_whitespace}'Commands' => %w[" \
                "\n#{array_content_whitespace}#{@current_frame.identified_commands.join("\n#{array_content_whitespace}")}\n" \
                "#{commands_whitespace}]\n" \
                "#{meterpreter_whitespace}}\n" \
                "#{compat_whitespace}}"

              corrector.replace(compat_hash_node, new_hash)

              # Handles scenario when we have no compats hash, no meterpreter hash
              # and  no compats array present within the module, but we do have an initialize method present
            elsif nodes[:compat_node].nil? && nodes[:meterpreter_node].nil? && nodes[:command_node].nil? && !nodes[:initialize_node].nil?
              # White spacing handling based of node offsets
              compat_whitespace = offset(nodes[:end_of_info_node])
              meterpreter_whitespace = compat_whitespace + "  "
              commands_whitespace = meterpreter_whitespace + "  "
              array_content_whitespace = commands_whitespace + "  "

              # Formatting to add missing commands node when the method has a compat node & meterpreter node present
              test_new_hash =
                ",\n#{compat_whitespace}'Compat' => {\n" \
                "#{meterpreter_whitespace}'Meterpreter' => {\n" \
                "#{commands_whitespace}'Commands' => %w[" \
                "\n#{array_content_whitespace}#{@current_frame.identified_commands.join("\n#{array_content_whitespace}")}\n" \
                "#{commands_whitespace}]\n" \
                "#{meterpreter_whitespace}}\n" \
                "#{compat_whitespace}}"

              corrector.insert_after(nodes[:end_of_info_node], test_new_hash)

              # Handles scenario when we have no compats hash, no meterpreter hash
              # and  no compats array present no initialize method present within the module
            elsif nodes[:compat_node].nil? && nodes[:meterpreter_node].nil? && nodes[:command_node].nil? && nodes[:initialize_node].nil?
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
                "\n#{def_whitespace}end" \
                "\n  "

              require "pry"; binding.pry
              corrector.insert_before(body, new_hash)

            else
              array_node = nodes[:command_node].children[1]
              commands_whitespace = offset(nodes[:command_node])
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
