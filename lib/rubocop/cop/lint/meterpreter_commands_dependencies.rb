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

        def on_new_investigation
          super

          @current_frame = StackFrame.new
        end

        def on_class(node)
          # TODO: Enter into a new stack frame
          @current_frame.nodes[:class_body_node] = node.body
        end

        def on_def(node)
          return unless @current_frame.visiting_state == :none

          if initialize_present?(node)
            @current_frame.nodes[:initialize_node] = node
          end

          update_info_node = find_update_info_node(node) || find_nested_update_info_node(node)
          return if update_info_node.nil?

          @current_frame.visiting_state = :looking_for_hash
        end

        def after_def(_node)
          @state = :finished
        end

        def on_hash(node)
          return unless @current_frame.visiting_state == :looking_for_hash
          if node.parent.children[1] == :update_info
            @current_frame.nodes[:end_of_info_node] = node.children.last
            @current_frame.visiting_state = :looking_for_hash_keys
          end
        end

        def on_pair(node)
          return unless @current_frame.visiting_state == :looking_for_hash_keys
          if node.key.value == 'Compat'
            @current_frame.nodes[:compat_node] = node
          elsif node.key.value == 'Meterpreter'
            @current_frame.nodes[:meterpreter_node] = node
          elsif node.key.value == 'Commands'
            @current_frame.nodes[:command_node] = node
          end
        end

        def hash_arg?(node)
          node.type == :hash
        end

        def on_send(node)
          if file_rm_call?(node)
            @current_frame.identified_commands << 'stdapi_fs_rm' unless @current_frame.identified_commands.include?('stdapi_fs_rm')
            # Add an offense, but don't provide an autocorrect. There will be a final autocorrect to fix all issues
            add_offense(node) unless @current_frame.current_commands.include?('stdapi_fs_rm')
          end

          if file_ls_call?(node)
            @current_frame.identified_commands << 'stdapi_fs_ls' unless @current_frame.identified_commands.include?('stdapi_fs_ls')
            # Add an offense, but don't provide an autocorrect. There will be a final autocorrect to fix all issues
            add_offense(node) unless @current_frame.current_commands.include?('stdapi_fs_ls')
          end
        end

        def on_investigation_end
          super
          # Ensure commands are sorted and unique
          @current_frame.identified_commands = @current_frame.identified_commands.uniq.sort

          if @current_frame.nodes[:compat_node] && @current_frame.nodes[:meterpreter_node] && @current_frame.nodes[:command_node] && @current_frame.identified_commands == @current_frame.current_commands
           # TODO: Handle happy path
          elsif @current_frame.nodes[:compat_node] && @current_frame.nodes[:meterpreter_node] && @current_frame.nodes[:command_node] && @current_frame.identified_commands != @current_frame.current_commands
            add_offense(@current_frame.nodes[:command_node], &autocorrector)
          elsif @current_frame.nodes[:compat_node] && @current_frame.nodes[:meterpreter_node] && @current_frame.nodes[:command_node].nil?
            add_offense(@current_frame.nodes[:meterpreter_node], &autocorrector)
          elsif @current_frame.nodes[:compat_node] && @current_frame.nodes[:meterpreter_node].nil? && @current_frame.nodes[:command_node].nil?
            add_offense(@current_frame.nodes[:compat_node], &autocorrector)
          elsif @current_frame.nodes[:compat_node].nil? && @current_frame.nodes[:meterpreter_node].nil? && @current_frame.nodes[:command_node].nil? && !@current_frame.nodes[:initialize_node].nil?
            if @current_frame.nodes[:end_of_info_node].nil?
              puts 'TODO'
              return
            end
            add_offense(@current_frame.nodes[:end_of_info_node], &autocorrector)
          elsif @current_frame.nodes[:initialize_node].nil?
            add_offense(@current_frame.nodes[:class_body_node], &autocorrector)
          else
            raise 'Fix this dummy'
          end
        end

        def autocorrector
          lambda do |corrector|
            # Handles scenario where we have both compat & meterpreter hashes
            # but no commands array present within a module
            if @current_frame.nodes[:compat_node] && @current_frame.nodes[:meterpreter_node] && @current_frame.nodes[:command_node].nil?
              meterpreter_hash_node = @current_frame.nodes[:meterpreter_node].children[1]

              # White spacing handling based of node offsets
              meterpreter_whitespace = offset(@current_frame.nodes[:meterpreter_node])
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
            elsif @current_frame.nodes[:compat_node] && @current_frame.nodes[:meterpreter_node].nil? && @current_frame.nodes[:command_node].nil?
              compat_hash_node = @current_frame.nodes[:compat_node].children[1]

              # White spacing handling based of node offsets
              compat_whitespace = offset(@current_frame.nodes[:compat_node])
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
            elsif @current_frame.nodes[:compat_node].nil? && @current_frame.nodes[:meterpreter_node].nil? && @current_frame.nodes[:command_node].nil? && !@current_frame.nodes[:initialize_node].nil?
              # White spacing handling based of node offsets
              compat_whitespace = offset(@current_frame.nodes[:end_of_info_node])
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

              corrector.insert_after(@current_frame.nodes[:end_of_info_node], test_new_hash)

            # Handles scenario when we have no compats hash, no meterpreter hash
            # and  no compats array present no initialize method present within the module
            elsif @current_frame.nodes[:compat_node].nil? && @current_frame.nodes[:meterpreter_node].nil? && @current_frame.nodes[:command_node].nil? && @current_frame.nodes[:initialize_node].nil?
              # White spacing handling based of node offset
              def_whitespace = offset(@current_frame.nodes[:class_body_node])
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

              corrector.insert_before(@current_frame.nodes[:class_body_node], new_hash)

            else
              array_node = @current_frame.nodes[:command_node].children[1]
              commands_whitespace = offset(@current_frame.nodes[:command_node])
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
