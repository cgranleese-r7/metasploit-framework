module RuboCop
  module Cop
    module Lint
      class MeterpreterCommandDependencies < Base
        extend AutoCorrector
        include Alignment

        # TODO:
        #   - reorder tests so they gradually build up in complexity
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

        def on_new_investigation
          super
          @current_commands = []
          @identified_commands = []
          @command_array_node = nil

          @state = :none
        end

        def on_class(node)
          @class_body_node = node.body
        end

        def on_def(node)
          return unless @state == :none

          if initialize_present?(node)
            @initialize_node = node
          end

          update_info_node = find_update_info_node(node) || find_nested_update_info_node(node)
          return if update_info_node.nil?

          @state = :looking_for_hash
        end

        def after_def(_node)
          @state = :finished
        end

        def on_hash(node)
          return unless @state == :looking_for_hash
          if node.parent.children[1] == :update_info
            @end_of_info_node = node.children.last
            @state = :looking_for_hash_keys
          end
        end

        def on_pair(node)
          return unless @state == :looking_for_hash_keys
          if node.key.value == 'Compat'
            @compat_node = node
          elsif node.key.value == 'Meterpreter'
            @meterpreter_node = node
          elsif node.key.value == 'Commands'
            @command_node = node
            node.value.each_child_node {|command| @current_commands << command.value}
          end
        end

        def hash_arg?(node)
          node.type == :hash
        end

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
          super
          # Ensure commands are sorted and unique
          @identified_commands = @identified_commands.uniq.sort

          if @compat_node && @meterpreter_node && @command_node && @identified_commands == @current_commands
           # TODO: Handle happy path
          elsif @compat_node && @meterpreter_node && @command_node && @identified_commands != @current_commands
            add_offense(@command_node, &autocorrector)
          elsif @compat_node && @meterpreter_node && @command_node.nil?
            add_offense(@meterpreter_node, &autocorrector)
          elsif @compat_node && @meterpreter_node.nil? && @command_node.nil?
            add_offense(@compat_node, &autocorrector)
          elsif @compat_node.nil? && @meterpreter_node.nil? && @command_node.nil? && !@initialize_node.nil?
            add_offense(@end_of_info_node, &autocorrector)
          elsif @initialize_node.nil?
            add_offense(@class_body_node, &autocorrector)
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
            # and compats array present within a module
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

            # Handles scenario when we have no compats hash, no meterpreter hash
            # and  no compats array present within the module, but we do have an initialize method present
            elsif @compat_node.nil? && @meterpreter_node.nil? && @command_node.nil? && !@initialize_node.nil?
              # White spacing handling based of node offsets
              compat_whitespace = offset(@end_of_info_node)
              meterpreter_whitespace = compat_whitespace + "  "
              commands_whitespace = meterpreter_whitespace + "  "
              array_content_whitespace = commands_whitespace + "  "

              # Formatting to add missing commands node when the method has a compat node & meterpreter node present
              test_new_hash =
                ",\n#{compat_whitespace}'Compat' => {\n" \
                "#{meterpreter_whitespace}'Meterpreter' => {\n" \
                "#{commands_whitespace}'Commands' => %w[" \
                "\n#{array_content_whitespace}#{@identified_commands.join("\n#{array_content_whitespace}")}\n" \
                "#{commands_whitespace}]\n" \
                "#{meterpreter_whitespace}}\n" \
                "#{compat_whitespace}}"

              corrector.insert_after(@end_of_info_node, test_new_hash)

            # Handles scenario when we have no compats hash, no meterpreter hash
            # and  no compats array present no initialize method present within the module
            elsif @compat_node.nil? && @meterpreter_node.nil? && @command_node.nil? && @initialize_node.nil?
              # White spacing handling based of node offset
              def_whitespace = offset(@class_body_node)
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
                "\n#{array_content_whitespace}#{@identified_commands.join("\n#{array_content_whitespace}")}" \
                "\n#{commands_whitespace}]" \
                "\n#{meterpreter_whitespace}}" \
                "\n#{info_whitespace}}" \
                "\n#{update_info_whitespace})" \
                "\n#{super_whitespace})" \
                "\n#{def_whitespace}end" \
                "\n  "

              corrector.insert_before(@class_body_node, new_hash)

            else
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
