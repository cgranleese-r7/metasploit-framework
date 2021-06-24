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
  end
end
