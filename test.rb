class Person
  # attr_accessor :name

  def initialize(name, age)
    @name = name
    @age = age
  end

  def say_hello
    puts "hello from #{@name}"
  end


  attr_reader(:name)
  #=>
  def name
    @name
  end

  attr_writer(:name)
  def name=(name)
    @name = name
  end
end

person1 = Person.new("alan", 3000)
person2 = Person.new("Chris", 3000)
person1.name = "new name"

stack = []
stack.push(person1)
stack.push(person2)

stack.each do |person|
  puts person.name
  puts person.say_hello
end
