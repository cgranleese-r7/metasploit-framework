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


## Before loops

person = Person.new("alan", 3000)
person2.say_hello

person2 = Person.new("Chris", 3000)
person2.say_hello

## After loops, adding intermediate data structure to keep track of the data, and loop over that
configuration = [
  { name: 'alan', age: 30000 },
  { name: 'chris', age: 30000 },
]

configuration.each do |value|
  Person.new(value[:name], value[:age]).say_hello
end
