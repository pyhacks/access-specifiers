# access-specifiers
This library provides runtime access modifiers with very high security and it is fully featured (e.g, supports private inheritance).

# Installation
```pip install access-specifiers```

The recommended way to import the library is like below:
```python
from access_specifiers import api as access_specifiers
```
This convoluted import statement is required in order to have a strong access security. Shortly, _api_ protects the library from monkeypatching. Rest of the documentation assumes the library is imported as shown above.

# Inheritance
In order to make access modifiers available to your simple class, you need to inherit from _Restricted_ class:
```python
class MyClass(access_specifiers.Restricted):
    pass
```
Metaclass of _Restricted_ is _Restrictor_.
If you need to inherit from classes which inherit from _Restricted_, you first need to create a new metaclass.

access_specifiers.**create_restrictor**(*bases)

Create a metaclass given the required bases.
```python
class MyClass4(metaclass = access_specifiers.create_restrictor(MyClass1, MyClass2, MyClass3)):
    pass
```

# Using The Modifiers
_function_ access_specifiers.**private**(value)

_decorator_ @access_specifiers.**private**(value)

_function_ access_specifiers.**protected**(value)

_decorator_ @access_specifiers.**protected**(value)

_function_ access_specifiers.**public**(value)

_decorator_ @access_specifiers.**public**(value)

Modifiers can be used both as a function and a decorator. Just call them with the value you need to set its modifier:
```python
class MyClass(access_specifiers.Restricted):
    a = access_specifiers.private(10) 

    @access_specifiers.private
    def func(self):
        pass
```
Alternatively, you can also use a fancier syntax:

_class_ access_specifiers.**PrivateModifier**

_class_ access_specifiers.**ProtectedModifier**

_class_ access_specifiers.**PublicModifier**
```python
private = access_specifiers.PrivateModifier
protected = access_specifiers.ProtectedModifier
public = access_specifiers.PublicModifier

class MyClass(access_specifiers.Restricted):
    private .a = 10
    protected .b = 20
    public .c = 30
```
The dot (.) in between the modifier and the name is required.

You can also set new members with access modifiers after creating the class. 
Classes inheriting _Restricted_ store _ClassModifier_ objects. You can use them as modifiers:
```python
class MyClass(access_specifiers.Restricted):
    @classmethod
    def func(cls):
        private = cls.private
        protected = cls.protected
        public = cls.public
        private .d = 10
        protected .e = 20
        public .f = 30
```
The dot (.) in between the modifier and the name is required.

You can also specify access modifiers for object attributes. _Restricted_ objects store _Modifier_ objects. 
You can use them as modifiers:
```python
class MyClass(access_specifiers.Restricted):
    def func(self):
        private = self.private 
        protected = self.protected
        public = self.public 
        private .a = 10
```
Again, the dot in between is required.

_function_ access_specifiers.**set_default**(modifier)

Set the default modifier when a member is defined with no explicit modifier. By default, default modifier is public. 
_modifier_ parameter can be either access_specifiers.private, access_specifiers.protected or access_specifiers.public.

There is one more feature of access_specifiers.**create_restrictor**: private and protected inheritance. Replace your base classes with calls to modifiers:
```python
class MyClass2(metaclass = access_specifiers.create_restrictor(access_specifiers.private(MyClass))):
    pass

 class MyClass3(metaclass = access_specifiers.create_restrictor(access_specifiers.protected(MyClass))):
    pass
```
# Utils
_function_ access_specifiers.**super**(obj_or_cls = None)

This function is equivalent to the built in super function and it should be used when the built in function doesn't work. 
Returns a proxy object to the superclass of obj_or_cls. 

_decorator_ @access_specifiers.**Decorator**(decorator)

Normally, if you decorate a method, the function returned by the decorator becomes the member and the original function won't be a member. 
This causes the original function to be unable to access private/protected members. 
Instead of decorating directly, pass your decorator to access_specifiers.Decorator() and this problem will be solved.
Along with the original function, all the wrapper functions returned by each of the decorators will also be authorized.
Lastly, access decorators must be topmost and you shouldn't pass them in access_specifiers.Decorator(). Example usage:
```python
def factory1(func):
    def wrapper(*args, **kwargs):
        print("by factory1")
        func(*args, **kwargs)
    return wrapper

def factory2(func):
    def wrapper(*args, **kwargs):
        print("by factory2")
        func(*args, **kwargs)
    return wrapper

class MyClass(access_specifiers.Restricted):
    @access_specifiers.private
    @access_specifiers.Decorator(factory1)
    @access_specifiers.Decorator(factory2)
    def func(self):
        pass
```

_Restricted_ class provides a few more useful things:

_method_ Restricted.**set_private**(name, value, cls = None)

_method_ Restricted.**set_protected**(name, value, cls = None)

_method_ Restricted.**set_public**(name, value)

You can specify modifiers for dynamically generated variable names. 
If _cls_ is specified it must be a class and the call to these functions will be treated as if it is done from one of the methods inside the _cls_.
_cls_ can either be the same as of the caller or it must be more derived than of the caller. 
If it is a parent of the caller's class, an access_specifiers.PrivateError will be raised.

_method_ Restricted.**authorize**(func_or_cls, for_all = True)

This function acts like the "friend" keyword of c++. Allows _func_or_cls_ to have as much member access right as any other method of this class. 
_func_or_cls_ can either be a function or a class. 
If _for_all_ is set, allows _func_or_cls_ to access private/protected members of not only this object, but also every other instantiated object of this class and also all future objects of this class which will be instantiated later and even the class itself.

_method_ Restricted.**get_hidden_value**(value, name = None)

Return a protected object whose only attribute "value" stores the given _value_. 
Access to the value attribute is only granted if the accessing function has the rights to access given _name_.
If _name_ is None, any class in the class hierarchy of this object can access the value but external access is rejected.
If you are calling this method from a base class called _MyBase_ and don't want any derived class to access value, _name_ must be one of the private members of MyBase.
Each object whose class derives from _Restricted_ has private members whose names has the following structure: class_name + "_" + "private".
For the case of _MyBase_, you can set name to "MyBase_private".
This function is useful in case you wanna call an external function and want to prevent that function from obtaining (possibly private) local variables of the calling method.
Example usage:
 ```python
import sys

def external_func():
    print(sys._getframe(1).f_locals)

class Base(access_specifiers.Restricted):
    pass

class Derived(metaclass = access_specifiers.create_restrictor(Base)):
    def __init__(self):
        private = self.private
        private .a = 10

    def func(self):
        a = self.a
        hidden_value = self.get_hidden_value(a, name = "Derived_private")
        del a
        external_func()
        a = hidden_value.value

obj = Derived()
obj.func()
 ```   
    
_method_ Restricted.**create_getattribute**(depth = 2)

Return a \_\_getattribute__ function which checks the access rights of the function _depth_ times back in the stack. 
Useful when you write a custom \_\_getattribute__ and don't wanna manually check the caller:
```python
    def __getattribute__(self, name):
        getter = self.create_getattribute()                
        value = getter(name)
        return value
```
Note: default value of _depth_ is deliberately not 1. The reason for that is complicated and you don't need to know the details unless you call this function from somewhere else.

_method_ Restricted.**create_setattr**(depth = 2)

Return a \_\_setattr__ function which checks the access rights of the function _depth_ times back in the stack. 
Useful when you write a custom \_\_setattr__ and don't wanna manually check the caller:
```python
    def __setattr__(self, name, value):
        setter = self.create_setattr()
        setter(name, value)
```
Note: default value of _depth_ is deliberately not 1. The reason for that is complicated and you don't need to know the details unless you call this function from somewhere else.

_method_ Restricted.**create_delattr**(depth = 2)

Return a \_\_delattr__ function which checks the access rights of the function _depth_ times back in the stack. 
Useful when you write a custom \_\_delattr__ and don't wanna manually check the caller:
```python
    def __delattr__(self, name):
        deleter = self.create_delattr()
        deleter(name)
```
Note: default value of _depth_ is deliberately not 1. The reason for that is complicated and you don't need to know the details unless you call this function from somewhere else.

Restricted.**\_subclasses_**

This is a class variable holding a list of subclasses. 
Elements of this list doesn't check access to their private and protected members but do check to private members coming from their bases.

Functions below are provided by _Restrictor_, which means they are only available to classes, not objects:

_method_ Restrictor.**set_class_private**(name, value)

_method_ Restrictor.**set_class_protected**(name, value)

_method_ Restrictor.**set_class_public**(name, value)
 
After the class has been created, these methods can be used to set private, protected and public class members which have dynamically generated names.

_method_ Restrictor.**authorize_for_class**(func_or_cls)

Authorize _func_or_cls_ so it can access private and protected class members. _func_or_cls_ can either be a function or a class. 
_func_or_cls_ will also be authorized to access private and protected members of future objects, but not current ones.

# Limitations
- [gc.get_objects()](https://docs.python.org/3/library/gc.html#gc.get_objects) can leak private/protected members. In order to prevent this, you may consider adding this to the top of your code:
```python
import gc
del gc.get_objects
```
This isn't done by this library in case the user actually requires this function. 
- @staticmethod is not supported
