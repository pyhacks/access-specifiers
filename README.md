# access-modifiers
This library provides runtime access modifiers with high security. The project is a proof of concept and the library is too slow to be used in production code. Currently installing from pip is not supported.

The recommended way to import the library is like below:
```python
from access_modifiers import api as access_modifiers
```
This convoluted import statement is required in order to have a strong access security. Shortly, _api_ protects the library from monkeypatching. Rest of the documentation assumes the library is imported as shown above.

# Inheritance
In order to make access modifiers available to your simple class, you need to inherit from _Restricted_ class:
```python
class MyClass(access_modifiers.Restricted):
    pass
```
Metaclass of _Restricted_ is _Restrictor_. And _Restrictor_ causes your class to inherit from _AccessEssentials_ class.
If you need to inherit from classes which inherit from _Restricted_, you first need to create a new metaclass.

access_modifiers.**create_restrictor**(*bases)

Create a metaclass given the required bases.
```python
class MyClass4(metaclass = access_modifiers.create_restrictor(MyClass1, MyClass2, MyClass3)):
    pass
```

# Using The Modifiers
_function_ access_modifiers.**private**(value)

_decorator_ access_modifiers.**private**(value)

_function_ access_modifiers.**protected**(value)

_decorator_ access_modifiers.**protected**(value)

_function_ access_modifiers.**public**(value)

_decorator_ access_modifiers.**public**(value)

Modifiers can be used both as a function and a decorator. Just call them with the value you need to set its modifier:
```python
class MyClass(access_modifiers.Restricted):
    a = access_modifiers.private(10) 

    @access_modifiers.private
    def func():
        pass
```
Alternatively, you can also use a fancier syntax:

_class_ access_modifiers.**PrivateModifier**

_class_ access_modifiers.**ProtectedModifier**

_class_ access_modifiers.**PublicModifier**
```python
private = access_modifiers.PrivateModifier
protected = access_modifiers.ProtectedModifier
public = access_modifiers.PublicModifier

class MyClass(access_modifiers.Restricted):
    private .a = 10
    protected .b = 20
    public .c = 30
```
The dot (.) in between the modifier and the name is required.

You can also specify access modifiers for object attributes. As stated above, your class will automatically inherit from _AccessEssentials_. _AccessEssentials_ objects store _Modifier_ objects. 
You can use them as modifiers:
```python
class MyClass(access_modifiers.Restricted):
    def func(self):
        private = self.private 
        protected = self.protected
        public = self.public 
        private .a = 10
```
Again, the dot in between is required. These modifiers belong to the object. That means a derived class can access private members defined in a base class method. 
Because since there is no type casting in python, that base class method processed a derived class object, not a base class object. 
This is in contrast with access_modifiers.PrivateModifier or access_modifiers.private. Derived classes can't access class variables/methods defined with access_modifiers.private. 

_function_ access_modifiers.**set_default**(modifier)

Set the default modifier when a member is defined with no explicit modifier. By default, default modifier is public. 
_modifier_ parameter can be either access_modifiers.private, access_modifiers.protected or access_modifiers.public.

There is one more feature of access_modifiers.**create_restrictor**: private and protected inheritance. Replace your base classes with calls to modifiers:
```python
class MyClass2(metaclass = access_modifiers.create_restrictor(access_modifiers.private(MyClass))):
    pass

 class MyClass3(metaclass = access_modifiers.create_restrictor(access_modifiers.protected(MyClass))):
    pass
```
# Utils
_function_ access_modifiers.**super**(obj_or_cls)

This function is equivalent to the built in super function: Returns a proxy object to the superclass of obj_or_cls. It should be used when the built in function doesn't work. Works only outside the class.

_AccessEssentials_ class provides a few more useful functions:

_method_ AccessEssentials.**set_private**(name, value)

_method_ AccessEssentials.**set_protected**(name, value)

_method_ AccessEssentials.**set_public**(name, value)

You can specify modifiers for dynamically generated variable names.

_method_ AccessEssentials.**get_private**(name)

Get any member which is not public. Works for not only privates but also protecteds.

_method_ AccessEssentials.**authorize**(func_or_cls)

Allow func_or_cls to access private/protected members of this object. This function acts like the "friend" keyword of c++. Only works from inside the class.

_method_ AccessEssentials.**super**(obj_or_cls = None)

This function is equivalent to the built in super function: Returns a proxy object to the superclass of obj_or_cls. It should be used when the built in function doesn't work. Works only inside the class.

_method_ AccessEssentials.**create_getattribute**(depth = 1)

Return a \_\_getattribute__ function which checks the access rights of the function _depth_ times back in the stack. 
Useful when you write a custom \_\_getattribute__ and don't wanna manually check the caller. If you write a custom \_\_getattribute__ function, you may get recursion error. 
In order to prevent this set _redirect_access_ to false. This variable controls which getters should be called. 
Another thing to note is stack structure may not always be the same. You need to think about every possibility when specifying the _depth_ parameter. Unfortunately there is no easier way:
```python
    def __getattribute__(self, name):
        self.own_hidden_values["redirect_access"] = False
        if sys._getframe(1).f_code == access_modifiers.SecureInstance._getattribute_.__code__:
            getter = self.create_getattribute(depth = 2)
        else:
            getter = self.create_getattribute(depth = 1)
        try:
            value = getter(name) # may raise AttributeError
        finally:
            self.own_hidden_values["redirect_access"] = True
        return value
```
Lastly, if you write a custom \_\_getattribute__ function in a base class, you need to override it in a derived class. Otherwise you may get _PrivateError_.

_method_ AccessEssentials.**create_setattr**(depth = 1)

Return a \_\_setattr__ function which checks the access rights of the function _depth_ times back in the stack. 
Useful when you write a custom \_\_setattr__ and don't wanna manually check the caller. 
Stack structure may not always be the same. You need to think about every possibility when specifying the _depth_ parameter:
```python
    def __setattr__(self, name, value):
        if sys._getframe(1).f_code == access_modifiers.SecureInstance._setattr_.__code__:
            setter = self.create_setattr(depth = 2)
        else:
            setter = self.create_setattr(depth = 1)
        setter(name, value)
```
_method_ AccessEssentials.**create_delattr**(depth = 1)

Return a \_\_delattr__ function which checks the access rights of the function _depth_ times back in the stack. 
Useful when you write a custom \_\_delattr__ and don't wanna manually check the caller. 
Stack structure may not always be the same. You need to think about every possibility when specifying the _depth_ parameter:
```python
    def __delattr__(self, name):
        if sys._getframe(1).f_code == access_modifiers.SecureInstance._delattr_.__code__:
            deleter = self.create_delattr(depth = 2)
        else:
            deleter = self.create_delattr(depth = 1)
        deleter(name)
```

