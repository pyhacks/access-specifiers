import sys
from access_modifiers import api as access_modifiers


private = access_modifiers.PrivateModifier
protected = access_modifiers.ProtectedModifier
public = access_modifiers.PublicModifier

access_modifiers.set_default(access_modifiers.public)


class Test(access_modifiers.Restricted):
    abc = access_modifiers.protected(30)
    public .my_var = 15

    @access_modifiers.public
    def __new__(cls):
        print("in __new__")
        return object.__new__(cls)

    @access_modifiers.public
    def __init__(self):
        
        self.set_private("a", 10)         
        hidden_values = self.get_private("hidden_values")
        hidden_values["dsfcsd"] = 10                
        self.set_private("hidden_values", hidden_values)
        self.get_private("a")

        def private2():
            self.get_private("a")
            print("in __init__")        
        self.set_private("private2", private2)
        self.get_private("private2")()
        self.set_protected("protected1", 23)        
        self.private.c = 46
        self.protected.c = 45        
        self.public.qwert = 50
        self.qwert = 60

    def public1(self):
        print("public method called")

    @access_modifiers.private
    def private1(self):
        self.a
        self.get_private("a")
        print("private method called")

    @access_modifiers.private
    def private3(self):
        print("private3 called")    

    def func(self):
        self.private1() 

    def setb(self):
        set_private = self.get_private("set_private")
        set_private("b", 20)

    def get_get_private(self):
        return self.get_private

    def show_a(self):
        print(self.a)

    def private_test(self):
        self.private.new_var = 5
        print(self.private.new_var)

    def leak_private(self, name):
        return self.get_private(name)

    def get_self(self):
        return self

    def authorize2(self, func):
        self.authorize(func)
       
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

    def __setattr__(self, name, value):
        if sys._getframe(1).f_code == access_modifiers.SecureInstance._setattr_.__code__:
            setter = self.create_setattr(depth = 2)
        else:
            setter = self.create_setattr(depth = 1)
        setter(name, value)

    def __delattr__(self, name):
        if sys._getframe(1).f_code == access_modifiers.SecureInstance._delattr_.__code__:
            deleter = self.create_delattr(depth = 2)
        else:
            deleter = self.create_delattr(depth = 1)
        deleter(name)
        

class Test2(access_modifiers.Restricted):
    @access_modifiers.protected
    def func1(self):
        print("hello in Test2")

    @access_modifiers.private
    def func2(self):
        pass


class Test3(metaclass = access_modifiers.create_restrictor(Test)):
    pass    


class Test9:
    ghj = 563
    

class Test4(metaclass = access_modifiers.create_restrictor(Test9, Test2, Test3)):
    _protecteds_ = ["var1"]
    var1 = 7
    abc = 43

    @access_modifiers.public
    def test4_func(self):
        self.set_private("a", 15)
        self.a
        self.a = 15
        self.__init__()
        
    def test4_func2(self):
        del self.a

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
    

class Test6(metaclass = access_modifiers.Restrictor):
    var2 = access_modifiers.protected(345)    
    
    @access_modifiers.private
    def func2(self, obj):
        print(obj.var2)
        
    def func1(self, obj):
        self.func2(obj)

    @classmethod
    def get_class(cls):
        return cls

    #def __init__(self):
    #    print("var2" in self.hidden_values)


class Test7(metaclass = access_modifiers.create_restrictor(access_modifiers.private(Test6))):
    pass


class Test8():
    def func3(self):
        a = 10
        print(self.var2)        


class Test5(Test8, metaclass = access_modifiers.create_restrictor(Test2, Test7)):
    _privates_ = ["var1"]
    _protecteds_ = ["var2"]
    var1 = 21
    var2 = 435

    def my_func(self):
        real_Test6 = Test6.get_class()
        real_Test6.func1(real_Test6(), self)
        Test8.func3(self)


class Test10(metaclass = access_modifiers.create_restrictor(Test5)):
    pass


class Test11(access_modifiers.HalfRestricted):
    _privates_ = ["a"]
    
    def __init__(self):
        print("in Test7")
        self.set_private("a", 238)

class Test12:
    def func(self, obj):
        print(obj.a)

def test():
    t = Test()
    t.public1()
    t.show_a()
    t.func()

    t2 = Test()
    y = Test4()
    y.func()
    y.test4_func()


test()

