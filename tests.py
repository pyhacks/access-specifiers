import sys
import time
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
        self.private2()
        self.set_protected("protected1", 23)        
        self.private.c = 46
        self.protected.c = 45
        self.public.qwert = 50
        self.qwert = 60
        self.fghd = 65

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
        SecureInstance = access_modifiers.SecureInstance
        SecureInstance.proxy = type(self).secure_class
        obj = SecureInstance(self)
        #obj = self
        Test4.test4_func2(obj)
        self.private1()

    def common_test(self):
        obj = type(self)()
        class A:
            def common(self, obj):
                obj.a
        self.authorize(A)
        A().common(self)
        A().common(obj)

    def set_b(self):
        type(self).b = 938

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

    @access_modifiers.protected
    def protected2(self):
        pass

    def __getattribute__(self, name):
        self.own_hidden_values["redirect_access"] = False
        getter = self.create_getattribute()
        try:
            value = getter(name) # may raise AttributeError           
        finally:
            self.own_hidden_values["redirect_access"] = True
        return value

    def __setattr__(self, name, value):
        setter = self.create_setattr()
        setter(name, value)

    def __delattr__(self, name):
        deleter = self.create_delattr()
        deleter(name)

        
class Test2(access_modifiers.Restricted):
    #var3 = access_modifiers.protected(374)
    
    @access_modifiers.protected
    def func1(self):
        print("hello in Test2")

    @access_modifiers.private
    def func2(self):
        pass

    @access_modifiers.private
    def func4(self):
        pass


class Test3(metaclass = access_modifiers.create_restrictor(Test)):
    pass


class Test9:
    ghj = 563


class Test4(metaclass = access_modifiers.create_restrictor(Test9, Test2, Test3)):
    _protecteds_ = ["var1"]
    var1 = 7
    private .var2 = 8
    abc = 43

    #def __new__(cls):
    #    return object.__new__(cls)
    
    @access_modifiers.public
    def test4_func(self):
        #self.check_caller.__func__.__code__ = create_bypass().__code__
        self.set_private("a", 15)
        self.a
        self.a = 15
        Test.abc
        self.protected2
        self.__init__()
        
    def test4_func2(self):
        #print(self.protected2)
        pass

    def __getattribute__(self, name):
        self.own_hidden_values["redirect_access"] = False
        getter = self.create_getattribute()
        try:
            value = getter(name) # may raise AttributeError           
        finally:
            self.own_hidden_values["redirect_access"] = True
        return value
    
    
class Test6(access_modifiers.Restricted):
    var2 = access_modifiers.protected(345)
    var3 = access_modifiers.protected(574)
    var4 = 11
    private .var5 = 12
    
    @access_modifiers.private
    def func2(self, obj):
        print(obj.var2)
        
    def func1(self, obj):
        self.func2(obj)

    @classmethod
    def get_class(cls):
        return cls

    #def __init__(self):
    #    print("in Test6.__init__")


class Test7(metaclass = access_modifiers.create_restrictor(Test2, access_modifiers.private(Test3), access_modifiers.private(Test6), access_modifiers.private(Test9))):
    def __new__(cls):        
        return object.__new__(cls)

    def __init__(self):
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

    #def __new__(cls):
    #    return object.__new__(cls)
    
    #def __init__(self):
    #    print("in Test5.__init__")
        
    def my_func(self):
        real_Test6 = Test6.get_class()
        real_Test6.func1(real_Test6(), self)
        Test8.func3(self)

    def my_func3(self):        
        try:
            self.public1
        except access_modifiers.PrivateError:
            pass
        else:
            raise RuntimeError("expected PrivateError")

        try:
            Test6.var4
        except access_modifiers.PrivateError:
            pass
        else:
            raise RuntimeError("expected PrivateError")
        
        try:
            self.func2
        except access_modifiers.PrivateError:
            pass
        else:
            raise RuntimeError("expected PrivateError")


class Test14(access_modifiers.Restricted):
    def test14_func(self):
        try:
            print(self.func4)
        except access_modifiers.PrivateError:
            pass
        else:
            raise RuntimeError("expected PrivateError")


class Test10(metaclass = access_modifiers.create_restrictor(Test14, Test5)):
    pass


class Test11(access_modifiers.HalfRestricted):
    def __init__(self):
        print("in Test11")
        self.set_private("a", 238)


class Test12:
    def func(self, obj):
        print(obj.a)


class Test13(metaclass = access_modifiers.create_restrictor(Test11)):
    def func(self):
        print(self.a)


class Class0(access_modifiers.Restricted):
    def MethodA(self):
        print("MethodA of Class0")
    

class ClassA(metaclass = access_modifiers.create_restrictor(Class0)):
    def MethodA(self):
        self.super().MethodA()
        print("MethodA of ClassA")
    

class ClassB(metaclass = access_modifiers.create_restrictor(Class0)):
    def MethodA(self):
        print("MethodA of ClassB")


class ClassC(metaclass = access_modifiers.create_restrictor(ClassA, ClassB)):
    def MethodA(self):
        self.super().MethodA()
            

def create_bypass():
    a = 10
    b = 20
    def bypass(self, *args, **kwargs):
        a
        #b
        return True
    return bypass
    
def test():    
    for base in ClassC.__mro__:
        print(base.__name__)
    ClassC().MethodA()
    a = Test()
    a.public1()
    a.show_a()
    a.func()
    a.common_test()
    b = Test()

    c = Test4()
    c.func()
    c.test4_func()

    d = Test5()
    d.my_func3()

    e = Test10()
    e.my_func3()
    e.test14_func()
    
    f = Test13()
    f.func()


def test2():
    print("finished")

    from access_modifiers import calls    

    times = []
    for frame in calls:
        times.append(calls[frame][0])
    times = sorted(times, reverse = True)
    times = list(times)
    print(sum(times))

    durations = []
    for frame in calls:
        durations.append(calls[frame][2])
    durations = sorted(durations, reverse = True)
    durations = list(durations)
    print(sum(durations))

    single_calls = {}
    call_per_frame = 1
    for frame in calls:
        #if calls[frame][0] == call_per_frame:
            if frame.f_code.co_name not in single_calls:
                single_calls[frame.f_code.co_name] = calls[frame][2]
            else:
                single_calls[frame.f_code.co_name] += calls[frame][2]
            if frame.f_code.co_name == "set_private":
                #print(frame, calls[frame][1])
                #if frame.f_back.f_back.f_code.co_name == "get_unbound_base_attr":
                #    print(frame.f_back.f_back.f_back.f_back, calls[frame][4])
                pass
    for name in sorted(single_calls, key = single_calls.get, reverse = True):
        print(name, single_calls[name])
            
    counter = 0
    for time in times:
        if time == call_per_frame:
            counter += call_per_frame
    #print(counter)

    ##time_map = {}
    ##for time in times:
    ##    if time not in time_map:
    ##        time_map[time] = 1
    ##    else:
    ##        time_map[time] += 1
    ##print(time_map)
      
test()
#test2()
