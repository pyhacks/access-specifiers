import sys
import types
import functools
import builtins
import collections
import dill
import time

calls = {}

class AccessError(Exception):
    def set_err(self):
        if self.recreate and self.inherited:
            self.err = f"""\"{self.caller_name}" cannot access inherited {self.modifier} member "{self.member_name}" of the "{self.class_name}\""""
        elif self.recreate:
            self.err = f"""\"{self.caller_name}" cannot access {self.modifier} member "{self.member_name}" of the "{self.class_name}\""""
        if self.recreate and self.class_attr:
            self.err = self.err + " class"                
        elif self.recreate:
            self.err = self.err + " object"

    def init1(self, err):
        self.recreate = False
        self.err = err
        
    def init2(self, caller_name, member_name, class_name, class_attr = False, inherited = False, private = True, caller = None):
        self.recreate = True
        self.caller_name = caller_name
        self.member_name = member_name
        self.class_name = class_name
        self.base_name = class_name
        self.class_attr = class_attr
        self.inherited = inherited
        if private:
            self.modifier = "private"
        else:
            self.modifier = "protected"
        self.caller = caller        
        self.set_err()        
        
    def __init__(self, *args, **kwargs):
        if len(args) == 1 and len(kwargs) == 0:
            self.init1(*args)
        else:
            self.init2(*args, **kwargs)            
      
    def __str__(self):
        self.set_err()
        return self.err          


class PrivateError(AccessError):
    def init2(self, *args, **kwargs):
        kwargs["private"] = True
        super().init2(*args, **kwargs)


class ProtectedError(AccessError):
    def init2(self, *args, **kwargs):
        kwargs["private"] = False
        super().init2(*args, **kwargs)
        

def create_api():
    """This function makes it possible to provide a raw api without creating a loophole for the SecureApi instance

    A raw Api is slightly faster than a SecureApi.
    Also, it's useful for monkeypatching the library in case someone finds a bug in it.
    That is possible since properties don't provide any protection against class level access.
    But that also means a raw api is open to possible bypasses.
    It's impossible to provide an api object which both allows monkeypatching and having a solid access security at the same time."""    
    class Api:
        """Property mechanism prevents possible bypasses based on modifying classes and functions.
        (Functions can be modified by overwriting their __code__ attribute)"""
        AccessError = AccessError
        PrivateError = PrivateError
        ProtectedError = ProtectedError

        
        @property
        def is_same_dict(api_self): # TODO: only check functions
            def is_same_dict(dict1, dict2):                                    
                for member_name, member in dict1.items():
                    pass_list = ["__getattribute__",
                                 "__setattr__",
                                 "__delattr__",
                                 "_getattribute_",
                                 "_setattr_",
                                 "_delattr_",
                                 "get_private"]
                    if member_name not in pass_list and api_self.is_function(member):
                        func_name = member.__code__.co_name
                        try:                        
                            function = dict2[func_name]
                        except AttributeError:                            
                            return False
                        if not api_self.is_function(function):
                            return False
                        elif not member.__code__ == function.__code__:                            
                            return False
                return True

            return is_same_dict


        @property
        def is_same_class(api_self):
            def is_same_class(cls1, cls2):
                return (cls1.__name__ == cls2.__name__ and api_self.is_same_dict(cls1.__dict__, cls2.__dict__))

            return is_same_class


        @property
        def PrivateValue(api_self):
            class PrivateValue:
                class_id = "access_modifiers.PrivateValue"
                
                def __init__(self, value):
                    self.value = value

            return PrivateValue


        @property
        def ProtectedValue(api_self):
            class ProtectedValue:
                class_id = "access_modifiers.ProtectedValue"
                
                def __init__(self, value):
                    self.value = value

            return ProtectedValue


        @property
        def PublicValue(api_self):
            class PublicValue:
                class_id = "access_modifiers.PublicValue"
                
                def __init__(self, value):
                    self.value = value

            return PublicValue


        class PrivateModifier:
            pass


        class ProtectedModifier:
            pass


        class PublicModifier:
            pass


        @property
        def private(api_self):
            def private(value):
                return api_self.PrivateValue(value)

            return private


        @property
        def protected(api_self):
            def protected(value):
                return api_self.ProtectedValue(value)

            return protected


        @property
        def public(api_self):
            def public(value):
                return api_self.PublicValue(value)

            return public


        @property
        def default(api_self):
            return api_self.public

        
        def set_default(api_self, modifier):
            @property
            def default(api_self):
                return modifier
            
            type(api_self).default = default            
        
        
        @property        
        def is_function(api_self):
            def is_function(func):
                try:
                    code = object.__getattribute__(func, "__code__")
                except AttributeError:
                    has_code = type(func) == types.MethodType
                else:
                    has_code = True
                if callable(func) and has_code and type(func.__code__) == types.CodeType:
                    return True
                else:
                    return False

            return is_function


        @property
        def get_all_subclasses(api_self):
            def get_all_subclasses(cls):
                all_subclasses = []
                for subclass in type.__getattribute__(cls, "__subclasses__")():
                    all_subclasses.append(subclass)
                    all_subclasses.extend(get_all_subclasses(subclass))
                all_subclasses = list(set(all_subclasses))
                return all_subclasses

            return get_all_subclasses


        @property
        def get_all_subclasses2(api_self):
            def get_all_subclasses2(cls):
                all_subclasses = []
                for subclass in cls._subclasses_:
                    all_subclasses.append(subclass)
                all_subclasses = list(set(all_subclasses))
                return all_subclasses
                
            return get_all_subclasses2        


        @property
        def Modifier(api_self):
            class Modifier:
                def __init__(self, setter):
                    object.__setattr__(self, "setter", setter)
                    
                def __getattribute__(self, name):
                    raise RuntimeError("this is a modifier, not a namespace")

                def __setattr__(self, name, value):
                    setter = object.__getattribute__(self, "setter")
                    setter(name, value, depth = 1)

                def __delattr__(self, name):
                    raise RuntimeError("this is a modifier, not a namespace")
            return Modifier


        @property
        def ClassModifier(api_self):
            class ClassModifier(api_self.Modifier):
                def __setattr__(self, name, value):
                    setter = object.__getattribute__(self, "setter")
                    setter(name, value)

            return ClassModifier
                    

        @property
        def get_blacklists(api_self):
            def get_blacklists(cls, is_access_essentials, bases, for_subclass = False):
                leaking_classes = []
                private_classes = []
                protected_classes = []
                for base in bases:
                    for grand_parent in base.__mro__:
                        if is_access_essentials(grand_parent):                                  
                            leaking_classes.append(base)
                            break
                    else:
                        try:
                            pg = type.__getattribute__(base, "protected_gate")
                        except AttributeError:
                            continue
                        is_private_base = hasattr(cls, "private_bases") and pg.cls in cls.private_bases
                        is_protected_base = hasattr(cls, "protected_bases") and pg.cls in cls.protected_bases
                        if is_private_base:
                            private_classes.append(base)
                        elif is_protected_base and not for_subclass:
                            protected_classes.append(base)
                return leaking_classes, private_classes, protected_classes

            return get_blacklists
        
                
        @property
        def replace_base(api_self):
            def replace_base(bases, blacklist, class_name):
                bases = list(bases)
                for cls in blacklist:
                    if cls in bases:
                        idx = bases.index(cls)
                        bases.remove(cls)
                        fake_base = type(class_name, (), {})
                        bases.insert(idx, fake_base)
                return tuple(bases)

            return replace_base


        @property
        def close_gates(api_self):
            def close_gates(bases):
                bases = list(bases)
                for base in bases:
                    try:
                        pg = type.__getattribute__(base, "protected_gate")
                    except AttributeError:
                        continue
                    idx = bases.index(base)
                    bases.remove(base)
                    bases.insert(idx, pg.cls)
                return tuple(bases)

            return close_gates
        
                
        @property
        def get_secure_bases(api_self):
            def get_secure_bases(cls, is_access_essentials, bases, for_subclass = False):
                #blacklists = api_self.get_blacklists(cls, is_access_essentials, bases, for_subclass)
                #bases = api_self.replace_base(bases, blacklists[0], "NotAccessEssentials")
                #bases = api_self.replace_base(bases, blacklists[1], "PrivateBaseClass")
                #bases = api_self.replace_base(bases, blacklists[2], "ProtectedBaseClass")
                if not for_subclass:
                    bases = api_self.close_gates(bases)                
                return bases

            return get_secure_bases


        @property
        def super(api_self):
            def super(obj_or_cls = None):
                if obj_or_cls is None:
                    self_name = sys._getframe(1).f_code.co_varnames[0]
                    obj_or_cls = sys._getframe(1).f_locals[self_name]
                elif isinstance(obj_or_cls, type):                    
                    obj_or_cls = obj_or_cls.secure_class
                try:
                    super = object.__getattribute__(obj_or_cls, "super")
                except AttributeError:
                    super = obj_or_cls.super
                return super()

            return super


        @property
        def IdentitySet(api_self):
            class IdentitySet(collections.abc.MutableSet):
                """https://stackoverflow.com/questions/16994307/identityset-in-python"""
                key = id  # should return a hashable object (we use id -> int)

                def __init__(self, iterable=()):
                    self.map = {}  # key -> object
                    for item in iterable:
                        self.add(item)

                def __len__(self):  # Sized
                    return len(self.map)

                def __iter__(self):  # Iterable
                    # return an iterator over stored objects (values)
                    return iter(self.map.values())

                def __contains__(self, x):  # Container
                    return self.key(x) in self.map

                def add(self, value):  # MutableSet
                    """Add an element (replace any object with the same key)."""
                    self.map[self.key(value)] = value

                def discard(self, value):  # MutableSet
                    """Remove an element. Do not raise if absent."""
                    self.map.pop(self.key(value), None)

                def __repr__(self):
                    if not self:
                        return f'{self.__class__.__name__}()'
                    return f'{self.__class__.__name__}({list(self)!r})'
                
            return IdentitySet


        @property
        def Decoration(api_self):
            class Decoration:
                class_id = "access_modifiers.Decoration"
                
                def __init__(self, decorator, func):
                    self.decorator = decorator
                    self.func = func

            return Decoration
        
                
        @property
        def Decorator(api_self):
            class Decorator:
                def __init__(self, decorator):
                    self.decorator = decorator

                def __call__(self, func):
                    return api_self.Decoration(self.decorator, func)

            return Decorator

        
        @property
        def AccessEssentials(api_self):
            class AccessEssentials:
                """This class provides basic access restriction tools

                Some of the methods below start with the line: self.static_dict
                It is there to prevent a possible bypass. Here's the thing:
                All the functions under this class can be directly accessed from api.AccessEssentials
                and they can be called by explicitly passing the self argument.
                Now, being able to externally call protected methods like authorize is a big problem.
                Fortunately, real instances aren't available externally. Only SecureInstance instances can be passed.
                When self is a SecureInstance (or even SecureClass) object,
                self.static_dict guarantees an exception is raised."""
                ae_class_id = "access_modifiers.AccessEssentials"

                _publics_ = []
                _protecteds_ = ["get_methods",
                                "no_redirect",
                                "no_redirect2",

                                # Must be protected to guarantee an exception is raised.
                                # Otherwise it could be monkeypatched to suppress and that could cause a bypass:
                                # if caller_is_not_authorized:
                                #     self.raise_PrivateError() # must break control flow
                                # return private_member
                                "raise_PrivateError",
                                "raise_ProtectedError",

                                "is_meta_method",
                                "get_base_attr",                                                                  
                                "get_attr",
                                "get_member",
                                "is_subclass_method",
                                "check_caller",
                                "authorize",
                                "internal_get_hidden_value",
                                "get_hidden_value",
                                "create_get_private",
                                "create_getattribute",
                                "create_setattr",
                                "create_delattr",                                
                                "mask_public_face",
                                "set_private",
                                "set_protected",
                                "set_public",
                                "start_access_check",
                                "ready_to_redirect",
                                "init_privates",
                                "pre_init"]

                _privates_ = ["_getattribute_",
                              "_setattr_",
                              "_delattr_",
                              "_privates_",
                              "_protecteds_",
                              "redirect_access",
                              "static_dict",
                              "AccessEssentials",
                              "InsecureRestrictor",
                              "base_publics",
                              "base_protecteds",
                              "base_privates",
                              "_subclasses_",
                              "objs",
                              "should_redirect",
                              "get_unbound_base_attr",
                              "has_own_attr",
                              "is_public",
                              "is_protected",
                              "set_class_public",
                              "set_class_protected",
                              "set_class_private",
                              "modify_attr",
                              "authorize_for_class",
                              "public",
                              "protected",
                              "private"]                                              

                base_publics = []
                base_protecteds = []
                base_privates = []
                _subclasses_ = []
                objs = []
                
                def get_methods(self):
                    """Get all the methods of this object"""
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")
                    try:
                        get_private = object.__getattribute__(self, "get_private")
                    except AttributeError:
                        pass
                    else:
                        try:
                            all_hidden_values = get_private("all_hidden_values")
                        except AttributeError:
                            pass
                        else:
                            _caller = sys._getframe(1).f_code
                            for _cls in all_hidden_values:
                                if _caller in all_hidden_values[_cls]["auth_codes"]:
                                    break
                            else:
                                raise ProtectedError(f"\"{_caller.co_name}\" is not authorized to use this function")                            
                    
                    methods = {}
                    all_names = object.__dir__(self) # don't trust self.__dir__
                    is_function = api_self.is_function
                    for member_name in all_names:                        
                        try:
                            member = object.__getattribute__(self, member_name)
                        except AttributeError:                
                            continue                      
                        if is_function(member):                            
                            methods[member_name] = member.__code__
                    return methods

                def no_redirect(self, all_hidden_values):
                    def factory(func):
                        def redirection_stopper(*args, **kwargs):
                            obj_will_redirect = "redirect_access" in all_hidden_values[type(self)] and all_hidden_values[type(self)]["redirect_access"] == True
                            try:
                                cls_will_redirect = type.__getattribute__(type(self), "redirect_access")
                            except AttributeError:
                                cls_will_redirect = False
                            if obj_will_redirect:
                                all_hidden_values[type(self)]["redirect_access"] = False                                          
                            if cls_will_redirect:
                                type(self).own_redirect_access = False
                            try:
                                return func(*args, **kwargs)
                            finally:
                                if obj_will_redirect:
                                    all_hidden_values[type(self)]["redirect_access"] = True                                          
                                if cls_will_redirect:
                                    type(self).own_redirect_access = True
                        
                        caller = sys._getframe(1).f_code
                        for cls in all_hidden_values:
                            if caller in all_hidden_values[cls]["auth_codes"]:
                                break
                        else:
                            raise ProtectedError(sys._getframe(1).f_code.co_name, "no_redirect", type(self).__name__)                                                                                                                  
                        redirection_stopper.func = func
                        all_hidden_values[cls]["auth_codes"].add(func.__code__)
                        all_hidden_values[cls]["auth_codes"].add(redirection_stopper.__code__)
                        return redirection_stopper                    
                    return factory

                def no_redirect2(self, hidden_values):
                    def factory(func):
                        def redirection_stopper(*args, **kwargs):
                            obj_will_redirect = "redirect_access" in hidden_values and hidden_values["redirect_access"] == True
                            try:
                                cls_will_redirect = type.__getattribute__(type(self), "redirect_access")
                            except AttributeError:
                                cls_will_redirect = False
                            if obj_will_redirect:
                                hidden_values["redirect_access"] = False                                          
                            if cls_will_redirect:
                                type(self).own_redirect_access = False
                            try:
                                return func(*args, **kwargs)
                            finally:
                                if obj_will_redirect:
                                    hidden_values["redirect_access"] = True                                          
                                if cls_will_redirect:
                                    type(self).own_redirect_access = True
                                                                                                                                         
                        redirection_stopper.func = func
                        hidden_values["auth_codes"].add(func.__code__)
                        hidden_values["auth_codes"].add(redirection_stopper.__code__)
                        return redirection_stopper                    
                    return factory                            
                
                            
                def raise_PrivateError(self, name, depth = 1, class_name = None):
                    depth += 1
                    if class_name is None:
                        all_hidden_values = self.all_hidden_values                    
                        class_name = type(self).__name__
                        if name not in ["hidden_values", "all_hidden_values"]:
                            for cls in all_hidden_values:
                                if name in all_hidden_values[cls]:
                                    class_name = cls.__name__
                                    break
                        elif name == "all_hidden_values":
                            class_name = "AccessEssentials"
                    inherited = False
                    if class_name != type(self).__name__:
                        inherited = True
                    raise PrivateError(sys._getframe(depth).f_code.co_name, name, class_name, inherited = inherited)

                def raise_ProtectedError(self, name, depth = 1):
                    depth += 1
                    class_name = type(self).__name__
                    if name == "all_hidden_values":
                        class_name = "AccessEssentials"                    
                    raise ProtectedError(sys._getframe(depth).f_code.co_name, name, class_name)

                def is_meta_method(self, name, value):
                    if hasattr(self.InsecureRestrictor, name):
                        function = getattr(self.InsecureRestrictor, name)
                        if api_self.is_function(value) and value.__code__ == function.__code__:
                            return True
                    return False                

                def get_base_attr(self, name):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")
                    try:
                        get_private = object.__getattribute__(self, "get_private")
                        type.__delattr__(type(self), "get_private")
                    except AttributeError:
                        pass
                    else:
                        type.__setattr__(type(self), "get_private", get_private.__func__)
                        try:
                            all_hidden_values = get_private("all_hidden_values")
                        except AttributeError:
                            pass
                        else:
                            _caller = sys._getframe(1).f_code
                            for _cls in all_hidden_values:
                                if _caller in all_hidden_values[_cls]["auth_codes"]:
                                    break
                            else:
                                raise ProtectedError(f"\"{_caller.co_name}\" is not authorized to use this function")                            
                    
                    try:
                        value = type(self).get_unbound_base_attr(name)
                    except AttributeError:
                        raise
                    except PrivateError as e:
                        e.caller_name = sys._getframe(1).f_code.co_name
                        e.class_attr = False
                        raise                                                                                
                    if api_self.is_function(value) and type(value) != types.MethodType:
                        value = types.MethodType(value, self)
                    elif type(value) == types.MethodType:
                        raise AttributeError(name)
                    return value
                    
                def get_attr(self, name):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")
                    try:
                        get_private = object.__getattribute__(self, "get_private")
                        type.__delattr__(type(self), "get_private")
                    except AttributeError:
                        pass
                    else:
                        type.__setattr__(type(self), "get_private", get_private.__func__)
                        try:
                            all_hidden_values = get_private("all_hidden_values")
                        except AttributeError:
                            pass
                        else:
                            _caller = sys._getframe(1).f_code
                            for _cls in all_hidden_values:
                                if _caller in all_hidden_values[_cls]["auth_codes"]:
                                    break
                            else:
                                raise ProtectedError(f"\"{_caller.co_name}\" is not authorized to use this function")                            
                    
                    try:
                        value = object.__getattribute__(self, name)
                    except AttributeError as e:
                        try:
                            value = AccessEssentials.get_base_attr(self, name)
                        except AttributeError:
                            raise e
                        except PrivateError as e:
                            e.caller_name = sys._getframe(1).f_code.co_name
                            raise
                    else:                                    
                        is_builtin_new = name == "_new_" and value == object.__new__
                        is_builtin_new2 = name == "__new__" and value == object.__new__
                        is_builtin_in = type(value) == types.MethodWrapperType
                        if is_builtin_new or is_builtin_new2 or is_builtin_in:
                            try:
                                value2 = AccessEssentials.get_base_attr(self, name)
                                if type(value2) != types.WrapperDescriptorType:
                                    value = value2                                                
                            except AttributeError:
                                pass
                            except PrivateError as e:
                                e.caller_name = sys._getframe(1).f_code.co_name
                                raise                        
                    return value

                def get_member(self, hidden_values, name):
                    if name in hidden_values:
                        return hidden_values[name]
                    elif hasattr(AccessEssentials, name):
                        func = getattr(AccessEssentials, name)
                        if api_self.is_function(func) and type(func) != types.MethodType:                            
                            return types.MethodType(func, self)
                    return object.__getattribute__(self, name)
                    
                def is_subclass_method(self, all_hidden_values, depth = 1, return_subclass = False):
                    def get_all_subclasses(cls):
                        """We have to duplicate this function for performance reasons"""
                        all_subclasses = []
                        for subclass in type.__getattribute__(cls, "__subclasses__")():
                            all_subclasses.append(subclass)
                            all_subclasses.extend(get_all_subclasses(subclass))
                        all_subclasses = list(set(all_subclasses))
                        return all_subclasses

                    def get_all_subclasses2(cls):
                        """We have to duplicate this function for performance reasons"""
                        all_subclasses = []
                        for subclass in cls._subclasses_:
                            all_subclasses.append(subclass)
                        all_subclasses = list(set(all_subclasses))
                        return all_subclasses
                    
                    def is_function(func):
                        """We have to duplicate this function for performance reasons"""
                        try:
                            code = object.__getattribute__(func, "__code__")
                        except AttributeError:
                            has_code = type(func) == types.MethodType
                        else:
                            has_code = True
                        if callable(func) and has_code and type(func.__code__) == types.CodeType:
                            return True
                        else:
                            return False                    
                    
                    depth += 1          
                    caller = sys._getframe(depth).f_code
                    subclasses = get_all_subclasses(type(self))                  
                    for subclass in subclasses:
                        for member in subclass.__dict__.values():
                            if is_function(member) and member.__code__ == caller and not return_subclass:
                                return True
                            elif is_function(member) and member.__code__ == caller:
                                return True, subclass.cls.own_all_hidden_values[type(subclass.cls)]["cls"]
                    if "cls" in all_hidden_values[type(self)]:
                        subclasses = get_all_subclasses2(all_hidden_values[type(self)]["cls"])
                    else:
                        subclasses = get_all_subclasses2(type(self))                    
                    for subclass in subclasses:
                        try:
                            member = type.__getattribute__(subclass, caller.co_name)
                        except AttributeError:
                            pass
                        else:
                            if is_function(member) and type(member) != types.MethodType and member.__code__ == caller and not return_subclass:
                                return True
                            elif is_function(member) and type(member) != types.MethodType and member.__code__ == caller:                                
                                return True, subclass
                            try:
                                type.__getattribute__(subclass, "_new_")
                            except AttributeError:
                                pass
                            else:
                                member = subclass._new_
                                if is_function(member) and member.__code__ == caller and not return_subclass:
                                    return True
                                elif is_function(member) and member.__code__ == caller:
                                    return True, subclass
                    if not return_subclass:
                        return False
                    else:
                        return False, None

                def check_caller(self, all_hidden_values, depth = 1, name = "hidden_values"):
                    """Go depth frames back in stack and check if the associated caller is authorized to access the name

                    Name is assumed to be either private or protected.
                    This function should not be called if the name is public.
                    Because even if it's public, it'll be treated as if it were private.
                    In that case, return value will probably be wrong."""
                    def is_function(func):
                        """We have to duplicate this function for performance reasons"""
                        try:
                            code = object.__getattribute__(func, "__code__")
                        except AttributeError:
                            has_code = type(func) == types.MethodType
                        else:
                            has_code = True
                        if callable(func) and has_code and type(func.__code__) == types.CodeType:
                            return True
                        else:
                            return False
                    
                    def get_base_attr(name):
                        """static_dict check would cause infinite recursion, so we have to duplicate this function."""
                        try:
                            value = type(self).get_unbound_base_attr(name)
                        except AttributeError:
                            raise
                        except PrivateError as e:
                            e.caller_name = sys._getframe(1).f_code.co_name
                            e.class_attr = False
                            raise                                                                                
                        if is_function(value) and type(value) != types.MethodType:
                            value = types.MethodType(value, self)
                        elif type(value) == types.MethodType:
                            raise AttributeError(name)
                        return value

                    def get_member(self, hidden_values, name):
                        """We have to duplicate this function because we can't trust AccessEssentials.get_member
                        This function must be read only and immutable, not just protected.
                        Otherwise derived classes could bypass private members of their bases.
                        Functions aren't immutable in python so we completely hide it this way."""
                        if name in hidden_values:
                            return hidden_values[name]
                        elif hasattr(AccessEssentials, name):
                            func = getattr(AccessEssentials, name)
                            if is_function(func) and type(func) != types.MethodType:                            
                                return types.MethodType(func, self)
                        return object.__getattribute__(self, name)                    
                    
                    depth += 1
                    common_names = ["_privates_",
                                    "_protecteds_",
                                    "_publics_",
                                    "AccessEssentials2",
                                    "AccessEssentials3",
                                    "InsecureRestrictor",
                                    "private",
                                    "protected",
                                    "public"]                    
                    caller = sys._getframe(depth).f_code
                    all_privates = []
                    for cls in all_hidden_values:
                        if "_privates_" in all_hidden_values[cls]:
                            all_privates.extend(all_hidden_values[cls]["_privates_"])
                    all_protecteds = []
                    for cls in all_hidden_values:
                        if "_protecteds_" in all_hidden_values[cls]:
                            all_protecteds.extend(all_hidden_values[cls]["_protecteds_"])
                    base_protecteds = type.__getattribute__(type(self), "base_protecteds")
                    base_privates = type.__getattribute__(type(self), "base_privates")
                    all_classes = list(all_hidden_values.keys())
                    AccessEssentials = all_classes[-1]                    
                    if name == "hidden_values":
                        for cls in all_hidden_values:
                            if caller in all_hidden_values[cls]["auth_codes"]:
                                return True                            
                    elif name == "all_hidden_values":
                        if caller in all_hidden_values[AccessEssentials]["auth_codes"]:
                            return True                        
                    else:                        
                        is_public = False
                        try:
                            class_id = type.__getattribute__(type(self), "class_id")
                        except AttributeError:
                            has_class_id = False
                        else:
                            has_class_id = True                            
                        if has_class_id and class_id == "access_modifiers.SecureClass":
                            for cls in all_hidden_values:
                                cls_has_name = name in all_hidden_values[cls] or \
                                               (cls == type(self) and "cls" in all_hidden_values[cls] and name in all_hidden_values[cls]["cls"]._privates_)
                                if cls_has_name and (name not in common_names or caller in all_hidden_values[cls]["auth_codes"]):
                                    break
                            else:
                                for cls in all_hidden_values:
                                    if "_publics_" in all_hidden_values[cls] and name in all_hidden_values[cls]["_publics_"]:
                                        is_public = True
                                        break
                        else:                        
                            for cls in all_hidden_values:
                                if name in all_hidden_values[cls] and (name not in common_names or caller in all_hidden_values[cls]["auth_codes"]):
                                    break
                            else:
                                for cls in all_hidden_values:
                                    if "_publics_" in all_hidden_values[cls] and name in all_hidden_values[cls]["_publics_"]:
                                        is_public = True
                                        break
                                    
                        if caller in all_hidden_values[cls]["auth_codes"]:
                            return True                        
                        for base in cls.__mro__:
                            if base is object:
                                break
                            try:
                                base = type.__getattribute__(base, "protected_gate")
                            except AttributeError:
                                pass
                            else:
                                base = base.cls.own_all_hidden_values[type(base.cls)]["cls"]                          
                            InsecureRestrictor = get_member(self, all_hidden_values[AccessEssentials], "InsecureRestrictor")
                            if InsecureRestrictor.is_access_essentials(base):
                                base = AccessEssentials                            
                            if caller in all_hidden_values[base]["auth_codes"]:
                                return True
                        if name in all_protecteds or is_public:
                            private_base_holders = []
                            for cls2 in reversed(all_hidden_values.keys()):
                                if hasattr(cls2, "private_bases") and cls2.private_bases != []:
                                    broken = False
                                    for private_base in cls2.private_bases:
                                        if not isinstance(private_base, type):
                                            private_base = private_base.own_all_hidden_values[type(private_base)]["cls"]
                                            for cls3 in private_base.__mro__:
                                                try:
                                                    cls3 = type.__getattribute__(cls3, "protected_gate")
                                                except AttributeError:
                                                    pass
                                                else:
                                                    cls3 = cls3.cls.own_all_hidden_values[type(cls3.cls)]["cls"]
                                                if cls3 == cls:
                                                    private_base_holders.append(cls2)
                                                    broken = True
                                                    break
                                        if broken:
                                            break
                            for cls4 in all_hidden_values:
                                if cls4 in cls._subclasses_ and caller in all_hidden_values[cls4]["auth_codes"]:
                                    if private_base_holders == []:
                                        return True
                                    if all(cls4 not in private_base_holder._subclasses_ for private_base_holder in private_base_holders):
                                        return True                                    

                        for caller_class in all_hidden_values:
                            if caller in all_hidden_values[caller_class]["auth_codes"]:
                                external_caller = False
                                break
                        else:
                            external_caller = True
                        classes = []
                        for cls in all_hidden_values:
                            try:
                                type.__getattribute__(cls, "_privates_")
                            except AttributeError:
                                class_has = False
                            else:
                                class_has = True                                
                            if class_has and (name in cls._privates_ or name in cls.base_privates or name in cls._publics_):
                                classes.append(cls)
                                if all_classes.index(cls) >= all_classes.index(caller_class) or external_caller:
                                    break
                        else:
                            if classes != []:
                                cls = classes[-1]
                        if caller in all_hidden_values[cls]["auth_codes"]:
                            return True
                        for base in cls.__mro__:
                            if base is object:
                                break
                            try:
                                base = type.__getattribute__(base, "protected_gate")
                            except AttributeError:
                                pass
                            else:
                                base = base.cls.own_all_hidden_values[type(base.cls)]["cls"]                            
                            InsecureRestrictor = get_member(self, all_hidden_values[AccessEssentials], "InsecureRestrictor")
                            if InsecureRestrictor.is_access_essentials(base):
                                base = AccessEssentials
                            if caller in all_hidden_values[base]["auth_codes"]:
                                return True
                        if name not in all_privates:
                            try:
                                class_id = type.__getattribute__(type(self), "class_id")
                            except AttributeError:
                                has_class_id = False
                            else:
                                has_class_id = True
                                
                            if has_class_id and class_id == "access_modifiers.SecureClass" and "cls" in all_hidden_values[type(self)]:
                                raw_class = all_hidden_values[type(self)]["cls"]
                            else:
                                raw_class = type(self)
                                
                            if hasattr(caller_class, "is_protected"):
                                is_protected = caller_class.is_protected(name)
                            else:
                                is_protected = name in caller_class._protecteds_                                
                            if not is_protected:
                                try:
                                    class_id = type.__getattribute__(type(self), "class_id")
                                except AttributeError:
                                    has_class_id = False
                                else:
                                    has_class_id = True
                                    
                                if has_class_id and class_id == "access_modifiers.SecureClass" and "cls" in all_hidden_values[type(self)]:
                                    raw_class = all_hidden_values[type(self)]["cls"]
                                    if hasattr(raw_class, "is_protected"):
                                        is_protected = raw_class.is_protected(name)
                                    else:
                                        is_protected = name in raw_class._protecteds_                                        
                                        
                            if is_protected:
                                for cls2 in all_hidden_values:
                                    if cls2 in cls._subclasses_ and caller in all_hidden_values[cls2]["auth_codes"]:
                                        return True
                                for cls2 in cls._subclasses_:                       
                                    for member_name in cls2.__dict__:
                                        member = cls2.__dict__[member_name]
                                        if is_function(member) and member.__code__ == caller:
                                            return True
                                                                    
                    is_subclass_method = types.MethodType(get_member(self, all_hidden_values[AccessEssentials], "AccessEssentials2").is_subclass_method, self)                    
                    try:
                        class_id = type.__getattribute__(type(self), "class_id")
                    except AttributeError:
                        has_class_id = False
                    else:
                        has_class_id = True
                        
                    if has_class_id and class_id == "access_modifiers.SecureClass" and "cls" in all_hidden_values[type(self)]:
                        cls = all_hidden_values[type(self)]["cls"]
                    else:
                        cls = type(self)
                    is_protected = name in all_protecteds or (name in base_protecteds and name not in all_privates and cls.is_protected(name))
                    if is_protected and is_subclass_method(all_hidden_values, depth = depth):                        
                        return True                    
                    return False

                def authorize(self, func_or_cls, for_all = True):
                    """Allow func_or_cls to access private/protected members of this object

                    This function acts like the "friend" keyword of c++"""
                    def is_function(func):
                        """We have to duplicate this function for performance reasons"""
                        try:
                            code = object.__getattribute__(func, "__code__")
                        except AttributeError:
                            has_code = type(func) == types.MethodType
                        else:
                            has_code = True
                        if callable(func) and has_code and type(func.__code__) == types.CodeType:
                            return True
                        else:
                            return False
                    
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")
                    try:
                        get_private = object.__getattribute__(self, "get_private")
                        type.__delattr__(type(self), "get_private")
                    except AttributeError:
                        pass
                    else:
                        type.__setattr__(type(self), "get_private", get_private.__func__)
                        try:
                            all_hidden_values = get_private("all_hidden_values")
                        except AttributeError:
                            pass
                        else:
                            _caller = sys._getframe(1).f_code                            
                            for _cls in all_hidden_values:
                                if _caller in all_hidden_values[_cls]["auth_codes"]:
                                    break
                            else:
                                raise ProtectedError(f"\"{_caller.co_name}\" is not authorized to use this function")                            
                    
                    get_private = object.__getattribute__(self, "get_private")
                    all_hidden_values = get_private("all_hidden_values")
                    caller = sys._getframe(1).f_code
                    broken = False
                    for cls in all_hidden_values:
                        __dict__ = type.__getattribute__(cls, "__dict__")
                        for member_name in __dict__:
                            member = __dict__[member_name]
                            if is_function(member) and member.__code__ == caller:                                
                                broken = True
                                break
                        if broken:
                            break                        
                    else:
                        for cls in all_hidden_values:                            
                            if caller in all_hidden_values[cls]["auth_codes"]:                                
                                break
                        else:
                            self.raise_ProtectedError("authorize")
                    if cls == list(all_hidden_values.keys())[0]:
                        change_class = True
                    else:
                        change_class = False
                    if is_function(func_or_cls) and for_all:
                        all_hidden_values[cls]["auth_codes"].add(func_or_cls.__code__)
                        if hasattr(cls, "secure_class"):
                            cls.secure_class.own_all_hidden_values[type(cls.secure_class)]["auth_codes"].add(func_or_cls.__code__)
                        for obj in type.__getattribute__(type(self), "objs"):
                            obj = obj.own_all_hidden_values[type(obj)]["inst"]
                            if change_class:
                                cls = type(obj)
                            get_private = object.__getattribute__(obj, "get_private")
                            all_hidden_values2 = get_private("all_hidden_values")
                            all_hidden_values2[cls]["auth_codes"].add(func_or_cls.__code__)
                    elif is_function(func_or_cls):
                        all_hidden_values[cls]["auth_codes"].add(func_or_cls.__code__)
                    else:
                        for name in dir(func_or_cls):
                            member = getattr(func_or_cls, name)
                            try:
                                isinstance(member, AccessError)
                            except RuntimeError:
                                pass
                            else:
                                if isinstance(member, AccessError):
                                    member = getattr(func_or_cls.own_all_hidden_values[type(func_or_cls)]["cls"], name)
                            if is_function(member) and for_all:
                                all_hidden_values[cls]["auth_codes"].add(member.__code__)
                                if hasattr(cls, "secure_class"):
                                    cls.secure_class.own_all_hidden_values[type(cls.secure_class)]["auth_codes"].add(member.__code__)
                                for obj in type.__getattribute__(type(self), "objs"):
                                    obj = obj.own_all_hidden_values[type(obj)]["inst"]
                                    if change_class:
                                        cls = type(obj)                                    
                                    get_private = object.__getattribute__(obj, "get_private")
                                    all_hidden_values2 = get_private("all_hidden_values")
                                    all_hidden_values2[cls]["auth_codes"].add(member.__code__)
                            elif is_function(member):
                                all_hidden_values[cls]["auth_codes"].add(member.__code__)
                    
                def internal_get_hidden_value(self, all_hidden_values, value, name = "all_hidden_values"):
                    def is_function(func):
                        """We have to duplicate this function for performance reasons"""
                        try:
                            code = object.__getattribute__(func, "__code__")
                        except AttributeError:
                            has_code = type(func) == types.MethodType
                        else:
                            has_code = True
                        if callable(func) and has_code and type(func.__code__) == types.CodeType:
                            return True
                        else:
                            return False
                    
                    def get_member(self, hidden_values, name):
                        """We have to duplicate this function because we can't trust AccessEssentials.get_member
                        This function must be read only and immutable, not just protected.
                        Otherwise derived classes could bypass private members of their bases.
                        Functions aren't immutable in python so we completely hide it this way."""                                                           
                        if name in hidden_values:
                            return hidden_values[name]                                
                        elif hasattr(AccessEssentials, name):
                            func = getattr(AccessEssentials, name)
                            if is_function(func) and type(func) != types.MethodType:                            
                                return types.MethodType(func, self)
                        return object.__getattribute__(self, name)                    

                    AccessEssentials = list(all_hidden_values.keys())[-1]
                    AccessEssentials2 = get_member(self, all_hidden_values[AccessEssentials], "AccessEssentials2")
                    if not hasattr(AccessEssentials2, "check_caller"):
                        AccessEssentials2 = api_self.AccessEssentials
                    check_caller = types.MethodType(AccessEssentials2.check_caller, self)
                    class CellProtector:
                        def __get__(self, instance, owner):                            
                            if check_caller(all_hidden_values, name = name) and type(instance) == HiddenValue:
                                return value
                            else:
                                raise PrivateError(f"\"{sys._getframe(1).f_code.co_name}\" is not allowed to access this object")
                 
                    self.authorize(CellProtector.__get__)
                    class ClassProtector(type):
                        __slots__ = []
                        
                        @property
                        def __dict__(self):
                            raise PrivateError("Nope, no ez bypass here :D")
                        
                    class HiddenValue(metaclass = ClassProtector):            
                        __slots__ = []            
                        value = CellProtector()
                    hidden_value = HiddenValue()
                    return hidden_value

                def get_hidden_value(self, value, name = None):
                    if name is None:
                        name = "hidden_values"
                    return self.internal_get_hidden_value(self.all_hidden_values, value, name = name)
                
                def create_get_private(self, all_hidden_values, enforce = True):
                    hidden_store = self.get_private("hidden_store")
                    AccessEssentials = list(all_hidden_values.keys())[-1]
                    def get_private(self, name):
                        """Return the requested private/protected member if the caller is authorized to access it."""
                        def get_base_attr(name):
                            """static_dict check would cause infinite recursion, so we have to duplicate this function."""
                            try:
                                value = getattr(type(self), name)
                            except AttributeError:
                                raise
                            except PrivateError as e:
                                e.caller_name = sys._getframe(1).f_code.co_name
                                e.class_attr = False
                                raise
                            
                            is_function = callable(value) and hasattr(value, "__code__") and type(value.__code__) == types.CodeType
                            if is_function and type(value) != types.MethodType:
                                value = types.MethodType(value, self)
                            elif type(value) == types.MethodType:
                                raise AttributeError(name)
                            return value
                            
                        def get_attr(name):
                            """static_dict check would cause infinite recursion, so we have to duplicate this function."""
                            try:
                                value = object.__getattribute__(self, name)
                            except AttributeError as e:
                                try:
                                    value = get_base_attr(name)
                                except AttributeError:
                                    raise e
                                except PrivateError as e:
                                    e.caller_name = sys._getframe(1).f_code.co_name
                                    raise
                            else:                                    
                                is_builtin_new = name == "_new_" and value == object.__new__
                                is_builtin_new2 = name == "__new__" and value == object.__new__
                                is_builtin_in = type(value) == types.MethodWrapperType
                                if is_builtin_new or is_builtin_new2 or is_builtin_in:
                                    try:
                                        value2 = get_base_attr(name)
                                        if type(value2) != types.WrapperDescriptorType:
                                            value = value2                                                
                                    except AttributeError:
                                        pass
                                    except PrivateError as e:
                                        e.caller_name = sys._getframe(1).f_code.co_name
                                        raise
                                if type(value) == types.MethodType and value.__self__ == type(self) and not is_meta_method(self, name, value):                                
                                    value = value.__func__
                                    value = types.MethodType(value, type(self).secure_class)                                    
                            return value                                          

                        def is_function(func):
                            """We have to duplicate this function for performance reasons"""
                            try:
                                code = object.__getattribute__(func, "__code__")
                            except AttributeError:
                                has_code = type(func) == types.MethodType
                            else:
                                has_code = True
                            if callable(func) and has_code and type(func.__code__) == types.CodeType:
                                return True
                            else:
                                return False

                        def is_meta_method(self, name, value):
                            if hasattr(all_hidden_values[AccessEssentials]["InsecureRestrictor"], name):
                                function = getattr(all_hidden_values[AccessEssentials]["InsecureRestrictor"], name)
                                if is_function(value) and value.__code__ == function.__code__:
                                    return True
                            return False                

                        def force_get_attr(bases, name):
                            """We have to duplicate this function because it can't be a part of the library api.
                            Otherwise that would cause a loophole"""
                            for base in bases:
                                try:
                                    pg = type.__getattribute__(base, "protected_gate")                            
                                except AttributeError:                            
                                    continue
                                hidden_values = pg.cls.own_all_hidden_values[type(pg.cls)]
                                cls = hidden_values["cls"]
                                try:
                                    value = type.__getattribute__(cls, name)
                                except AttributeError:
                                    try:
                                        return force_get_attr(cls.__bases__, name)     
                                    except AttributeError:
                                        continue
                                else:
                                    if api_self.is_function(value) and type(value) != types.MethodType:
                                        value = types.MethodType(value, self)
                                    elif is_meta_method(self, name, value):                                            
                                        continue
                                    elif type(value) == types.MethodType:
                                        value = value.__func__
                                        value = types.MethodType(value, type(self).secure_class)
                                    return value                                    
                            raise AttributeError(name)                                          
                            
                        def get_member(self, hidden_values, name):
                            """We have to duplicate this function because we can't trust AccessEssentials.get_member
                            This function must be read only and immutable, not just protected.
                            Otherwise derived classes could bypass private members of their bases.
                            Functions aren't immutable in python so we completely hide it this way."""                        
                            if name in hidden_values:
                                return hidden_values[name]
                            elif hasattr(AccessEssentials, name):
                                func = getattr(AccessEssentials, name)
                                if api_self.is_function(func) and type(func) != types.MethodType:                            
                                    return types.MethodType(func, self)
                            return object.__getattribute__(self, name)                    

                        def get_private(self, all_hidden_values, name):                            
                            common_names = ["_privates_",
                                            "_protecteds_",
                                            "_publics_",
                                            "AccessEssentials2",
                                            "AccessEssentials3",
                                            "InsecureRestrictor",
                                            "private",
                                            "protected",
                                            "public"]                            
                            AccessEssentials2 = get_member(self, all_hidden_values[AccessEssentials], "AccessEssentials2")
                            if not hasattr(AccessEssentials2, "check_caller"):
                                AccessEssentials2 = api_self.AccessEssentials
                            check_caller = types.MethodType(AccessEssentials2.check_caller, self)
                            authorized_caller = check_caller(all_hidden_values, depth = 2, name = name)
                            caller = sys._getframe(2).f_code
                            if name not in ["hidden_values", "all_hidden_values"]:
                                try:                                    
                                    if name in common_names:
                                        for cls in all_hidden_values:
                                            if caller in all_hidden_values[cls]["auth_codes"]:                                                
                                                value = all_hidden_values[cls][name]
                                                break
                                        else:
                                            raise KeyError
                                    else:    
                                        for cls in all_hidden_values:
                                            if name in all_hidden_values[cls]:
                                                value = all_hidden_values[cls][name]
                                                break
                                        else:
                                            raise KeyError
                                except KeyError:
                                    try:
                                        value = get_base_attr(name)
                                    except AttributeError:
                                        class_name = type(self).__name__
                                        class_name = "\"" + class_name + "\""
                                        error = class_name + " object has no private attribute " + "\"" + name + "\""
                                        raise AttributeError(error)
                                    except PrivateError as e:
                                        if not authorized_caller:
                                            e.caller_name = sys._getframe(2).f_code.co_name
                                            raise
                                        else:
                                            value = force_get_attr(type(self).__bases__, name)
                                    if type(self).is_public(name):
                                        class_name = type(self).__name__
                                        class_name = "\"" + class_name + "\""
                                        error = class_name + " object has no private attribute " + "\"" + name + "\""
                                        raise AttributeError(error)
                            elif name == "hidden_values":                                
                                for cls in all_hidden_values:
                                    if caller in all_hidden_values[cls]["auth_codes"]:
                                        break
                                else:
                                    self.raise_PrivateError(name, depth = 2)
                                value = all_hidden_values[cls]
                            else:
                                value = all_hidden_values
                                
                            all_privates = []
                            for cls in all_hidden_values:
                                if "_privates_" in all_hidden_values[cls]:
                                    all_privates.extend(all_hidden_values[cls]["_privates_"])
                            all_protecteds = []
                            for cls in all_hidden_values:
                                if "_protecteds_" in all_hidden_values[cls]:
                                    all_protecteds.extend(all_hidden_values[cls]["_protecteds_"])                                
                            if authorized_caller or enforce == False:              
                                return value
                            elif name in all_protecteds or (name in self.base_protecteds and name not in all_privates and type(self).is_protected(name)):
                                if name in all_privates:
                                    for cls in all_hidden_values:
                                        if name in all_hidden_values[cls]:
                                            break                                        
                                    broken = False
                                    for cls2 in reversed(all_hidden_values.keys()):
                                        if hasattr(cls2, "private_bases") and cls2.private_bases != []:
                                            for private_base in cls2.private_bases:
                                                if not isinstance(private_base, type):
                                                    private_base = private_base.own_all_hidden_values[type(private_base)]["cls"]
                                                for cls3 in private_base.__mro__:
                                                    try:
                                                        cls3 = type.__getattribute__(cls3, "protected_gate")
                                                    except AttributeError:
                                                        pass
                                                    else:
                                                        cls3 = cls3.cls.own_all_hidden_values[type(cls3.cls)]["cls"]
                                                    if cls3 == cls:
                                                        self.raise_PrivateError(name, depth = 2, class_name = cls2.__name__)                                
                                self.raise_ProtectedError(name, depth = 2)
                            else:
                                self.raise_PrivateError(name, depth = 2)

                        all_hidden_values = hidden_store.value.all_hidden_values
                        all_hidden_values[AccessEssentials]["auth_codes"].add(force_get_attr.__code__)
                        all_hidden_values[AccessEssentials]["auth_codes"].add(get_private.__code__)
                        
                        # inlining no_redirect for performance reasons
                        obj_will_redirect = "redirect_access" in all_hidden_values[type(self)] and all_hidden_values[type(self)]["redirect_access"] == True
                        try:
                            cls_will_redirect = type.__getattribute__(type(self), "redirect_access")
                        except AttributeError:
                            cls_will_redirect = False
                        if obj_will_redirect:
                            all_hidden_values[type(self)]["redirect_access"] = False                                          
                        if cls_will_redirect:
                            type(self).own_redirect_access = False
                        try:
                            return get_private(self, all_hidden_values, name)
                        finally:
                            if obj_will_redirect:
                                all_hidden_values[type(self)]["redirect_access"] = True                                          
                            if cls_will_redirect:
                                type(self).own_redirect_access = True

                    all_hidden_values[AccessEssentials]["auth_codes"].add(get_private.__code__)
                    type(self)._publics_.append("get_private")
                    get_private(self, "hidden_values")
                    return get_private                    

                def create_getattribute(self, depth = 2, enforce = True):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")
                    try:
                        get_private = object.__getattribute__(self, "get_private")
                        type.__delattr__(type(self), "get_private")
                    except AttributeError:
                        pass
                    else:
                        type.__setattr__(type(self), "get_private", get_private.__func__)
                        try:
                            all_hidden_values = get_private("all_hidden_values")
                        except AttributeError:
                            pass
                        else:
                            _caller = sys._getframe(1).f_code
                            for _cls in all_hidden_values:
                                if _caller in all_hidden_values[_cls]["auth_codes"]:
                                    break
                            else:
                                raise ProtectedError(f"\"{_caller.co_name}\" is not authorized to use this function")                            
                    
                    get_private = object.__getattribute__(self, "get_private")
                    all_hidden_values = get_private("all_hidden_values")
                    AccessEssentials = list(all_hidden_values.keys())[-1]
                    hidden_store = all_hidden_values[AccessEssentials]["hidden_store"]
                    no_redirect = types.MethodType(api_self.AccessEssentials.no_redirect, self)
                    @no_redirect(get_private("all_hidden_values"))
                    def create_getattribute(self, depth, enforce = True):                    
                        depth += 4
                        def _getattribute_(self, name):
                            def is_meta_method(self, name, value):
                                if hasattr(all_hidden_values[AccessEssentials]["InsecureRestrictor"], name):
                                    function = getattr(all_hidden_values[AccessEssentials]["InsecureRestrictor"], name)
                                    if is_function(value) and value.__code__ == function.__code__:
                                        return True
                                return False                
                            
                            def get_base_attr(name):
                                """static_dict check would cause infinite recursion, so we have to duplicate this function."""
                                try:
                                    value = getattr(type(self), name)
                                except AttributeError:
                                    raise
                                except PrivateError as e:                                    
                                    e.caller_name = sys._getframe(1).f_code.co_name
                                    e.class_attr = False
                                    raise
                                
                                is_function = callable(value) and hasattr(value, "__code__") and type(value.__code__) == types.CodeType
                                if is_function and type(value) != types.MethodType:
                                    value = types.MethodType(value, self)
                                elif is_meta_method(self, name, value):
                                    raise AttributeError(name)
                                return value
                                
                            def get_attr(name):
                                """static_dict check would cause infinite recursion, so we have to duplicate this function."""
                                try:
                                    value = object.__getattribute__(self, name)
                                except AttributeError as e:
                                    try:
                                        value = get_base_attr(name)                                        
                                    except AttributeError:
                                        raise e
                                    except PrivateError as e:                                        
                                        e.caller_name = sys._getframe(1).f_code.co_name
                                        raise
                                else:                                    
                                    is_builtin_new = name == "_new_" and value == object.__new__
                                    is_builtin_new2 = name == "__new__" and value == object.__new__
                                    is_builtin_in = type(value) == types.MethodWrapperType
                                    if is_builtin_new or is_builtin_new2 or is_builtin_in:
                                        try:
                                            value2 = get_base_attr(name)
                                            if type(value2) != types.WrapperDescriptorType:
                                                value = value2                                                
                                        except AttributeError:
                                            pass
                                        except PrivateError as e:
                                            e.caller_name = sys._getframe(1).f_code.co_name
                                            raise
                                    if type(value) == types.MethodType and value.__self__ == type(self) and not is_meta_method(self, name, value):                                
                                        value = value.__func__
                                        value = types.MethodType(value, type(self).secure_class)
                                        
                                return value

                            def force_get_attr(bases, name):
                                """We have to duplicate this function because it can't be a part of the library api.
                                Otherwise that would cause a loophole"""
                                for base in bases:                                    
                                    try:
                                        pg = type.__getattribute__(base, "protected_gate")                            
                                    except AttributeError:                            
                                        continue                                    
                                    hidden_values = pg.cls.own_all_hidden_values[type(pg.cls)]
                                    cls = hidden_values["cls"]
                                    try:
                                        value = type.__getattribute__(cls, name)                                        
                                    except AttributeError:                                        
                                        try:
                                            return force_get_attr(cls.__bases__, name)     
                                        except AttributeError:
                                            continue
                                    else:
                                        if api_self.is_function(value) and type(value) != types.MethodType:
                                            value = types.MethodType(value, self)
                                        elif is_meta_method(self, name, value):                                            
                                            continue
                                        elif type(value) == types.MethodType:
                                            value = value.__func__
                                            value = types.MethodType(value, type(self).secure_class)
                                        return value                                    
                                raise AttributeError(name)

                            def is_function(func):
                                """We have to duplicate this function for performance reasons"""
                                try:
                                    code = object.__getattribute__(func, "__code__")
                                except AttributeError:
                                    has_code = type(func) == types.MethodType
                                else:
                                    has_code = True
                                if callable(func) and has_code and type(func.__code__) == types.CodeType:
                                    return True
                                else:
                                    return False
                            
                            def get_member(self, hidden_values, name):
                                """We have to duplicate this function because we can't trust AccessEssentials.get_member
                                This function must be read only and immutable, not just protected.
                                Otherwise derived classes could bypass private members of their bases.
                                Functions aren't immutable in python so we completely hide it this way."""                                                           
                                if name in hidden_values:
                                    return hidden_values[name]                                
                                elif hasattr(AccessEssentials, name):
                                    func = getattr(AccessEssentials, name)
                                    if is_function(func) and type(func) != types.MethodType:                            
                                        return types.MethodType(func, self)
                                return object.__getattribute__(self, name)                    
                                                        
                            def _getattribute_(self, name):
                                public_names = ["_privates_",
                                                "_protecteds_",
                                                "_class_",
                                                "__bases__",
                                                "__mro__",
                                                "_mro",
                                                "_bases",
                                                "base_publics",
                                                "base_protecteds",
                                                "base_privates"]
                                common_names = ["_privates_",
                                                "_protecteds_",
                                                "_publics_",
                                                "AccessEssentials2",
                                                "AccessEssentials3",
                                                "InsecureRestrictor",
                                                "private",
                                                "protected",
                                                "public"]
                                
                                all_privates = []
                                for cls in all_hidden_values:
                                    if "_privates_" in all_hidden_values[cls]:
                                        all_privates.extend(all_hidden_values[cls]["_privates_"])
                                all_protecteds = []
                                for cls in all_hidden_values:
                                    if "_protecteds_" in all_hidden_values[cls]:
                                        all_protecteds.extend(all_hidden_values[cls]["_protecteds_"])
                                all_publics = []
                                for cls in all_hidden_values:
                                    if "_publics_" in all_hidden_values[cls]:
                                        all_publics.extend(all_hidden_values[cls]["_publics_"])                                        

                                caller = sys._getframe(depth).f_code
                                
                                is_private = name in all_privates or name in ["hidden_values", "all_hidden_values"]
                                is_base_protected = False
                                class_name = None
                                if not is_private:
                                    try:
                                        value = object.__getattribute__(self, name)
                                        object.__delattr__(self, name)                                        
                                    except AttributeError:
                                        try:
                                            is_private = hasattr(type(self), name) and not type(self).is_public(name)
                                        except PrivateError:                                            
                                            is_private = False # will skip to else clause                                            
                                        if is_private and type(self).is_protected(name):
                                            is_base_protected = True

                                    except TypeError: # name is "__class__"
                                        pass
                                    else:
                                        object.__setattr__(self, name, value)
                                        broken = False
                                        for cls in all_hidden_values:
                                            if "_publics_" in all_hidden_values[cls] and name in all_hidden_values[cls]["_publics_"]:                                
                                                for cls2 in reversed(all_hidden_values.keys()):
                                                    if hasattr(cls2, "private_bases") and cls2.private_bases != []:
                                                        for private_base in cls2.private_bases:
                                                            if not isinstance(private_base, type):
                                                                private_base = private_base.own_all_hidden_values[type(private_base)]["cls"]
                                                            for cls3 in private_base.__mro__:
                                                                try:
                                                                    cls3 = type.__getattribute__(cls3, "protected_gate")
                                                                except AttributeError:
                                                                    pass
                                                                else:
                                                                    cls3 = cls3.cls.own_all_hidden_values[type(cls3.cls)]["cls"]
                                                                if cls3 == cls:
                                                                    for cls4 in all_hidden_values:
                                                                        if caller in all_hidden_values[cls4]["auth_codes"]:
                                                                            break
                                                                    else:
                                                                        cls4 = type(self)
                                                                    if cls4 in cls2._subclasses_:                                                                
                                                                        is_private = True
                                                                        class_name = cls2.__name__
                                                                        broken = True
                                                                        break
                                                            if broken:
                                                                break
                                                        if broken:
                                                            break
                                                    if hasattr(cls2, "protected_bases") and cls2.protected_bases != []:
                                                        for protected_base in cls2.protected_bases:
                                                            if not isinstance(protected_base, type):
                                                                protected_base = protected_base.own_all_hidden_values[type(protected_base)]["cls"]
                                                            for cls3 in protected_base.__mro__:
                                                                try:
                                                                    cls3 = type.__getattribute__(cls3, "protected_gate")
                                                                except AttributeError:
                                                                    pass
                                                                else:
                                                                    cls3 = cls3.cls.own_all_hidden_values[type(cls3.cls)]["cls"]
                                                                if cls3 == cls:
                                                                    for cls4 in all_hidden_values:
                                                                        if caller in all_hidden_values[cls4]["auth_codes"]:
                                                                            break
                                                                    else:
                                                                        cls4 = type(self)
                                                                    if cls4 in cls2._subclasses_:                                                                
                                                                        is_private = True
                                                                        is_base_protected = True
                                                                        broken = True
                                                                        break
                                                            if broken:
                                                                break
                                                        if broken:
                                                            break
                                                if broken:
                                                    break                                                
                                AccessEssentials2 = get_member(self, all_hidden_values[AccessEssentials], "AccessEssentials2")
                                if not hasattr(AccessEssentials2, "check_caller"):
                                    AccessEssentials2 = api_self.AccessEssentials
                                check_caller = types.MethodType(AccessEssentials2.check_caller, self)
                                authorized_caller = check_caller(all_hidden_values, depth = depth, name = name)
                                if enforce and is_private and not authorized_caller and name not in public_names and name not in all_protecteds and not is_base_protected:                                    
                                    self.raise_PrivateError(name, depth, class_name = class_name)
                                elif enforce and is_private and not authorized_caller and name not in public_names:
                                    if name in all_privates:
                                        for cls in all_hidden_values:
                                            if name in all_hidden_values[cls]:
                                                break                                        
                                        for cls2 in reversed(all_hidden_values.keys()):
                                            if hasattr(cls2, "private_bases") and cls2.private_bases != []:
                                                for private_base in cls2.private_bases:
                                                    if not isinstance(private_base, type):
                                                        private_base = private_base.own_all_hidden_values[type(private_base)]["cls"]
                                                    for cls3 in private_base.__mro__:
                                                        try:
                                                            cls3 = type.__getattribute__(cls3, "protected_gate")
                                                        except AttributeError:
                                                            pass
                                                        else:
                                                            cls3 = cls3.cls.own_all_hidden_values[type(cls3.cls)]["cls"]
                                                        if cls3 == cls:
                                                            self.raise_PrivateError(name, depth, class_name = cls2.__name__)                                   
                                    self.raise_ProtectedError(name, depth)
                                elif is_private and not authorized_caller and name == "_class_":                                    
                                    value = get_attr("_class_")
                                elif is_private and not authorized_caller and name in ["base_publics", "base_protecteds", "base_privates"]:
                                    value = list(getattr(type(self), name))
                                elif is_private and not authorized_caller and name == "_privates_":                                  
                                    value = all_privates
                                elif is_private and not authorized_caller and name == "_protecteds_":
                                    value = all_protecteds
                                elif is_private and not authorized_caller and name == "_publics_":
                                    value = all_publics                                    
                                elif is_private and not authorized_caller and name in ["__bases__", "__mro__", "_mro", "_bases"]:
                                    value = api_self.get_secure_bases(type(self), self.InsecureRestrictor.is_access_essentials, getattr(type(self), name))
                                elif name in common_names:
                                    for cls in all_hidden_values:
                                        if caller in all_hidden_values[cls]["auth_codes"]:
                                            if name in all_hidden_values[cls]:
                                                value = all_hidden_values[cls][name]
                                            else:
                                                value = object.__getattribute__(self, name)
                                            break
                                    else:
                                        value = object.__getattribute__(self, name)                                    
                                elif any(name in all_hidden_values[cls] for cls in all_hidden_values):
                                    for cls in all_hidden_values:
                                        if name in all_hidden_values[cls]:
                                            value = all_hidden_values[cls][name]
                                elif name == "hidden_values":
                                    for cls in all_hidden_values:
                                        if caller in all_hidden_values[cls]["auth_codes"]:                                                
                                            value = all_hidden_values[cls]
                                elif name == "all_hidden_values":
                                    value = all_hidden_values
                                else:
                                    try:                                        
                                        value = get_attr(name)
                                    except PrivateError as e:
                                        if not authorized_caller:
                                            e.caller_name = sys._getframe(depth).f_code.co_name
                                            raise
                                        else:
                                            value = force_get_attr(type(self).__bases__, name)                                            
                                return value

                            all_hidden_values = hidden_store.value.all_hidden_values                            
                            all_hidden_values[AccessEssentials]["auth_codes"].add(force_get_attr.__code__)
                            all_hidden_values[AccessEssentials]["auth_codes"].add(_getattribute_.__code__)                            

                            # inlining no_redirect for performance reasons
                            obj_will_redirect = "redirect_access" in all_hidden_values[type(self)] and all_hidden_values[type(self)]["redirect_access"] == True
                            try:
                                cls_will_redirect = type.__getattribute__(type(self), "redirect_access")
                            except AttributeError:
                                cls_will_redirect = False
                            if obj_will_redirect:
                                all_hidden_values[type(self)]["redirect_access"] = False                                          
                            if cls_will_redirect:
                                type(self).own_redirect_access = False
                            try:
                                return _getattribute_(self, name)
                            finally:
                                if obj_will_redirect:
                                    all_hidden_values[type(self)]["redirect_access"] = True                                          
                                if cls_will_redirect:
                                    type(self).own_redirect_access = True

                        self.authorize(_getattribute_)
                        _getattribute_ = types.MethodType(_getattribute_, self)
                        return _getattribute_

                    return create_getattribute(self, depth = depth, enforce = enforce)

                def create_setattr(self, depth = 2):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")
                    try:
                        get_private = object.__getattribute__(self, "get_private")
                        type.__delattr__(type(self), "get_private")
                    except AttributeError:
                        pass
                    else:
                        type.__setattr__(type(self), "get_private", get_private.__func__)
                        try:
                            all_hidden_values = get_private("all_hidden_values")
                        except AttributeError:
                            pass
                        else:
                            _caller = sys._getframe(1).f_code
                            for _cls in all_hidden_values:
                                if _caller in all_hidden_values[_cls]["auth_codes"]:
                                    break
                            else:
                                raise ProtectedError(f"\"{_caller.co_name}\" is not authorized to use this function")                            
                    
                    get_private = object.__getattribute__(self, "get_private")
                    no_redirect = types.MethodType(api_self.AccessEssentials.no_redirect, self)
                    @no_redirect(get_private("all_hidden_values"))                                        
                    def create_setattr(self, depth):                    
                        depth += 5
                        def _setattr_(self, name, value):
                            get_private = object.__getattribute__(self, "get_private")
                            all_hidden_values = get_private("all_hidden_values")
                            AccessEssentials = list(all_hidden_values.keys())[-1]
                            no_redirect = types.MethodType(api_self.AccessEssentials.no_redirect, self)
                            @no_redirect(get_private("all_hidden_values"))                    
                            def _setattr_(self, name, value):
                                common_names = ["_privates_",
                                                "_protecteds_",
                                                "_publics_",
                                                "AccessEssentials2",
                                                "AccessEssentials3",
                                                "InsecureRestrictor",
                                                "private",
                                                "protected",
                                                "public"]
                                all_privates = []
                                for cls in all_hidden_values:
                                    if "_privates_" in all_hidden_values[cls]:
                                        all_privates.extend(all_hidden_values[cls]["_privates_"])                                
                                all_protecteds = []
                                for cls in all_hidden_values:
                                    if "_protecteds_" in all_hidden_values[cls]:
                                        all_protecteds.extend(all_hidden_values[cls]["_protecteds_"])
                                all_publics = []
                                for cls in all_hidden_values:
                                    if "_publics_" in all_hidden_values[cls]:
                                        all_publics.extend(all_hidden_values[cls]["_publics_"])                                        
                                        
                                found = False
                                for cls in all_hidden_values:
                                    if name in all_hidden_values[cls]:
                                        found = True
                                        break
                                caller = sys._getframe(depth).f_code
                                for cls2 in all_hidden_values:
                                    if caller in all_hidden_values[cls2]["auth_codes"]:
                                        external_caller = False
                                        break
                                else:
                                    external_caller = True
                                    
                                is_private = found or name in ["hidden_values", "all_hidden_values"]
                                is_base_protected = False
                                class_name = None                                
                                if not is_private:
                                    broken = False
                                    for cls in all_hidden_values:
                                        if "_publics_" in all_hidden_values[cls] and name in all_hidden_values[cls]["_publics_"]:                                
                                            for cls2 in reversed(all_hidden_values.keys()):
                                                if hasattr(cls2, "private_bases") and cls2.private_bases != []:
                                                    for private_base in cls2.private_bases:
                                                        if not isinstance(private_base, type):
                                                            private_base = private_base.own_all_hidden_values[type(private_base)]["cls"]
                                                        for cls3 in private_base.__mro__:
                                                            try:
                                                                cls3 = type.__getattribute__(cls3, "protected_gate")
                                                            except AttributeError:
                                                                pass
                                                            else:
                                                                cls3 = cls3.cls.own_all_hidden_values[type(cls3.cls)]["cls"]
                                                            if cls3 == cls:
                                                                for cls4 in all_hidden_values:
                                                                    if caller in all_hidden_values[cls4]["auth_codes"]:
                                                                        break
                                                                else:
                                                                    cls4 = type(self)
                                                                if cls4 in cls2._subclasses_:                                                                
                                                                    is_private = True
                                                                    class_name = cls2.__name__
                                                                    broken = True
                                                                    break
                                                        if broken:
                                                            break
                                                    if broken:
                                                        break
                                                if hasattr(cls2, "protected_bases") and cls2.protected_bases != []:
                                                    for protected_base in cls2.protected_bases:
                                                        if not isinstance(protected_base, type):
                                                            protected_base = protected_base.own_all_hidden_values[type(protected_base)]["cls"]
                                                        for cls3 in protected_base.__mro__:
                                                            try:
                                                                cls3 = type.__getattribute__(cls3, "protected_gate")
                                                            except AttributeError:
                                                                pass
                                                            else:
                                                                cls3 = cls3.cls.own_all_hidden_values[type(cls3.cls)]["cls"]
                                                            if cls3 == cls:
                                                                for cls4 in all_hidden_values:
                                                                    if caller in all_hidden_values[cls4]["auth_codes"]:
                                                                        break
                                                                else:
                                                                    cls4 = type(self)
                                                                if cls4 in cls2._subclasses_:                                                                
                                                                    is_private = True
                                                                    is_base_protected = True
                                                                    broken = True
                                                                    break
                                                        if broken:
                                                            break
                                                    if broken:
                                                        break
                                            if broken:
                                                break                                    
                                check_caller = types.MethodType(all_hidden_values[AccessEssentials]["AccessEssentials2"].check_caller, self)
                                authorized_caller = check_caller(all_hidden_values, depth = depth, name = name)
                                if is_private and not authorized_caller and name not in all_protecteds and not is_base_protected:
                                    self.raise_PrivateError(name, depth, class_name = class_name)
                                elif is_private and not authorized_caller:
                                    if name in all_privates:
                                        for cls in all_hidden_values:
                                            if name in all_hidden_values[cls]:
                                                break                                        
                                        for cls2 in reversed(all_hidden_values.keys()):
                                            if hasattr(cls2, "private_bases") and cls2.private_bases != []:
                                                for private_base in cls2.private_bases:
                                                    if not isinstance(private_base, type):
                                                        private_base = private_base.own_all_hidden_values[type(private_base)]["cls"]
                                                    for cls3 in private_base.__mro__:
                                                        try:
                                                            cls3 = type.__getattribute__(cls3, "protected_gate")
                                                        except AttributeError:
                                                            pass
                                                        else:
                                                            cls3 = cls3.cls.own_all_hidden_values[type(cls3.cls)]["cls"]
                                                        if cls3 == cls:
                                                            self.raise_PrivateError(name, depth, class_name = cls2.__name__)                                    
                                    self.raise_ProtectedError(name, depth)
                                elif found and name not in common_names:
                                    all_hidden_values[cls][name] = value
                                elif found:
                                    all_hidden_values[cls2][name] = value
                                elif name == "hidden_values":
                                    if value is not all_hidden_values[cls2]:
                                        all_hidden_values[cls2].clear()
                                        all_hidden_values[cls2].update(value)
                                elif name == "all_hidden_values":
                                    if value is not all_hidden_values:
                                        all_hidden_values.clear()
                                        all_hidden_values.update(value)                                    
                                else:
                                    try:
                                        object.__getattribute__(self, name)
                                    except AttributeError:
                                        if not authorized_caller and external_caller and api_self.default.__code__ == api_self.private.__code__:
                                            self.raise_PrivateError(name, depth)
                                        elif not authorized_caller and external_caller and api_self.default.__code__ == api_self.protected.__code__:
                                            self.raise_ProtectedError(name, depth)
                                        elif api_self.default.__code__ == api_self.private.__code__:
                                            self.set_private(name, value, depth = depth)
                                        elif api_self.default.__code__ == api_self.protected.__code__:
                                            self.set_protected(name, value, depth = depth)
                                        else:
                                            if name in common_names:
                                                raise RuntimeError(f"{name} can't be public")
                                            object.__setattr__(self, name, value)
                                            for cls2 in all_hidden_values:
                                                if caller in all_hidden_values[cls2]["auth_codes"]:
                                                    all_hidden_values[cls2]["_publics_"].append(name)
                                                    break
                                            else:
                                                all_hidden_values[type(self)]["_publics_"].append(name)                                            
                                    else:
                                        if name in common_names:
                                            raise RuntimeError(f"{name} can't be public")                                        
                                        object.__setattr__(self, name, value)
                                        if name not in all_publics:
                                            for cls2 in all_hidden_values:
                                                if caller in all_hidden_values[cls2]["auth_codes"]:
                                                    all_hidden_values[cls2]["_publics_"].append(name)
                                                    break
                                            else:
                                                all_hidden_values[type(self)]["_publics_"].append(name)                                        

                            all_hidden_values[AccessEssentials]["auth_codes"].add(_setattr_.__code__)
                            _setattr_(self, name, value)
                        
                        self.authorize(_setattr_)
                        _setattr_ = types.MethodType(_setattr_, self)
                        return _setattr_
                    
                    return create_setattr(self, depth = depth)

                def create_delattr(self, depth = 2):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")
                    try:
                        get_private = object.__getattribute__(self, "get_private")
                        type.__delattr__(type(self), "get_private")
                    except AttributeError:
                        pass
                    else:
                        type.__setattr__(type(self), "get_private", get_private.__func__)
                        try:
                            all_hidden_values = get_private("all_hidden_values")
                        except AttributeError:
                            pass
                        else:
                            _caller = sys._getframe(1).f_code
                            for _cls in all_hidden_values:
                                if _caller in all_hidden_values[_cls]["auth_codes"]:
                                    break
                            else:
                                raise ProtectedError(f"\"{_caller.co_name}\" is not authorized to use this function")                            
                    
                    get_private = object.__getattribute__(self, "get_private")
                    no_redirect = types.MethodType(api_self.AccessEssentials.no_redirect, self)
                    @no_redirect(get_private("all_hidden_values"))                                       
                    def create_delattr(self, depth):                    
                        depth += 5
                        def _delattr_(self, name):
                            get_private = object.__getattribute__(self, "get_private")
                            all_hidden_values = get_private("all_hidden_values")
                            no_redirect = types.MethodType(api_self.AccessEssentials.no_redirect, self)
                            AccessEssentials = list(all_hidden_values.keys())[-1]
                            @no_redirect(get_private("all_hidden_values"))
                            def _delattr_(self, name):
                                def is_function(func):
                                    """We have to duplicate this function for performance reasons"""
                                    try:
                                        code = object.__getattribute__(func, "__code__")
                                    except AttributeError:
                                        has_code = type(func) == types.MethodType
                                    else:
                                        has_code = True
                                    if callable(func) and has_code and type(func.__code__) == types.CodeType:
                                        return True
                                    else:
                                        return False
                                
                                def get_member(self, hidden_values, name):
                                    """We have to duplicate this function because we can't trust AccessEssentials.get_member
                                    This function must be read only and immutable, not just protected.
                                    Otherwise derived classes could bypass private members of their bases.
                                    Functions aren't immutable in python so we completely hide it this way."""                                                           
                                    if name in hidden_values:
                                        return hidden_values[name]                                
                                    elif hasattr(AccessEssentials, name):
                                        func = getattr(AccessEssentials, name)
                                        if is_function(func) and type(func) != types.MethodType:                            
                                            return types.MethodType(func, self)
                                    return object.__getattribute__(self, name)                    
                                                                                            
                                common_names = ["_privates_",
                                                "_protecteds_",
                                                "_publics_",
                                                "AccessEssentials2",
                                                "AccessEssentials3",
                                                "InsecureRestrictor",
                                                "private",
                                                "protected",
                                                "public"]
                                all_privates = []
                                for cls in all_hidden_values:
                                    if "_privates_" in all_hidden_values[cls]:
                                        all_privates.extend(all_hidden_values[cls]["_privates_"])                                
                                all_protecteds = []
                                for cls in all_hidden_values:
                                    if "_protecteds_" in all_hidden_values[cls]:
                                        all_protecteds.extend(all_hidden_values[cls]["_protecteds_"])                                
                                found = False
                                for cls in all_hidden_values:
                                    if name in all_hidden_values[cls]:
                                        found = True
                                        break
                                caller = sys._getframe(depth).f_code
                                for cls2 in all_hidden_values:
                                    if caller in all_hidden_values[cls2]["auth_codes"]:
                                        break
                                
                                is_private = found or name in ["hidden_values", "all_hidden_values"]
                                is_base_protected = False
                                class_name = None                                
                                if not is_private:
                                    broken = False
                                    for cls in all_hidden_values:
                                        if "_publics_" in all_hidden_values[cls] and name in all_hidden_values[cls]["_publics_"]:                                
                                            for cls2 in reversed(all_hidden_values.keys()):
                                                if hasattr(cls2, "private_bases") and cls2.private_bases != []:
                                                    for private_base in cls2.private_bases:
                                                        if not isinstance(private_base, type):
                                                            private_base = private_base.own_all_hidden_values[type(private_base)]["cls"]
                                                        for cls3 in private_base.__mro__:
                                                            try:
                                                                cls3 = type.__getattribute__(cls3, "protected_gate")
                                                            except AttributeError:
                                                                pass
                                                            else:
                                                                cls3 = cls3.cls.own_all_hidden_values[type(cls3.cls)]["cls"]
                                                            if cls3 == cls:
                                                                for cls4 in all_hidden_values:
                                                                    if caller in all_hidden_values[cls4]["auth_codes"]:
                                                                        break
                                                                else:
                                                                    cls4 = type(self)
                                                                if cls4 in cls2._subclasses_:                                                                
                                                                    is_private = True
                                                                    class_name = cls2.__name__
                                                                    broken = True
                                                                    break
                                                        if broken:
                                                            break
                                                    if broken:
                                                        break
                                                if hasattr(cls2, "protected_bases") and cls2.protected_bases != []:
                                                    for protected_base in cls2.protected_bases:
                                                        if not isinstance(protected_base, type):
                                                            protected_base = protected_base.own_all_hidden_values[type(protected_base)]["cls"]
                                                        for cls3 in protected_base.__mro__:
                                                            try:
                                                                cls3 = type.__getattribute__(cls3, "protected_gate")
                                                            except AttributeError:
                                                                pass
                                                            else:
                                                                cls3 = cls3.cls.own_all_hidden_values[type(cls3.cls)]["cls"]
                                                            if cls3 == cls:
                                                                for cls4 in all_hidden_values:
                                                                    if caller in all_hidden_values[cls4]["auth_codes"]:
                                                                        break
                                                                else:
                                                                    cls4 = type(self)
                                                                if cls4 in cls2._subclasses_:                                                                
                                                                    is_private = True
                                                                    is_base_protected = True
                                                                    broken = True
                                                                    break
                                                        if broken:
                                                            break
                                                    if broken:
                                                        break
                                            if broken:
                                                break                                
                                AccessEssentials2 = get_member(self, all_hidden_values[AccessEssentials], "AccessEssentials2")
                                if not hasattr(AccessEssentials2, "check_caller"):
                                    AccessEssentials2 = api_self.AccessEssentials
                                check_caller = types.MethodType(AccessEssentials2.check_caller, self)
                                authorized_caller = check_caller(all_hidden_values, depth = depth, name = name)
                                if is_private and not authorized_caller and name not in all_protecteds and not is_base_protected:
                                    self.raise_PrivateError(name, depth, class_name = class_name)
                                elif is_private and not authorized_caller:
                                    if name in all_privates:
                                        for cls in all_hidden_values:
                                            if name in all_hidden_values[cls]:
                                                break                                        
                                        for cls2 in reversed(all_hidden_values.keys()):
                                            if hasattr(cls2, "private_bases") and cls2.private_bases != []:
                                                for private_base in cls2.private_bases:
                                                    if not isinstance(private_base, type):
                                                        private_base = private_base.own_all_hidden_values[type(private_base)]["cls"]
                                                    for cls3 in private_base.__mro__:
                                                        try:
                                                            cls3 = type.__getattribute__(cls3, "protected_gate")
                                                        except AttributeError:
                                                            pass
                                                        else:
                                                            cls3 = cls3.cls.own_all_hidden_values[type(cls3.cls)]["cls"]
                                                        if cls3 == cls:
                                                            self.raise_PrivateError(name, depth, class_name = cls2.__name__)                                    
                                    self.raise_ProtectedError(name, depth)
                                elif found and name not in common_names:
                                    object.__delattr__(self, name)
                                    del all_hidden_values[cls][name]
                                    all_hidden_values[cls]["_privates_"].remove(name)
                                    if name in all_hidden_values[cls]["_protecteds_"]:
                                        all_hidden_values[cls]["_protecteds_"].remove(name)
                                elif found:                                    
                                    del all_hidden_values[cls2][name]
                                    all_hidden_values[cls2]["_privates_"].remove(name)
                                    if name in all_hidden_values[cls2]["_protecteds_"]:
                                        all_hidden_values[cls2]["_protecteds_"].remove(name)                                    
                                    for cls in all_hidden_values:
                                        if name in all_hidden_values[cls]:
                                            break
                                    else:
                                        object.__delattr__(self, name)
                                elif name == "hidden_values":
                                    all_hidden_values[cls2].clear()
                                elif name == "all_hidden_values":
                                    all_hidden_values.clear()
                                else:
                                    object.__delattr__(self, name)
                                    for cls in all_hidden_values:
                                        if "_publics_" in all_hidden_values[cls] and name in all_hidden_values[cls]["_publics_"]:
                                            all_hidden_values[cls]["_publics_"].remove(name)

                            all_hidden_values[AccessEssentials]["auth_codes"].add(_delattr_.__code__)                             
                            _delattr_(self, name)

                        self.authorize(_delattr_)
                        _delattr_ = types.MethodType(_delattr_, self)
                        return _delattr_
                    
                    return create_delattr(self, depth = depth)                
                
                def mask_public_face(self, all_hidden_values):
                    """Make interaction with private members more intuitive"""
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")
                    try:
                        get_private = object.__getattribute__(self, "get_private")
                        type.__delattr__(type(self), "get_private")
                    except AttributeError:
                        pass
                    else:
                        type.__setattr__(type(self), "get_private", get_private.__func__)
                        try:
                            all_hidden_values = get_private("all_hidden_values")
                        except AttributeError:
                            pass
                        else:
                            _caller = sys._getframe(1).f_code
                            for _cls in all_hidden_values:
                                if _caller in all_hidden_values[_cls]["auth_codes"]:
                                    break
                            else:
                                raise ProtectedError(f"\"{_caller.co_name}\" is not authorized to use this function")                            
                    
                    hidden_store = self.get_private("hidden_store")
                    AccessEssentials = list(all_hidden_values.keys())[-1]

                    def is_function(func):
                        """We have to duplicate this function for performance reasons"""
                        try:
                            code = object.__getattribute__(func, "__code__")
                        except AttributeError:
                            has_code = type(func) == types.MethodType
                        else:
                            has_code = True
                        if callable(func) and has_code and type(func.__code__) == types.CodeType:
                            return True
                        else:
                            return False

                    def get_member(self, hidden_values, name):
                        """We have to duplicate this function because we can't trust AccessEssentials.get_member
                        This function must be read only and immutable, not just protected.
                        Otherwise derived classes could bypass private members of their bases.
                        Functions aren't immutable in python so we completely hide it this way."""                        
                        if name in hidden_values:
                            return hidden_values[name]
                        elif hasattr(AccessEssentials, name):
                            func = getattr(AccessEssentials, name)
                            if api_self.is_function(func) and type(func) != types.MethodType:                            
                                return types.MethodType(func, self)
                        try:
                            value = object.__getattribute__(self, name)
                        except AttributeError:                            
                            found = False
                            for base2 in type(self).__mro__:                        
                                try:
                                    raw_base = type.__getattribute__(base2, "protected_gate")
                                except AttributeError:
                                    raw_base = base2                            
                                else:
                                    raw_base = raw_base.cls.own_all_hidden_values[type(raw_base.cls)]["cls"]
                                try:                            
                                    value = type.__getattribute__(raw_base, name)                            
                                    type.__delattr__(raw_base, name)
                                    found = True
                                except AttributeError:                                                   
                                    continue
                                except TypeError:
                                    pass
                                else:
                                    type.__setattr__(raw_base, name, value)                           
                                    is_builtin_new = name == "_new_" and value == object.__new__
                                    is_builtin_new2 = name == "__new__" and value == object.__new__
                                    is_builtin = type(value) == types.WrapperDescriptorType
                                    if is_builtin_new or is_builtin_new2 or is_builtin:
                                        continue
                                    break
                            if is_function(value):
                                value = types.MethodType(value, self)
                        return value

                    self.authorize(get_member)
                    
                    def check_caller(self, depth = 2, name = "hidden_values"):
                        depth += 1
                        return get_member(self, all_hidden_values[AccessEssentials], "AccessEssentials2").check_caller(self, all_hidden_values, depth = depth, name = name)

                    def get_caller_class(depth = 2):
                        depth += 1
                        caller = sys._getframe(depth).f_code
                        broken = False
                        for cls in all_hidden_values:
                            for member_name in cls.__dict__:
                                member = cls.__dict__[member_name]
                                if api_self.is_function(member) and member.__code__ == caller:
                                    broken = True
                                    break
                            if broken:
                                break
                        return cls

                    hidden_store.value.check_caller = check_caller
                    hidden_store.value.get_member = get_member

                    default_getter = self.create_getattribute(depth = 0)
                    hidden_store.value.default_getter = default_getter
                    def getter(self, name):
                        maybe_redirect = hidden_store.value.all_hidden_values is not None and \
                                         "redirect_access" in hidden_store.value.all_hidden_values[type(self)] and \
                                         hidden_store.value.all_hidden_values[type(self)]["redirect_access"] == True
                        should_redirect = maybe_redirect and name not in ["__class__", "own_hidden_values", "own_all_hidden_values"]
                        if should_redirect:
                            hidden_store.value.all_hidden_values[type(self)]["redirect_access"] = False
                            _getattribute_ = hidden_store.value.get_member(self, hidden_store.value.all_hidden_values[type(self)], "_getattribute_")
                            if type(_getattribute_) == PrivateError:
                                _getattribute_ = hidden_store.value.get_member(self, hidden_store.value.all_hidden_values[AccessEssentials], "_getattribute_")
                            if _getattribute_.__code__ != hidden_store.value.default_getter.__code__:                                
                                try:
                                    _self_ = object.__getattribute__(self, "_self_")
                                except AttributeError:
                                    pass
                                else:
                                    _getattribute_ = _getattribute_.__func__
                                    _getattribute_ = types.MethodType(_getattribute_, _self_)
                            del self
                            try:
                                value = _getattribute_(name)                                
                            finally:
                                hidden_store.value.all_hidden_values[type(hidden_store.value.self)]["redirect_access"] = True

                            try:
                                class_id = type.__getattribute__(type(hidden_store.value.self), "class_id")
                            except AttributeError:
                                has_class_id = False
                            else:
                                has_class_id = True                                
                            is_secure_instance = has_class_id and class_id == "access_modifiers.SecureInstance"
                            try:
                                is_secure_method = object.__getattribute__(value, "is_secure_method")
                            except AttributeError:
                                is_secure_method = False
                            if is_secure_method and value.is_secure_method == True and not is_secure_instance:
                                for cls in hidden_store.value.all_hidden_values:
                                    if value.__code__ in hidden_store.value.all_hidden_values[cls]["auth_codes"]:
                                        hidden_store.value.all_hidden_values[cls]["auth_codes"].remove(value.__code__)
                                caller = sys._getframe(2).f_code
                                for cls in hidden_store.value.all_hidden_values:
                                    if caller in hidden_store.value.all_hidden_values[cls]["auth_codes"]:
                                        hidden_store.value.all_hidden_values[cls]["auth_codes"].add(value.__code__)
                                        break
                            return value
                        elif name == "own_hidden_values":                            
                            if not hidden_store.value.check_caller(self):                                
                                raise PrivateError(sys._getframe(2).f_code.co_name, name, type(self).__name__)
                            caller = sys._getframe(2).f_code
                            for cls in hidden_store.value.all_hidden_values:
                                if caller in hidden_store.value.all_hidden_values[cls]["auth_codes"]:
                                    break
                            else:
                                raise PrivateError(sys._getframe(2).f_code.co_name, "own_hidden_values", type(self).__name__)
                            return hidden_store.value.all_hidden_values[cls]
                        elif name == "own_all_hidden_values":
                            if not hidden_store.value.check_caller(self, name = "all_hidden_values"):
                                raise PrivateError(sys._getframe(2).f_code.co_name, name, "AccessEssentials")
                            return hidden_store.value.all_hidden_values
                        else:
                            return hidden_store.value.default_getter(name)

                    self.authorize(getter)
                    hidden_store.value.getter = getter
                    def __getattribute__(self, name):
                        """this function is for debug purposes"""
                        start = time.time()
                        try:
                            hidden_store.value.self = self
                            del self                           
                            value = hidden_store.value.getter(hidden_store.value.self, name)                           
                        finally:
                            stop = time.time()
                            runtime = stop - start
                            frame = sys._getframe(1)
                            try:
                                second_lineno = frame.f_back.f_back.f_back.f_lineno
                                #second_lineno = frame.f_back.f_back.f_back.f_back.f_lineno # get_unbound_base_attr
                                #second_lineno = frame.f_back.f_back.f_back.f_lineno
                            except AttributeError:
                                second_lineno = -1                                                            
                            if frame in calls:
                                calls[frame][0] += 1
                                calls[frame][1].append(frame.f_lineno)
                                calls[frame][2] += runtime
                                calls[frame][4].append(second_lineno)
                            else:
                                calls[frame] = [1, [frame.f_lineno], runtime, frame.f_back.f_back.f_lineno, [second_lineno]]                        
                        return value

                    def __getattribute__(self, name):
                        hidden_store.value.self = self
                        del self
                        value = hidden_store.value.getter(hidden_store.value.self, name)
                        return value
                        
                    self.authorize(__getattribute__)
                    type(self).__getattribute__ = __getattribute__

                    default_setter = self.create_setattr(depth = 0)
                    hidden_store.value.default_setter = default_setter
                    def setter(self, name, value):
                        maybe_redirect = hidden_store.value.all_hidden_values is not None and \
                                         "redirect_access" in hidden_store.value.all_hidden_values[type(self)] and \
                                         hidden_store.value.all_hidden_values[type(self)]["redirect_access"] == True
                        should_redirect = maybe_redirect and name not in ["__class__", "own_hidden_values", "own_all_hidden_values"]
                        if should_redirect:
                            _setattr_ = hidden_store.value.get_member(self, hidden_store.value.all_hidden_values[type(self)], "_setattr_")
                            if type(_setattr_) == PrivateError:
                                _setattr_ = hidden_store.value.get_member(self, hidden_store.value.all_hidden_values[AccessEssentials], "_setattr_")
                            if _setattr_.__code__ != hidden_store.value.default_setter.__code__:
                                try:
                                    _self_ = object.__getattribute__(self, "_self_")
                                except AttributeError:
                                    pass
                                else:
                                    if type(_setattr_) == types.MethodType:
                                        _setattr_ = _setattr_.__func__                        
                                        _setattr_ = types.MethodType(_setattr_, _self_)
                            del self
                            _setattr_(name, value)
                        elif name == "own_hidden_values":
                            if not hidden_store.value.check_caller(self):
                                raise PrivateError(sys._getframe(2).f_code.co_name, name, type(self).__name__)
                            caller = sys._getframe(2).f_code
                            for cls in hidden_store.value.all_hidden_values:
                                if caller in hidden_store.value.all_hidden_values[cls]["auth_codes"]:
                                    break
                            else:
                                raise PrivateError(sys._getframe(2).f_code.co_name, "own_hidden_values", type(self).__name__)
                            if value is not hidden_store.value.all_hidden_values[cls]:
                                hidden_store.value.all_hidden_values[cls].clear()
                                hidden_store.value.all_hidden_values[cls].update(value)
                        elif name == "own_all_hidden_values":
                            if not hidden_store.value.check_caller(self, name = "all_hidden_values"):
                                raise PrivateError(sys._getframe(2).f_code.co_name, name, "AccessEssentials")
                            if value is not hidden_store.value.all_hidden_values:
                                hidden_store.value.all_hidden_values.clear()
                                hidden_store.value.all_hidden_values.update(value)                                                        
                        else:
                            hidden_store.value.default_setter(name, value)
                            
                    self.authorize(setter)
                    hidden_store.value.setter = setter                    
                    def __setattr__(self, name, value):
                        hidden_store.value.self = self
                        del self                        
                        hidden_store.value.setter(hidden_store.value.self, name, value)
                    
                    self.authorize(__setattr__)  
                    type(self).__setattr__ = __setattr__

                    default_deleter = self.create_delattr(depth = 0)
                    hidden_store.value.default_deleter = default_deleter
                    def deleter(self, name):
                        maybe_redirect = hidden_store.value.all_hidden_values is not None and \
                                         "redirect_access" in hidden_store.value.all_hidden_values[type(self)] and \
                                         hidden_store.value.all_hidden_values[type(self)]["redirect_access"] == True
                        should_redirect = maybe_redirect and name not in ["__class__", "own_hidden_values", "own_all_hidden_values"]
                        if should_redirect:
                            _delattr_ = hidden_store.value.get_member(self, hidden_store.value.all_hidden_values[type(self)], "_delattr_")
                            if type(_delattr_) == PrivateError:
                                _delattr_ = hidden_store.value.get_member(self, hidden_store.value.all_hidden_values[AccessEssentials], "_delattr_")
                            if _delattr_.__code__ != hidden_store.value.default_deleter.__code__:
                                try:
                                    _self_ = object.__getattribute__(self, "_self_")
                                except AttributeError:
                                    pass
                                else:
                                    if type(_delattr_) == types.MethodType:
                                        _delattr_ = _delattr_.__func__
                                        _delattr_ = types.MethodType(_delattr_, _self_)                                        
                            del self
                            _delattr_(name)                            
                        elif name == "own_hidden_values":
                            if not hidden_store.value.check_caller(self):
                                raise PrivateError(sys._getframe(2).f_code.co_name, name, type(self).__name__)
                            caller = sys._getframe(2).f_code
                            for cls in hidden_store.value.all_hidden_values:
                                if caller in hidden_store.value.all_hidden_values[cls]["auth_codes"]:
                                    break
                            else:
                                raise PrivateError(sys._getframe(2).f_code.co_name, "own_hidden_values", type(self).__name__)                                                                                                                  
                            hidden_store.value.all_hidden_values[cls].clear()
                        elif name == "own_all_hidden_values":
                            if not hidden_store.value.check_caller(self, name = "all_hidden_values"):
                                raise PrivateError(sys._getframe(2).f_code.co_name, name, "AccessEssentials")
                            hidden_store.value.all_hidden_values.clear()
                        else:
                            hidden_store.value.default_deleter(name)

                    self.authorize(deleter)       
                    hidden_store.value.deleter = deleter                    
                    def __delattr__(self, name):
                        hidden_store.value.self = self
                        del self                                                
                        hidden_store.value.deleter(hidden_store.value.self, name)
                        
                    self.authorize(__delattr__)
                    type(self).__delattr__ = __delattr__
                            
                def set_private(self, name, value, cls = None, depth = 0):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")
                    try:
                        get_private = object.__getattribute__(self, "get_private")
                        type.__delattr__(type(self), "get_private")
                    except AttributeError:
                        pass
                    else:
                        type.__setattr__(type(self), "get_private", get_private.__func__)
                        try:
                            all_hidden_values = get_private("all_hidden_values")
                        except AttributeError:
                            pass
                        else:
                            _caller = sys._getframe(1).f_code
                            for _cls in all_hidden_values:
                                if _caller in all_hidden_values[_cls]["auth_codes"]:
                                    break
                            else:
                                raise ProtectedError(f"\"{_caller.co_name}\" is not authorized to use this function")                            
                        
                    get_private = object.__getattribute__(self, "get_private")
                    all_hidden_values = get_private("all_hidden_values")
                    AccessEssentials = list(all_hidden_values.keys())[-1]
                    def set_private(self, name, value, cls = None, depth = 0):
                        def is_function(func):
                            """We have to duplicate this function for performance reasons"""
                            try:
                                code = object.__getattribute__(func, "__code__")
                            except AttributeError:
                                has_code = type(func) == types.MethodType
                            else:
                                has_code = True
                            if callable(func) and has_code and type(func.__code__) == types.CodeType:
                                return True
                            else:
                                return False
                        
                        def get_member(self, hidden_values, name):
                            """We have to duplicate this function because we can't trust AccessEssentials.get_member
                            This function must be read only and immutable, not just protected.
                            Otherwise derived classes could bypass private members of their bases.
                            Functions aren't immutable in python so we completely hide it this way."""                        
                            if name in hidden_values:
                                return hidden_values[name]
                            elif hasattr(AccessEssentials, name):
                                func = getattr(AccessEssentials, name)
                                if is_function(func) and type(func) != types.MethodType:                            
                                    return types.MethodType(func, self)
                            return object.__getattribute__(self, name)                    

                        depth += 2
                        if cls is not None and not isinstance(cls, type):
                            for cls2 in all_hidden_values:
                                if cls.__name__ == cls2.__name__:
                                    cls = cls2                        
                        if depth != 2:
                            caller = sys._getframe(2).f_code
                            if caller not in all_hidden_values[AccessEssentials]["auth_codes"]:
                                raise PrivateError("only functions authorized by AccessEssentials can set depth parameter")
                            
                        common_names = ["_privates_",
                                        "_protecteds_",
                                        "_publics_",
                                        "AccessEssentials2",
                                        "AccessEssentials3",
                                        "InsecureRestrictor",
                                        "private",
                                        "protected",
                                        "public"]                        
                        caller = sys._getframe(depth).f_code
                        for cls2 in all_hidden_values:
                            if caller in all_hidden_values[cls2]["auth_codes"]:
                                break
                        else:
                            raise PrivateError(f"\"{caller.co_name}\" is not authorized to use this function")
                        if cls is not None and cls != cls2 and cls not in cls2._subclasses_:
                            raise PrivateError(sys._getframe(2).f_code.co_name, name, cls.__name__)
                        elif cls is None:
                            cls = cls2
                        if name not in ["hidden_values", "all_hidden_values"] and name not in common_names:
                            for cls3 in all_hidden_values:
                                if name in all_hidden_values[cls3]:
                                    if name not in all_hidden_values[cls3]["_protecteds_"] and cls3 != cls2 and cls3 not in cls2._subclasses_:
                                        raise PrivateError(sys._getframe(2).f_code.co_name, name, cls3.__name__)
                                    del all_hidden_values[cls3][name]
                                    all_hidden_values[cls3]["_privates_"].remove(name)
                                    if name in all_hidden_values[cls3]["_protecteds_"]:
                                        all_hidden_values[cls3]["_protecteds_"].remove(name)                                        
                                    break
                            if name in self.__dict__:
                                create_delattr = types.MethodType(get_member(self, all_hidden_values[AccessEssentials], "AccessEssentials2").create_delattr, self)
                                _delattr_ = create_delattr(depth = 0)
                                _delattr_(name)
                            all_hidden_values[cls][name] = value
                        elif name not in ["hidden_values", "all_hidden_values"]:
                            all_hidden_values[cls][name] = value
                        elif name == "hidden_values":
                            if value is not all_hidden_values[cls]:
                                all_hidden_values[cls].clear()
                                all_hidden_values[cls].update(value)
                        elif cls2 != AccessEssentials:
                            raise PrivateError(sys._getframe(2).f_code.co_name, name, "AccessEssentials")
                        else:
                            if value is not all_hidden_values:
                                all_hidden_values.clear()
                                all_hidden_values.update(value)
                        _privates_ = get_member(self, all_hidden_values[cls], "_privates_")
                        _protecteds_ = get_member(self, all_hidden_values[cls], "_protecteds_")
                        _publics_ = get_member(self, all_hidden_values[cls], "_publics_")
                        if name not in ["hidden_values", "all_hidden_values"] and name not in _privates_:
                            _privates_.append(name)
                        if "_protecteds_" in all_hidden_values[cls] and name in _protecteds_:
                            _protecteds_.remove(name)
                        if "_publics_" in all_hidden_values[cls] and name in _publics_:
                            _publics_.remove(name)                            
                        if is_function(value):
                            all_hidden_values[cls]["auth_codes"].add(value.__code__)
                        try:
                            object.__setattr__(self, name, PrivateError("private member"))
                        except AttributeError:
                            pass

                    all_hidden_values[AccessEssentials]["auth_codes"].add(set_private.__code__)
                    # inlining no_redirect for performance reasons
                    obj_will_redirect = "redirect_access" in all_hidden_values[type(self)] and all_hidden_values[type(self)]["redirect_access"] == True
                    try:
                        cls_will_redirect = type.__getattribute__(type(self), "redirect_access")
                    except AttributeError:
                        cls_will_redirect = False
                    if obj_will_redirect:
                        all_hidden_values[type(self)]["redirect_access"] = False                                          
                    if cls_will_redirect:
                        type(self).own_redirect_access = False
                    try:
                        return set_private(self, name, value, cls, depth)
                    finally:
                        if obj_will_redirect:
                            all_hidden_values[type(self)]["redirect_access"] = True                                          
                        if cls_will_redirect:
                            type(self).own_redirect_access = True         

                def set_protected(self, name, value, cls = None, depth = 0):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")
                    try:
                        get_private = object.__getattribute__(self, "get_private")
                        type.__delattr__(type(self), "get_private")
                    except AttributeError:
                        pass
                    else:
                        type.__setattr__(type(self), "get_private", get_private.__func__)
                        try:
                            all_hidden_values = get_private("all_hidden_values")
                        except AttributeError:
                            pass
                        else:
                            _caller = sys._getframe(1).f_code
                            for _cls in all_hidden_values:
                                if _caller in all_hidden_values[_cls]["auth_codes"]:
                                    break
                            else:
                                raise ProtectedError(f"\"{_caller.co_name}\" is not authorized to use this function")                            
                    
                    get_private = object.__getattribute__(self, "get_private")
                    all_hidden_values = get_private("all_hidden_values")
                    AccessEssentials = list(all_hidden_values.keys())[-1]
                    no_redirect = types.MethodType(api_self.AccessEssentials.no_redirect, self)
                    @no_redirect(get_private("all_hidden_values"))                    
                    def set_protected(self, name, value, cls = None, depth = 0):
                        def is_function(func):
                            """We have to duplicate this function for performance reasons"""
                            try:
                                code = object.__getattribute__(func, "__code__")
                            except AttributeError:
                                has_code = type(func) == types.MethodType
                            else:
                                has_code = True
                            if callable(func) and has_code and type(func.__code__) == types.CodeType:
                                return True
                            else:
                                return False
                        
                        def get_member(self, hidden_values, name):
                            """We have to duplicate this function because we can't trust AccessEssentials.get_member
                            This function must be read only and immutable, not just protected.
                            Otherwise derived classes could bypass private members of their bases.
                            Functions aren't immutable in python so we completely hide it this way."""                        
                            if name in hidden_values:
                                return hidden_values[name]
                            elif hasattr(AccessEssentials, name):
                                func = getattr(AccessEssentials, name)
                                if is_function(func) and type(func) != types.MethodType:                            
                                    return types.MethodType(func, self)
                            return object.__getattribute__(self, name)                    

                        depth += 3
                        if cls is not None and not isinstance(cls, type):
                            for cls2 in all_hidden_values:
                                if cls.__name__ == cls2.__name__:
                                    cls = cls2                        
                        if depth != 2:
                            caller = sys._getframe(2).f_code
                            if caller not in all_hidden_values[AccessEssentials]["auth_codes"]:
                                raise PrivateError("only functions authorized by AccessEssentials can set depth parameter")
                            
                        common_names = ["_privates_",
                                        "_protecteds_",
                                        "_publics_",
                                        "AccessEssentials2",
                                        "AccessEssentials3",
                                        "InsecureRestrictor",
                                        "private",
                                        "protected",
                                        "public"]                        
                        caller = sys._getframe(depth).f_code
                        for cls2 in all_hidden_values:
                            if caller in all_hidden_values[cls2]["auth_codes"]:
                                break
                        else:
                            raise PrivateError(f"\"{caller.co_name}\" is not authorized to use this function")                            
                        if cls is None:
                            cls = cls2
                        if name not in ["hidden_values", "all_hidden_values"] and name not in common_names:
                            for cls3 in all_hidden_values:
                                if name in all_hidden_values[cls3]:
                                    if name not in all_hidden_values[cls3]["_protecteds_"] and cls3 != cls2 and cls3 not in cls2._subclasses_:
                                        raise PrivateError(sys._getframe(2).f_code.co_name, name, cls3.__name__)                                    
                                    del all_hidden_values[cls3][name]
                                    all_hidden_values[cls3]["_privates_"].remove(name)
                                    if name in all_hidden_values[cls3]["_protecteds_"]:
                                        all_hidden_values[cls3]["_protecteds_"].remove(name)                                    
                                    break
                            if name in self.__dict__:
                                create_delattr = types.MethodType(get_member(self, all_hidden_values[AccessEssentials], "AccessEssentials2").create_delattr, self)
                                _delattr_ = create_delattr(depth = 1)
                                _delattr_(name)                                                                
                            all_hidden_values[cls][name] = value
                        elif name not in ["hidden_values", "all_hidden_values"]:
                            all_hidden_values[cls][name] = value
                        else:
                            raise RuntimeError(f"access modifier of {name} can't be changed")
                        
                        _privates_ = get_member(self, all_hidden_values[cls], "_privates_")
                        _protecteds_ = get_member(self, all_hidden_values[cls], "_protecteds_")
                        _publics_ = get_member(self, all_hidden_values[cls], "_publics_")
                        if name not in _privates_:
                            _privates_.append(name)
                        if name not in _protecteds_:
                            _protecteds_.append(name)
                        if name in _publics_:
                            _publics_.remove(name)                            
                        if is_function(value):
                            all_hidden_values[cls]["auth_codes"].add(value.__code__)
                        try:
                            object.__setattr__(self, name, ProtectedError("protected member"))
                        except AttributeError:
                            pass
                    set_protected(self, name, value, cls, depth)

                def set_public(self, name, value, depth = 0):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")
                    try:
                        get_private = object.__getattribute__(self, "get_private")
                        type.__delattr__(type(self), "get_private")
                    except AttributeError:
                        pass
                    else:
                        type.__setattr__(type(self), "get_private", get_private.__func__)
                        try:
                            all_hidden_values = get_private("all_hidden_values")
                        except AttributeError:
                            pass
                        else:
                            _caller = sys._getframe(1).f_code
                            for _cls in all_hidden_values:
                                if _caller in all_hidden_values[_cls]["auth_codes"]:
                                    break
                            else:
                                raise ProtectedError(f"\"{_caller.co_name}\" is not authorized to use this function")                            
                    
                    get_private = object.__getattribute__(self, "get_private")
                    all_hidden_values = get_private("all_hidden_values")
                    AccessEssentials = list(all_hidden_values.keys())[-1]
                    no_redirect = types.MethodType(api_self.AccessEssentials.no_redirect, self)
                    @no_redirect(get_private("all_hidden_values"))                    
                    def set_public(self, name, value, depth = 0):
                        def is_function(func):
                            """We have to duplicate this function for performance reasons"""
                            try:
                                code = object.__getattribute__(func, "__code__")
                            except AttributeError:
                                has_code = type(func) == types.MethodType
                            else:
                                has_code = True
                            if callable(func) and has_code and type(func.__code__) == types.CodeType:
                                return True
                            else:
                                return False
                        
                        def get_member(self, hidden_values, name):
                            """We have to duplicate this function because we can't trust AccessEssentials.get_member
                            This function must be read only and immutable, not just protected.
                            Otherwise derived classes could bypass private members of their bases.
                            Functions aren't immutable in python so we completely hide it this way."""                        
                            if name in hidden_values:
                                return hidden_values[name]
                            elif hasattr(AccessEssentials, name):
                                func = getattr(AccessEssentials, name)
                                if is_function(func) and type(func) != types.MethodType:                            
                                    return types.MethodType(func, self)
                            return object.__getattribute__(self, name)                    
                        
                        depth += 3
                        if depth != 2:
                            caller = sys._getframe(2).f_code
                            if caller not in all_hidden_values[AccessEssentials]["auth_codes"]:
                                raise PrivateError("only functions authorized by AccessEssentials can set depth parameter")
                        
                        common_names = ["_privates_",
                                        "_protecteds_",
                                        "_publics_",
                                        "AccessEssentials2",
                                        "AccessEssentials3",
                                        "InsecureRestrictor",
                                        "private",
                                        "protected",
                                        "public"]                        
                        caller = sys._getframe(depth).f_code
                        for cls2 in all_hidden_values:
                            if caller in all_hidden_values[cls2]["auth_codes"]:
                                break
                        else:
                            raise PrivateError(f"\"{caller.co_name}\" is not authorized to use this function")                            
                        cls = cls2
                        if name not in ["hidden_values", "all_hidden_values"] and name not in common_names:
                            for cls3 in all_hidden_values:
                                if name in all_hidden_values[cls3]:
                                    if name not in all_hidden_values[cls3]["_protecteds_"] and cls3 != cls2 and cls3 not in cls2._subclasses_:
                                        raise PrivateError(sys._getframe(2).f_code.co_name, name, cls3.__name__)                                    
                                    del all_hidden_values[cls3][name]
                                    all_hidden_values[cls3]["_privates_"].remove(name)
                                    if name in all_hidden_values[cls3]["_protecteds_"]:
                                        all_hidden_values[cls3]["_protecteds_"].remove(name)                                    
                                    break
                            if name in self.__dict__:
                                create_delattr = types.MethodType(get_member(self, all_hidden_values[AccessEssentials], "AccessEssentials2").create_delattr, self)
                                _delattr_ = create_delattr(depth = 1)
                                _delattr_(name)                                                               
                        else:
                            raise RuntimeError(f"access modifier of {name} can't be changed")
                        _privates_ = get_member(self, all_hidden_values[cls], "_privates_")
                        _protecteds_ = get_member(self, all_hidden_values[cls], "_protecteds_")
                        _publics_ = get_member(self, all_hidden_values[cls], "_publics_")                        
                        if name in _privates_:
                            _privates_.remove(name)
                        if name in _protecteds_:
                            _protecteds_.remove(name)
                        if name not in _publics_:
                            _publics_.append(name)                        
                        if api_self.is_function(value):
                            all_hidden_values[cls]["auth_codes"].add(value.__code__)                    
                        object.__setattr__(self, name, value)

                    set_public(self, name, value, depth)
                    
                def start_access_check(self):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")
                    try:
                        get_private = object.__getattribute__(self, "get_private")
                        type.__delattr__(type(self), "get_private")
                    except AttributeError:
                        pass
                    else:
                        type.__setattr__(type(self), "get_private", get_private.__func__)
                        try:
                            all_hidden_values = get_private("all_hidden_values")
                        except AttributeError:
                            pass
                        else:
                            _caller = sys._getframe(1).f_code
                            for _cls in all_hidden_values:
                                if _caller in all_hidden_values[_cls]["auth_codes"]:
                                    break
                            else:
                                raise ProtectedError(f"\"{_caller.co_name}\" is not authorized to use this function")                            
                    
                    auth_codes = api_self.IdentitySet([api_self.get_all_subclasses2.__code__])
                    for member_name in type(self).__dict__:
                        try:
                            member = type.__getattribute__(type(self), member_name)
                        except AttributeError:
                            continue             
                        if api_self.is_function(member):
                            auth_codes.add(member.__code__)
                    if hasattr(type(self), "secure_class"):
                        for caller in type(self).secure_class.own_all_hidden_values[type(type(self).secure_class)]["auth_codes"]:
                            auth_codes.add(caller)                            
                    all_hidden_values = {type(self) : {"auth_codes" : auth_codes}}                    
                    for base in type(self).__mro__:
                        if base is object:
                            break
                        try:
                            base = type.__getattribute__(base, "protected_gate")
                        except AttributeError:
                            pass
                        else:
                            base = base.cls.own_all_hidden_values[type(base.cls)]["cls"]
                        auth_codes = api_self.IdentitySet([api_self.get_all_subclasses2.__code__])
                        all_names = base.__dict__
                        for member_name in all_names:                        
                            try:
                                member = type.__getattribute__(base, member_name)
                            except AttributeError:
                                continue             
                            if api_self.is_function(member):
                                auth_codes.add(member.__code__)
                        if hasattr(base, "secure_class"):
                            for caller in base.secure_class.own_all_hidden_values[type(base.secure_class)]["auth_codes"]:
                                auth_codes.add(caller)
                        all_hidden_values[base] = {"auth_codes" : auth_codes}                        
                            
                    AccessEssentials = list(all_hidden_values.keys())[-1]
                        
                    def get_private(self, name):
                        if name == "all_hidden_values":
                            return all_hidden_values
                        else:
                            return all_hidden_values[AccessEssentials][name]
 
                    type(self).get_private = get_private                    
                    class HiddenStore:
                        pass                    
                    hidden_store = HiddenStore()                    
                    hidden_store = self.internal_get_hidden_value(all_hidden_values, hidden_store)                        
                    all_hidden_values[AccessEssentials]["hidden_store"] = hidden_store                    
                    hidden_store.value.all_hidden_values = all_hidden_values
                    type(self).get_private = self.create_get_private(all_hidden_values, enforce = True)                   
                    self.mask_public_face(all_hidden_values)

                def ready_to_redirect(self):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")
                    try:
                        get_private = object.__getattribute__(self, "get_private")
                        type.__delattr__(type(self), "get_private")
                    except AttributeError:
                        pass
                    else:
                        type.__setattr__(type(self), "get_private", get_private.__func__)
                        try:
                            all_hidden_values = get_private("all_hidden_values")
                        except AttributeError:
                            pass
                        else:
                            _caller = sys._getframe(1).f_code
                            for _cls in all_hidden_values:
                                if _caller in all_hidden_values[_cls]["auth_codes"]:
                                    break
                            else:
                                raise ProtectedError(f"\"{_caller.co_name}\" is not authorized to use this function")                            
                    
                    if not hasattr(self, "_getattribute_"):
                        self.set_private("_getattribute_", self.create_getattribute(depth = 0, enforce = True))
                    if not hasattr(self, "_setattr_"):
                        self.set_private("_setattr_", self.create_setattr(depth = 0))
                    if not hasattr(self, "_delattr_"):
                        self.set_private("_delattr_", self.create_delattr(depth = 0))
                  
                def init_privates(self):                   
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")
                    try:
                        get_private = object.__getattribute__(self, "get_private")
                    except AttributeError:
                        pass
                    else:
                        try:
                            all_hidden_values = get_private("all_hidden_values")
                        except AttributeError:
                            pass
                        else:
                            _caller = sys._getframe(1).f_code
                            for _cls in all_hidden_values:
                                if _caller in all_hidden_values[_cls]["auth_codes"]:
                                    break
                            else:
                                raise ProtectedError(f"\"{_caller.co_name}\" is not authorized to use this function")                                                

                    all_hidden_values = self.all_hidden_values
                    AccessEssentials = list(all_hidden_values.keys())[-1]
                    set_private = self.set_private
                    for cls in all_hidden_values:
                        if cls == AccessEssentials or cls in AccessEssentials._subclasses_:
                            set_private("_privates_", [], cls = cls)
                            set_private("_protecteds_", [], cls = cls)
                            set_private("_publics_", [], cls = cls)
                            set_private("AccessEssentials2", api_self.AccessEssentials, cls = cls) # derived classes can monkeypatch methods like self.check_caller but this will stay intact
                            set_private("AccessEssentials3", api_self.AccessEssentials, cls = cls)
                            set_private("InsecureRestrictor", api_self.InsecureRestrictor, cls = cls)                            
                    for cls in all_hidden_values:
                        if cls == AccessEssentials or cls in AccessEssentials._subclasses_:
                            set_private("private", api_self.Modifier(self.set_private), cls = cls) 
                            set_private("protected", api_self.Modifier(self.set_protected), cls = cls) 
                            set_private("public", api_self.Modifier(self.set_public), cls = cls)
                            set_private(f"{cls.__name__}_private", None, cls = cls)
                    if hasattr(self, "secure_class"):
                        set_private("_class_", type(self), cls = type(self))               
                    self.ready_to_redirect()                    
                    
                def pre_init(self):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")
                    try:
                        get_private = object.__getattribute__(self, "get_private")
                        type.__delattr__(type(self), "get_private")
                    except AttributeError:
                        pass
                    else:
                        type.__setattr__(type(self), "get_private", get_private.__func__)
                        try:
                            all_hidden_values = get_private("all_hidden_values")
                        except AttributeError:
                            pass
                        else:
                            _caller = sys._getframe(1).f_code
                            for _cls in all_hidden_values:
                                if _caller in all_hidden_values[_cls]["auth_codes"]:
                                    break
                            else:
                                raise ProtectedError(f"\"{_caller.co_name}\" is not authorized to use this function")                            
                    
                    self.AccessEssentials2 = api_self.AccessEssentials
                    self.InsecureRestrictor = api_self.InsecureRestrictor 
                    self.start_access_check()                    
                    self.init_privates()
                    self.authorize(api_self.SecureClass)
                    self.authorize(api_self.SecureInstance)                    
                    self.authorize(api_self.super)
                    self.authorize(api_self.Modifier)
                    _setattr_ = self.create_setattr(depth = -2)
                    _setattr_("temp", None)
                    _delattr_ = self.create_delattr(depth = -2)
                    _delattr_("temp")
                                        
            return AccessEssentials  


        @property
        def create_protected_gate(api_self):
            def create_protected_gate(base):
                class ProtectedGate(type(base)):
                    class_id = "access_modifiers.ProtectedGate"
                    _privates_ = []
                    _protecteds_ = []                    
                    cls = base
                    
                    def __init__(self):
                        pass                        
                    
                    __getattribute__ = object.__getattribute__
                    __setattr__ = object.__setattr__
                    __delattr__ = object.__delattr__
                                                                       
                    def getter(self, name):
                        return getattr(base, name)

                    def setter(self, name, value):
                        setattr(base, name, value)

                    def deleter(self, name):
                        delattr(base, name)                    
                
                pg = ProtectedGate()
                type(pg).__getattribute__ = object.__getattribute__
                type(pg).__setattr__ = object.__setattr__
                type(pg).__delattr__ = object.__delattr__
                return pg
            
            return create_protected_gate


        @property
        def create_object_proxy_meta(api_self):
            def create_object_proxy_meta(protected_gate):
                class ObjectProxyMeta(type):
                    def __getattribute__(cls, name):
                        try:
                            getter = object.__getattribute__(protected_gate, "getter")
                            return getter(name)
                        except PrivateError as e:
                            e.inherited = True
                            e.caller_name = sys._getframe(1).f_code.co_name
                            raise
                        
                return ObjectProxyMeta

            return create_object_proxy_meta

            
        @property
        def make_real_bases(api_self):
            def make_real_bases(bases):
                new_bases = []
                for base in bases:
                    if not isinstance(base, type):
                        pg = api_self.create_protected_gate(base)            
                        class ObjectProxy(metaclass = api_self.create_object_proxy_meta(pg)):
                            def __getattribute__(self, name):
                                try:
                                    value = object.__getattribute__(self, name)
                                except AttributeError:
                                    try:
                                        value = getattr(type(self), name)
                                    except PrivateError as e:
                                        e.caller_name = sys._getframe(1).f_code.co_name
                                        raise                                       
                                    if api_self.is_function(value) and type(value) != types.MethodType:
                                        value = types.MethodType(value, self)
                                else:
                                    if hasattr(value, "__code__") and hasattr(ObjectProxy, name):                                        
                                        method = type.__getattribute__(ObjectProxy, name)
                                        if hasattr(method, "__code__") and method.__code__ == value.__code__:                                            
                                            try:
                                                value = getattr(type(self), name)
                                            except PrivateError as e:
                                                e.caller_name = sys._getframe(1).f_code.co_name
                                                raise                                       
                                            if api_self.is_function(value) and type(value) != types.MethodType:
                                                value = types.MethodType(value, self)                                                
                                return value
                            
                        ObjectProxy.protected_gate = pg
                        new_bases.append(ObjectProxy)
                    else:
                        new_bases.append(base)
                new_bases = tuple(new_bases)
                return new_bases
            
            return make_real_bases

        
        @property
        def InsecureRestrictor(api_self):
            """Slightly faster than Restrictor but has almost no security.
            Inheritance is not supported (derived classes can access private members of their bases)"""
            class InsecureRestrictor(type):
                @classmethod
                def acts_access_essentials(metacls, base):
                    try:
                        if not hasattr(base, "ae_class_id") or base.ae_class_id != "access_modifiers.AccessEssentials":
                            return False
                    except PrivateError:
                        pass
                    return True

                @classmethod
                def is_access_essentials(metacls, base):                    
                    if not metacls.acts_access_essentials(base):
                        return False
                    try:
                        base = type.__getattribute__(base, "protected_gate")
                    except AttributeError:
                        pass
                    else:
                        return False
                    try:
                        ae_class_id = type.__getattribute__(base, "ae_class_id")
                        type.__delattr__(base, "ae_class_id")
                    except AttributeError:                        
                        return False                    
                    else:
                        type.__setattr__(base, "ae_class_id", ae_class_id)
                        if ae_class_id == "access_modifiers.AccessEssentials":
                            return True
                        else:
                            return False                    

                @classmethod
                def remove_access_essentials(metacls, bases):
                    new_bases = list(bases)
                    for base in bases:                        
                        if metacls.is_access_essentials(base):
                            new_bases.remove(base)
                    return tuple(new_bases)

                @classmethod
                def add_access_essentials(metacls, bases):
                    for base in bases:
                        if metacls.acts_access_essentials(base):
                            return bases                    
                    bases = list(bases)
                    bases.append(api_self.AccessEssentials)
                    bases = tuple(bases)                                       
                    return bases                    
                    
                @classmethod
                def has_access_essentials(metacls, bases):
                    for base in bases:                       
                        if metacls.acts_access_essentials(base):
                            return True
                    return False

                @classmethod
                def get_derived_mbases(metacls, bases):
                    metaclasses = [type]
                    for base in bases:
                        metaclasses.append(type(base))
                    metaclasses = list(set(metaclasses))
                    derived_mbases = []
                    for a in range(len(metaclasses)):
                        same = 0
                        for b in range(len(metaclasses)):
                            if issubclass(metaclasses[b], metaclasses[a]):
                                same += 1
                                if same == 2:
                                    break
                        if same != 2:
                            derived_mbases.append(metaclasses[a])
                    return derived_mbases
                
                @classmethod
                def get_needed_mbases(metacls, bases):
                    derived_mbases = metacls.get_derived_mbases(bases)
                    needed = []
                    for derived_mbase in derived_mbases:
                        sufficient = False
                        for own_base in metacls.__bases__:
                            if issubclass(own_base, derived_mbase):
                                sufficient = True
                                break
                        if not sufficient:
                            needed.append(derived_mbase)
                    return needed

                @classmethod
                def has_conflicts(metacls, bases):
                    needed = metacls.get_needed_mbases(bases)
                    if len(needed) != 0:
                        return True
                    else:
                        return False                

                @classmethod
                def resolve_conflicts(metacls, bases):
                    needed = metacls.get_needed_mbases(bases)
                    meta_bases = needed + list(metacls.__bases__)
                    meta_bases = tuple(meta_bases)
                    InsecureRestrictor = api_self.InsecureRestrictor
                    meta_dct = dict(InsecureRestrictor.__dict__)
                    meta_dct["__new__"] = InsecureRestrictor.__new__
                    InsecureRestrictor = type("InsecureRestrictor", meta_bases, meta_dct)
                    return InsecureRestrictor

                @classmethod
                def init_dct(metacls, dct):
                    lists_names = ["_privates_",
                                   "_protecteds_",
                                   "_publics_",
                                   "private_bases",
                                   "protected_bases",
                                   "base_protecteds",
                                   "base_publics",
                                   "base_privates",
                                   "_subclasses_",
                                   "objs"]
                    for list_name in lists_names:
                        if list_name not in dct:
                            dct[list_name] = []
                        elif list_name != "objs":
                            dct[list_name] = list(dct[list_name])
                    
                @classmethod
                def extract_values(metacls, dct, group_name, value_type):
                    for name, member in dct.items():
                        both_has = hasattr(type(member), "class_id") and hasattr(value_type, "class_id")
                        if both_has and type(member).class_id == value_type.class_id:
                            dct[group_name].append(name)
                            dct[name] = member.value

                @classmethod
                def extract_modifier(metacls, dct, modifier, list_name):
                    for name in dir(modifier):
                        if not (name.startswith("__") and name.endswith("__")):
                            dct[list_name].append(name)
                            dct[name] = getattr(modifier, name)
                            delattr(modifier, name)
                    
                @classmethod
                def apply_base_rules(metacls, bases, dct):
                    for base in bases:
                        if hasattr(base, "_protecteds_"):
                            dct["base_protecteds"].extend(base._protecteds_)
                            if hasattr(base, "base_protecteds"):
                                dct["base_protecteds"].extend(base.base_protecteds)                           
                            dct["base_publics"].extend(base.base_publics)
                        names = list(base.__dict__.keys())
                        for name in list(names):
                            try:
                                isinstance(base.__dict__[name], AccessError)
                            except RuntimeError:
                                pass
                            else:
                                if isinstance(base.__dict__[name], AccessError):
                                    names.remove(name)                    
                        dct["base_publics"].extend(names)
                        if hasattr(base, "protected_bases"):
                            dct["protected_bases"].extend(base.protected_bases)
                    dct["base_protecteds"] = list(set(dct["base_protecteds"]))
                    dct["base_publics"] = list(set(dct["base_publics"]))
                
                @classmethod
                def set_name_rules(metacls, bases, dct):
                    for member_name, member in dct.items():
                        valid_ids = ["access_modifiers.PrivateValue",
                                     "access_modifiers.ProtectedValue",
                                     "access_modifiers.PublicValue"]
                        no_modifier = not hasattr(type(member), "class_id") or type(member).class_id not in valid_ids
                        no_modifier2 = member_name not in dct["_privates_"] and member_name not in dct["_protecteds_"] and member_name not in dct["_publics_"]
                        special_names = ["_privates_",
                                       "_protecteds_",
                                       "_publics_",
                                       "_new_",
                                       "_getattribute_",
                                       "_setattr_",
                                       "_delattr_",
                                       "private_bases",
                                       "protected_bases",
                                       "base_protecteds",
                                       "base_privates",
                                       "base_publics"]
                        if no_modifier and no_modifier2 and member_name not in special_names:
                            dct[member_name] = api_self.default(member)                            
                    metacls.extract_values(dct, "_privates_", api_self.PrivateValue)                    
                    metacls.extract_values(dct, "_protecteds_", api_self.ProtectedValue)
                    metacls.extract_values(dct, "_publics_", api_self.PublicValue)
                    metacls.extract_modifier(dct, api_self.PrivateModifier, "_privates_")
                    metacls.extract_modifier(dct, api_self.ProtectedModifier, "_protecteds_")
                    metacls.extract_modifier(dct, api_self.PublicModifier, "_publics_")                    
                    metacls.apply_base_rules(bases, dct)                    
                    if "__new__" in dct["_privates_"]:
                        dct["_privates_"].append("_new_")
                    if "__new__" in dct["_protecteds_"]:
                        dct["_protecteds_"].append("_new_")
                    if "__new__" in dct["_publics_"]:
                        dct["_publics_"].append("_new_")
                    if "__new__" not in dct["_privates_"] and "__new__" not in dct["_protecteds_"] and "__new__" not in dct["_publics_"]:                        
                        dct["_publics_"].append("__new__")                        
                    dct["_privates_"] = dct["_privates_"] + dct["_protecteds_"] + api_self.AccessEssentials._privates_
                    dct["_privates_"] += ["__dict__",
                                          "__bases__",
                                          "_bases",
                                          "__mro__",
                                          "_mro",
                                          "last_class",
                                          "private_bases",
                                          "protected_bases"]
                    for member_name in dct:
                        if (member_name in dct["_privates_"] or member_name in dct["_protecteds_"]) and member_name in dct["_publics_"]:
                            dct["_publics_"].remove(member_name)                    
                    dct["_protecteds_"] = list(set(dct["_protecteds_"]))                
                    dct["_privates_"] = list(set(dct["_privates_"]))
                    dct["_publics_"] = list(set(dct["_publics_"]))  

                @classmethod
                def set_accessors(metacls, dct):
                    if "__getattribute__" in dct:
                        dct["_getattribute_"] = dct["__getattribute__"]
                        if "class_id" not in dct or dct["class_id"] != "access_modifiers.ProtectedGate":
                            del dct["__getattribute__"]
                    if "__setattr__" in dct:
                        dct["_setattr_"] = dct["__setattr__"]
                        if "class_id" not in dct or dct["class_id"] != "access_modifiers.ProtectedGate":
                            del dct["__setattr__"]
                    if "__delattr__" in dct:
                        dct["_delattr_"] = dct["__delattr__"]
                        if "class_id" not in dct or dct["class_id"] != "access_modifiers.ProtectedGate":
                            del dct["__delattr__"]

                @classmethod
                def get_new(metacls):
                    def __new__(cls, *args, **kwargs):
                        if hasattr(cls, "secure_class"):
                            cls = cls.secure_class.own_hidden_values["cls"]
                            
                        new_dict = dict(cls.__dict__)
                        del new_dict["static_dict"]
                        if "__getattribute__" in cls.static_dict:
                            new_dict["__getattribute__"] = cls.static_dict["__getattribute__"]
                        if "__setattr__" in cls.static_dict:
                            new_dict["__setattr__"] = cls.static_dict["__setattr__"]
                        if "__delattr__" in cls.static_dict:
                            new_dict["__delattr__"] = cls.static_dict["__delattr__"]
                        if "__new__" in cls.static_dict:
                            new_dict["__new__"] = cls.static_dict["__new__"]
                        else:
                            del new_dict["__new__"]
                        if "__classcell__" in cls.static_dict:
                            new_dict["__classcell__"] = cls.static_dict["__classcell__"]

                        new_cls = api_self.InsecureRestrictor(cls.__name__, cls.__bases__, new_dict)
                        
                        if "__new__" in new_cls._privates_ and "__new__" not in new_cls._protecteds_:
                            caller = sys._getframe(1).f_code
                            raise PrivateError(caller.co_name, "__new__", new_cls.__name__, caller = caller)
                        elif "_new_" in new_cls._privates_ and "_new_" not in new_cls._protecteds_:
                            caller = sys._getframe(1).f_code
                            raise PrivateError(caller.co_name, "__new__", new_cls.__name__, caller = caller)
                        elif "__new__" in new_cls._protecteds_:
                            caller = sys._getframe(1).f_code
                            raise ProtectedError(caller.co_name, "__new__", new_cls.__name__, caller = caller)
                        elif "_new_" in new_cls._protecteds_:
                            caller = sys._getframe(1).f_code
                            raise ProtectedError(caller.co_name, "__new__", new_cls.__name__, caller = caller)

                        try:
                            new_cls._new_
                        except PrivateError as e:
                            e.caller = sys._getframe(1).f_code
                            e.caller_name = sys._getframe(1).f_code.co_name
                            e.member_name = "__new__"
                        inherited_new = False
                        for base in new_cls.__bases__:
                            if hasattr(base, "_new_") and base._new_ == new_cls._new_:
                                inherited_new = True                               
                                break
                        if inherited_new:
                            for base in new_cls.__mro__:
                                if hasattr(base, "_privates_") and "__new__" in (base._privates_ or base.base_privates) and "__new__" not in base._protecteds_:
                                    caller = sys._getframe(1).f_code
                                    raise PrivateError(caller.co_name, "__new__", base.__name__, inherited = True, caller = caller)
                                elif hasattr(base, "_privates_") and "__new__" in base._protecteds_:
                                    caller = sys._getframe(1).f_code
                                    raise ProtectedError(caller.co_name, "__new__", cls.__name__, caller = caller)
                                elif hasattr(base, "_privates_") and "__new__" in base.base_protecteds:
                                    for grand_parent in base.__bases__:
                                        if hasattr(grand_parent, "_privates_") and ("__new__" in grand_parent._protecteds_ or "__new__" in grand_parent.base_protecteds):
                                            break
                                    else:
                                        if "__new__" not in base._publics_:                                            
                                            caller = sys._getframe(1).f_code
                                            raise ProtectedError(caller.co_name, "__new__", cls.__name__, caller = caller)
                                if hasattr(base, "_new_") and base._new_ != object.__new__:
                                    for grand_parent in base.__bases__:
                                        try:
                                            if hasattr(grand_parent, "_new_") and grand_parent._new_ == base._new_:                              
                                                break
                                        except PrivateError:
                                            pass
                                    else:
                                        break

                        new_obj = new_cls._new_(new_cls)                        
                        if type(new_obj) == new_cls:
                            new_obj.pre_init()                            
                            if "__init__" in new_cls._privates_ and "__init__" not in new_cls._protecteds_:
                                caller = sys._getframe(1).f_code
                                raise PrivateError(caller.co_name, "__init__", new_cls.__name__, caller = caller)
                            elif "__init__" in new_cls._protecteds_:
                                caller = sys._getframe(1).f_code
                                raise ProtectedError(caller.co_name, "__init__", new_cls.__name__, caller = caller)                                                    
                            __init__ = new_obj.__init__
                            if not api_self.is_function(__init__):
                                for base in new_cls.__mro__:
                                    if hasattr(base, "_privates_") and "__init__" in (base._privates_ or base.base_privates) and "__init__" not in base._protecteds_:
                                        caller = sys._getframe(1).f_code
                                        raise PrivateError(caller.co_name, "__init__", base.__name__, inherited = True, caller = caller)
                                    elif hasattr(base, "_privates_") and "__init__" in base._protecteds_:
                                        caller = sys._getframe(1).f_code
                                        raise ProtectedError(caller.co_name, "__init__", cls.__name__, caller = caller)
                                    elif hasattr(base, "_privates_") and "__init__" in base.base_protecteds:
                                        for grand_parent in base.__bases__:
                                            if hasattr(grand_parent, "_privates_") and ("__init__" in grand_parent._protecteds_ or "__init__" in grand_parent.base_protecteds):
                                                break
                                        else:
                                            if "__init__" not in base._publics_:
                                                caller = sys._getframe(1).f_code
                                                raise ProtectedError(caller.co_name, "__init__", cls.__name__, caller = caller)
                                    if api_self.is_function(base.__init__):
                                        __init__ = base.__init__
                                        __init__ = types.MethodType(__init__, new_obj)                                        
                                        break
                            
                            new_obj.private.redirect_access = True
                            if not hasattr(cls, "class_id") or cls.class_id not in ["access_modifiers.SecureClass",
                                                                                    "access_modifiers.SecureInstance",
                                                                                    "access_modifiers.ProtectedGate",
                                                                                    "access_modifiers.SecureApi"]:
                                object.__setattr__(new_obj, "_class_", cls.secure_class)
                                modifier_backup = api_self.default
                                api_self.set_default(api_self.public)                                        
                                SecureInstance = api_self.SecureInstance
                                api_self.set_default(modifier_backup)
                                SecureInstance.proxy = cls.secure_class
                                new_obj = SecureInstance(new_obj)
                                api_self.Restrictor.remove_base_leaks(new_obj)                        
                                type(new_obj).redirect_access = True
                                new_cls.objs.append(new_obj)
                                if type(__init__) == types.MethodType:
                                    __init__ = __init__.__func__
                                    __init__ = types.MethodType(__init__, new_obj)
                            __init__(*args, **kwargs)                            
                        return new_obj
                    return __new__
                    
                @classmethod
                def set_new(metacls, dct, bases):
                    if "__new__" in dct:
                        dct["_new_"] = dct["__new__"]
                        if "_new_" not in dct["_privates_"] and "_new_" not in dct["_protecteds_"] and "_new_" not in dct["_publics_"]:                        
                            dct["_publics_"].append("_new_")                                                
                    elif "_new_" not in dct:
                        for base in bases:
                            try:
                                hasattr(base, "_new_")
                            except PrivateError:
                                break
                            if hasattr(base, "_new_"):
                                if base._new_ != object.__new__:
                                    break
                            elif hasattr(base, "__new__"):
                                if base.__new__ != object.__new__:
                                    break
                        else:                            
                            dct["_new_"] = object.__new__
                            if "_new_" not in dct["_privates_"] and "_new_" not in dct["_protecteds_"] and "_new_" not in dct["_publics_"]:                        
                                dct["_publics_"].append("_new_")                            
                    dct["__new__"] = metacls.get_new()

                @classmethod
                def get_mro(metacls, bases):
                    mro = []
                    for base in bases:
                        base_mro = list(base.__mro__)
                        if base not in base.__mro__:
                            base_mro.insert(0, base)
                        mro.append(base_mro)
                    mro = functools._c3_merge(mro)
                    bases = list(filter(metacls.is_access_essentials, mro))                   
                    AccessEssentials = bases[-1]
                    for base in bases:
                        mro.remove(base)
                    for base in bases:
                        AccessEssentials._subclasses_.extend(base._subclasses_)
                    AccessEssentials._subclasses_ = list(set(AccessEssentials._subclasses_))
                    mro.insert(-1, AccessEssentials)
                    mro = tuple(mro)
                    return mro
                                    
                @classmethod
                def create_class(metacls, name, bases, dct):
                    metacls.init_dct(dct)                    
                    metacls.set_name_rules(bases, dct)                    
                    dct["static_dict"] = dict(dct)
                    metacls.set_accessors(dct)
                    metacls.set_new(dct, bases)
                    dct["_bases"] = bases
                    dct["_mro"] = metacls.get_mro(bases)
                    cls = type.__new__(metacls, name, bases, dct)
                    return cls

                @classmethod
                def update_subclasses(metacls, bases, cls):
                    for base in bases:
                        try:
                            base = type.__getattribute__(base, "protected_gate")
                        except AttributeError:
                            if base is object:
                                continue
                            if not hasattr(base, "_subclasses_"):
                                base._subclasses_ = []                            
                        else:
                            base = base.cls.own_hidden_values["cls"]
                        base._subclasses_.append(cls)
                    
                def __new__(metacls, name, bases, dct):                    
                    bases = api_self.make_real_bases(bases)                    
                    bases = metacls.add_access_essentials(bases)
                    if metacls.has_conflicts(bases):
                        InsecureRestrictor = metacls.resolve_conflicts(bases)
                        return InsecureRestrictor(name, bases, dct)
                    else:
                        cls = metacls.create_class(name, bases, dct)
                        metacls.update_subclasses(cls.__mro__, cls)
                        type.__setattr__(cls, "public", api_self.ClassModifier(cls.set_class_public))
                        type.__setattr__(cls, "protected", api_self.ClassModifier(cls.set_class_protected))
                        type.__setattr__(cls, "private", api_self.ClassModifier(cls.set_class_private))                        
                        return cls              

                @property
                def __bases__(cls):
                    return type.__getattribute__(cls, "_bases")

                @property
                def __mro__(cls):
                    return type.__getattribute__(cls, "_mro")

                def mro(cls):
                    return type.mro(cls)                
                
                def should_redirect(cls, name):
                    try:
                       redirect_access = type.__getattribute__(cls, "redirect_access")
                    except AttributeError:
                        has_redirect_access = False
                    else:
                        has_redirect_access = True
                       
                    maybe_redirect = has_redirect_access and redirect_access == True
                    return maybe_redirect and name != "__class__" and name != "own_redirect_access"
                    
                def get_unbound_base_attr(cls, name, bases = None, return_base = False):
                    def is_function(func):
                        """We have to duplicate this function for performance reasons"""
                        try:
                            code = object.__getattribute__(func, "__code__")
                        except AttributeError:
                            has_code = type(func) == types.MethodType
                        else:
                            has_code = True
                        if callable(func) and has_code and type(func.__code__) == types.CodeType:
                            return True
                        else:
                            return False                        
                    
                    if bases is None:
                        bases = type.__getattribute__(cls, "__mro__")
                    AccessEssentials = type.__getattribute__(cls, "__mro__")[-2]
                    if name in AccessEssentials.__dict__ and is_function(getattr(AccessEssentials, name)):
                        AccessEssentials = api_self.AccessEssentials
                        value = getattr(AccessEssentials, name)
                        if not return_base:                                
                            return value
                        else:
                            return value, AccessEssentials
                                                
                    found = False                    
                    for base in bases:                        
                        try:
                            raw_base = type.__getattribute__(base, "protected_gate")
                        except AttributeError:
                            raw_base = base                            
                        else:                            
                            raw_base = raw_base.cls.own_hidden_values["cls"]
                        try:                            
                            value = type.__getattribute__(raw_base, name)
                            type.__delattr__(raw_base, name)
                        except AttributeError:
                            try:
                                type(base).__getattribute__(base, name)                                
                            except AttributeError:
                                continue                                
                            except PrivateError as e:
                                e.caller_name = sys._getframe(1).f_code.co_name
                                cls.last_class = base
                                e.class_name = e.base_name
                                raise                        
                            continue
                        except TypeError:
                            pass
                        else:
                            type.__setattr__(raw_base, name, value)
                            
                        try:                            
                            value = type(base).__getattribute__(base, name)                            
                            found = True                            
                        except AttributeError:                                                       
                            continue
                        except PrivateError as e:                            
                            e.caller_name = sys._getframe(1).f_code.co_name
                            cls.last_class = base
                            e.class_name = e.base_name
                            raise
                        else:                            
                            is_builtin_new = name == "_new_" and value == object.__new__
                            is_builtin_new2 = name == "__new__" and value == object.__new__
                            is_builtin = type(value) == types.WrapperDescriptorType
                            if is_builtin_new or is_builtin_new2 or is_builtin:
                                continue
                            if not return_base:                                
                                return value
                            else:
                                return value, base
                            
                    if found and not return_base:
                        return value
                    elif found:
                        return value, base
                    raise AttributeError(name)

                def has_own_attr(cls, name):
                    try:
                        value = type.__getattribute__(cls, name)
                        type.__delattr__(cls, name)
                    except AttributeError:
                        return False
                    except TypeError: # name is "__name__"
                        return True
                    else:
                        type.__setattr__(cls, name, value)
                        return True

                def is_public(cls, name):                    
                    subclass = cls
                    has_public = cls.has_own_attr(name)                    
                    if not has_public:
                        try:
                            _, cls = cls.get_unbound_base_attr(name, return_base = True)
                        except PrivateError:                            
                            return False
                        except AttributeError:
                            if hasattr(cls, name) and name in cls._privates_:
                                return False
                            elif hasattr(cls, name):
                                return True
                            else:
                                raise

                    is_private = hasattr(cls, "_publics_") and name not in cls._publics_ and name != "__name__" and name in cls.base_privates
                    if hasattr(cls, "_privates_") and (name in cls._privates_ or name in cls._protecteds_ or is_private):                        
                        return False
                    is_private = hasattr(subclass, "_publics_") and name not in subclass._publics_ and name != "__name__" and  name in subclass.base_privates
                    if is_private:                        
                        return False
                    if hasattr(subclass, "_publics_") and name in subclass._publics_:
                        return True
                    if hasattr(subclass, "_protecteds_") and name in subclass._protecteds_:
                        return False
                    try:
                        cls = type.__getattribute__(cls, "protected_gate")
                    except AttributeError:
                        pass                            
                    else:
                        cls = cls.cls.own_hidden_values["cls"]                                           
                    for base in subclass.__mro__:
                        try:
                            base = type.__getattribute__(base, "protected_gate")
                        except AttributeError:
                            pass                            
                        else:
                            base = base.cls.own_hidden_values["cls"]                       
                        if base == cls:
                            break
                        if hasattr(base, "_publics_") and name in base._publics_:
                            return True                            
                        if hasattr(base, "_protecteds_") and name in base._protecteds_:                            
                            return False                        
                    return True

                def is_protected(cls, name):
                    if name in cls._protecteds_ or name in cls.base_protecteds:
                        protected_holder = None                                        
                        private_holder = None
                        base_privates_holder = None
                        check_protected = True
                        check_private = True
                        check_base_privates = True
                        mro = cls.__mro__
                        mro = list(mro)
                        mro.insert(0, cls)
                        mro = tuple(mro)                                            
                        for base in mro:
                            will_check = check_protected or check_private or check_base_privates
                            if will_check and hasattr(base, "_privates_"):
                                if check_protected and name in base._protecteds_:
                                    check_protected = False
                                    protected_holder = base
                                if check_private and name in base._privates_:
                                    check_private = False
                                    private_holder = base
                                if check_base_privates and name in base.base_privates:
                                    check_base_privates = False
                                    base_privates_holder = base
                        if protected_holder is None:
                            return True
                        if base_privates_holder is not None:
                            for base in base_privates_holder.private_bases:
                                if hasattr(base, name):
                                    break
                            mro2 = []
                            for base2 in mro:
                                try:
                                    mro2.append(type.__getattribute__(base2, "protected_gate").cls)
                                except AttributeError:
                                    mro2.append(base2)
                            if mro2.index(base) <= mro.index(protected_holder):
                                return False
                        if private_holder is not None and mro.index(private_holder) < mro.index(protected_holder):                                                
                            return False
                        else:
                            return True
                    return False                                         
                    
                def __getattribute__(cls, name):
                    should_redirect = type.__getattribute__(cls, "should_redirect")
                    if should_redirect(name):
                        cls = type.__getattribute__(cls, "proxy")
                        try:                            
                            return getattr(cls, name)
                        except AccessError as e:
                            e.caller_name = sys._getframe(1).f_code.co_name
                            raise
                    else:                        
                        if name == "own_redirect_access":
                            name = "redirect_access"                            
                        try:                                                 
                            value = type.__getattribute__(cls, name)                            
                            deleted = False
                            try:
                                not_meta_method = not hasattr(value, "__code__") or \
                                                  not hasattr(type(cls), name) or \
                                                  not hasattr(getattr(type(cls), name), "__code__") or \
                                                  getattr(type(cls), name).__code__ != value.__code__
                            except RuntimeError:
                                not_meta_method = True
                            if type(value) == types.FunctionType and hasattr(value, "__code__") and not_meta_method:
                                class AttributeTest:
                                    pass
                                try:
                                    setattr(AttributeTest, name, value)
                                    delattr(AttributeTest, name)
                                except AttributeError:                                    
                                    pass
                                else:
                                    type.__delattr__(cls, name)
                                    deleted = True
                        except AttributeError as e:
                            get_unbound_base_attr = type.__getattribute__(cls, "get_unbound_base_attr")
                            try:                                
                                value = get_unbound_base_attr(name)
                            except AttributeError:                                
                                raise e
                            except PrivateError as e:                                
                                e.caller_name = sys._getframe(1).f_code.co_name
                                raise
                            if type(value) == types.MethodType:
                                value = value.__func__
                                value = types.MethodType(value, cls.secure_class)
                            return value
                        else:
                            if deleted:
                                type.__setattr__(cls, name, value)
                            is_builtin_new = name == "_new_" and value == object.__new__
                            is_builtin_new2 = name == "__new__" and value == object.__new__
                            is_builtin = type(value) == types.WrapperDescriptorType
                            try:
                                class_id = type.__getattribute__(cls, "class_id")
                            except AttributeError:
                                has_class_id = False
                            else:
                                has_class_id = True                                
                            is_protected_gate =  has_class_id and class_id == "access_modifiers.ProtectedGate"                            
                            if not is_protected_gate and (is_builtin_new or is_builtin_new2 or is_builtin):                                
                                get_unbound_base_attr = type.__getattribute__(cls, "get_unbound_base_attr")
                                try:
                                    value = get_unbound_base_attr(name)                                  
                                except AttributeError:
                                    pass
                                except PrivateError as e:                                
                                    e.caller_name = sys._getframe(1).f_code.co_name
                                    raise
                            try:
                                secure_class = type.__getattribute__(cls, "secure_class")
                            except AttributeError:
                                has_secure_class = False
                            else:
                                has_secure_class = True
                            if type(value) == types.MethodType and has_secure_class:                                
                                def is_meta_method(cls, name, value):
                                    if hasattr(type(cls), name):
                                        function = getattr(type(cls), name)
                                        if value.__code__ == function.__code__:
                                            return True
                                    return False                
                                
                                if not is_meta_method(cls, name, value):                                
                                    value = value.__func__
                                    value = types.MethodType(value, secure_class)
                            return value                            

                def set_class_public(cls, name, value):
                    type.__setattr__(cls, name, value)
                    if name not in cls._publics_:
                        cls._publics_.append(name)
                    if name in cls._protecteds_:
                        cls._protecteds_.remove(name)
                    if name in cls._privates_:
                        cls._privates_.remove(name)                        
                    for subclass in cls._subclasses_:
                        if name not in subclass.base_publics:
                            subclass.base_publics.append(name)
                        if subclass.private_bases != []:
                            for private_base in subclass.private_bases:
                                if not isinstance(private_base, type):
                                    private_base = private_base.own_hidden_values["cls"]
                                for cls2 in private_base.__mro__:
                                    try:
                                        cls2 = type.__getattribute__(cls2, "protected_gate")
                                    except AttributeError:
                                        pass
                                    else:
                                        cls2 = cls2.cls.own_hidden_values["cls"]
                                    if cls2 == cls and name not in subclass.base_privates:
                                        subclass.base_privates.append(name)
                        if subclass.protected_bases != []:
                            for protected_base in subclass.protected_bases:
                                if not isinstance(protected_base, type):
                                    protected_base = protected_base.own_hidden_values["cls"]
                                for cls2 in protected_base.__mro__:
                                    try:
                                        cls2 = type.__getattribute__(cls2, "protected_gate")
                                    except AttributeError:
                                        pass
                                    else:
                                        cls2 = cls2.cls.own_hidden_values["cls"]
                                    if cls2 == cls:
                                        if name not in subclass.base_protecteds:
                                            subclass.base_protecteds.append(name)
                                        for subclass2 in subclass._subclasses_:
                                            if name not in subclass2.base_protecteds:
                                                subclass2.base_protecteds.append(name)

                def set_class_protected(cls, name, value):
                    type.__setattr__(cls, name, value)
                    if name in cls._publics_:
                        cls._publics_.remove(name)
                    if name not in cls._protecteds_:
                        cls._protecteds_.append(name)
                    if name not in cls._privates_:
                        cls._privates_.append(name)                        
                    for subclass in cls._subclasses_:
                        if name not in subclass.base_protecteds:
                            subclass.base_protecteds.append(name)
                        if subclass.private_bases != []:
                            for private_base in subclass.private_bases:
                                if not isinstance(private_base, type):
                                    private_base = private_base.own_hidden_values["cls"]
                                for cls2 in private_base.__mro__:
                                    try:
                                        cls2 = type.__getattribute__(cls2, "protected_gate")
                                    except AttributeError:
                                        pass
                                    else:
                                        cls2 = cls2.cls.own_hidden_values["cls"]
                                    if cls2 == cls and name not in subclass.base_privates:
                                        subclass.base_privates.append(name)
                                        
                def set_class_private(cls, name, value):
                    type.__setattr__(cls, name, value)
                    if name in cls._publics_:
                        cls._publics_.remove(name)
                    if name in cls._protecteds_:
                        cls._protecteds_.remove(name)
                    if name not in cls._privates_:
                        cls._privates_.append(name)                                            
                    
                def modify_attr(cls, name, delete = False, value = None):
                    should_redirect = type.__getattribute__(cls, "should_redirect")                   
                    if should_redirect(name):                                
                        try:
                            cls.own_redirect_access = False                            
                            if not delete:
                                def setter(cls, name, value):
                                    setattr(cls.proxy, name, value)
                                setter(cls, name, value)
                            else:
                                def deleter(cls, name):
                                    delattr(cls.proxy, name)                                
                                deleter(cls, name)
                        except PrivateError:
                            raise PrivateError(sys._getframe(2).f_code.co_name, name, cls.proxy.__name__, True)
                        finally:
                            cls.redirect_access = True
                    else:
                        if name == "own_redirect_access":
                            name = "redirect_access"
                        names = ["redirect_access",
                                 "get_private",
                                 "__getattribute__",
                                 "__setattr__",
                                 "__delattr__",
                                 "last_class",
                                 "secure_class"]                            
                        if not delete:
                            if name not in names:
                                exists = cls.has_own_attr(name)
                            type.__setattr__(cls, name, value)
                            if name not in names:
                                if hasattr(cls, "secure_class"):
                                    type.__setattr__(cls.secure_class.own_hidden_values["cls"], name, value)
                                for obj in cls.objs:                                    
                                    type.__setattr__(type(obj.own_hidden_values["inst"]), name, value)
                                if not exists:
                                    if api_self.default.__code__ == api_self.public.__code__:
                                        cls.set_class_public(name, value)
                                    elif api_self.default.__code__ == api_self.protected.__code__:
                                        cls.set_class_protected(name, value)
                                    else:
                                        cls.set_class_private(name, value)
                        else:
                            if name not in names:
                                if name in cls._privates_:
                                    cls._privates_.remove(name)
                                if name in cls._protecteds_:
                                    cls._protecteds_.remove(name)
                                if name in cls._publics_:
                                    cls._publics_.remove(name)
                                for subclass in cls._subclasses_:
                                    found = False
                                    for base2 in subclass.__mro__:                        
                                        try:
                                            raw_base = type.__getattribute__(base2, "protected_gate")
                                        except AttributeError:
                                            raw_base = base2                            
                                        else:
                                            raw_base = raw_base.cls.own_hidden_values["cls"]
                                        try:                            
                                            value = type.__getattribute__(raw_base, name)                            
                                            type.__delattr__(raw_base, name)
                                            found = True
                                        except AttributeError:                                                   
                                            continue
                                        except TypeError:
                                            pass
                                        else:
                                            type.__setattr__(raw_base, name, value)                           
                                            is_builtin_new = name == "_new_" and value == object.__new__
                                            is_builtin_new2 = name == "__new__" and value == object.__new__
                                            is_builtin = type(value) == types.WrapperDescriptorType
                                            if is_builtin_new or is_builtin_new2 or is_builtin:
                                                continue
                                            break
                                    if found and raw_base == cls:
                                        if name in subclass.base_publics:
                                            subclass.base_publics.remove(name)
                                        if name in subclass.base_protecteds:
                                            subclass.base_protecteds.remove(name)
                                        if name in subclass.base_privates:
                                            subclass.base_privates.remove(name)                                 
                            type.__delattr__(cls, name)
                            if name not in names:
                                for subclass in cls._subclasses_:
                                    found = False
                                    for base2 in subclass.__mro__:                        
                                        try:
                                            raw_base = type.__getattribute__(base2, "protected_gate")
                                        except AttributeError:
                                            raw_base = base2                            
                                        else:
                                            raw_base = raw_base.cls.own_hidden_values["cls"]
                                        try:                            
                                            value = type.__getattribute__(raw_base, name)                            
                                            type.__delattr__(raw_base, name)
                                            found = True
                                        except AttributeError:                                                   
                                            continue
                                        except TypeError:
                                            pass
                                        else:
                                            type.__setattr__(raw_base, name, value)                           
                                            is_builtin_new = name == "_new_" and value == object.__new__
                                            is_builtin_new2 = name == "__new__" and value == object.__new__
                                            is_builtin = type(value) == types.WrapperDescriptorType
                                            if is_builtin_new or is_builtin_new2 or is_builtin:
                                                continue
                                            break
                                    if found and name in raw_base._privates_ and name not in raw_base._protecteds_:
                                        raw_base.set_class_private(name, value)
                                    elif found and name in raw_base._privates_ and name in raw_base._protecteds_:
                                        raw_base.set_class_protected(name, value)
                                    elif found and name not in raw_base._privates_ and name not in raw_base._protecteds_:
                                        raw_base.set_class_public(name, value)                                                                        
                                
                                if hasattr(cls, "secure_class") and cls != cls.secure_class.own_hidden_values["cls"]:
                                    type.__delattr__(cls.secure_class.own_hidden_values["cls"], name)
                                for obj in cls.objs:                                    
                                    if type(obj.own_hidden_values["inst"]) != cls:
                                        type.__delattr__(type(obj.own_hidden_values["inst"]), name)
                                                    
                def __setattr__(cls, name, value):
                    modify_attr = type.__getattribute__(cls, "modify_attr")
                    modify_attr(name, value = value)                                        

                def __delattr__(cls, name):
                    modify_attr = type.__getattribute__(cls, "modify_attr") 
                    modify_attr(name, delete = True)

                def authorize_for_class(cls, func_or_cls):
                    cls.secure_class.own_hidden_values["redirect_access"] = False
                    cls.secure_class.authorize(func_or_cls)
                    cls.secure_class.own_hidden_values["redirect_access"] = True

            return InsecureRestrictor


        @property
        def SecureClass(api_self):
            class SecureClass(metaclass = api_self.InsecureRestrictor):
                class_id = "access_modifiers.SecureClass"
                
                def __init__(self, cls):
                    get_private = object.__getattribute__(self, "get_private")                    
                    no_redirect = types.MethodType(api_self.AccessEssentials.no_redirect, self)
                    all_hidden_values = get_private("all_hidden_values")
                    @no_redirect(all_hidden_values)                    
                    def __init__(self, cls):                        
                        private = self.private
                        private.cls = cls                        
                        private._privates_ = cls._privates_
                        private._protecteds_ = cls._protecteds_
                        private.base_publics = cls.base_publics
                        private.base_protecteds = cls.base_protecteds
                        private.base_privates = cls.base_privates
                        all_names = self.cls.__dict__
                        for member_name in all_names:                        
                            try:
                                member = type.__getattribute__(self.cls, member_name)
                            except AttributeError:
                                continue             
                            if api_self.is_function(member):
                                self.authorize(member)
                            else:
                                try:
                                    has_class_id = hasattr(member, "class_id")
                                except RuntimeError:
                                    continue
                                else:
                                    if has_class_id and member.class_id == "access_modifiers.Decoration":
                                        functions = []
                                        decoration = member
                                        while not api_self.is_function(decoration.func):                                            
                                            functions.append(decoration.decorator)
                                            decoration = decoration.func
                                        functions.append(decoration.decorator)
                                        func = decoration.func
                                        self.authorize(func)
                                        while True:
                                            try:
                                                func = functions.pop()(func)
                                            except IndexError:
                                                break
                                            self.authorize(func)
                                        type.__setattr__(cls, member_name, func)
                        self.authorize(api_self.InsecureRestrictor.modify_attr)
                        self.authorize(api_self.InsecureRestrictor.update_subclasses)
                        self.authorize(api_self.InsecureRestrictor.get_unbound_base_attr)
                        self.authorize(api_self.InsecureRestrictor.is_protected)
                        self.authorize(api_self.InsecureRestrictor.is_public)
                        self.authorize(api_self.InsecureRestrictor.set_class_public)
                        self.authorize(api_self.InsecureRestrictor.set_class_protected)
                        self.authorize(api_self.InsecureRestrictor.set_class_private)
                        self.authorize(api_self.InsecureRestrictor.authorize_for_class)                        
                        class A:
                            pass
                        super_ = api_self.super(api_self.SecureInstance(A()))
                        AccessEssentials = list(all_hidden_values.keys())[-1]
                        all_hidden_values[AccessEssentials]["auth_codes"].add(object.__getattribute__(super_, "__getattribute__").__code__)
                        self.super()
                        
                        self.cls.secure_class = self
                        self.cls._publics_.append("secure_class")

                        private.raise_PrivateError2 = self.raise_PrivateError2
                        private.raise_ProtectedError2 = self.raise_ProtectedError2
                        private.is_ro_method = self.is_ro_method
                        private.create_secure_method = self.create_secure_method
                        private.is_subclass_method2 = self.is_subclass_method2                        
                        private.control_access = self.control_access
                        
                    __init__(self, cls)

                def __call__(self, *args, **kwargs):
                    get_private = object.__getattribute__(self, "get_private")
                    hidden_values = get_private("hidden_values")                                                                  
                    try:
                        obj = self.own_hidden_values["cls"](*args, **kwargs)
                    except AccessError as e:
                        if hasattr(e, "caller") and e.caller == type(self).__call__.__code__:
                            e.caller = sys._getframe(1).f_code
                            e.caller_name = sys._getframe(1).f_code.co_name
                        raise                    
                    return obj

                def super(self):
                    get_private = object.__getattribute__(self, "get_private")                    
                    no_redirect2 = types.MethodType(api_self.AccessEssentials.no_redirect2, self)
                    all_hidden_values = get_private("all_hidden_values")
                    AccessEssentials = list(all_hidden_values.keys())[-1]                    
                    @no_redirect2(get_private("hidden_values"))
                    def super(self):
                        class super:
                            __slots__ = ["secure_class"]
                            
                            def __init__(self, secure_class):
                                self.secure_class = secure_class
                                
                            def __getattribute__(self, name):
                                secure_class = object.__getattribute__(self, "secure_class")
                                get_private = object.__getattribute__(secure_class, "get_private")
                                hidden_values = get_private("hidden_values")
                                obj_will_redirect = "redirect_access" in hidden_values and hidden_values["redirect_access"] == True
                                try:
                                    cls_will_redirect = type.__getattribute__(type(self), "redirect_access")
                                except AttributeError:
                                    cls_will_redirect = False
                                if obj_will_redirect:
                                    hidden_values["redirect_access"] = False                                          
                                if cls_will_redirect:
                                    type(self).own_redirect_access = False
                                try:                                    
                                    secure_class = object.__getattribute__(self, "secure_class")
                                    cls = secure_class.cls
                                    try:                                        
                                        bases = type.__getattribute__(cls, "__mro__")
                                        AccessEssentials = type.__getattribute__(cls, "__mro__")[-2]
                                        found = False
                                        if name in AccessEssentials.__dict__ and api_self.is_function(getattr(AccessEssentials, name)):
                                            value = getattr(AccessEssentials, name)
                                            found = True
                                        else:                                                                                                                                            
                                            for base2 in bases:                        
                                                try:
                                                    raw_base = type.__getattribute__(base2, "protected_gate")
                                                except AttributeError:
                                                    raw_base = base2                            
                                                else:
                                                    raw_base = raw_base.cls.own_all_hidden_values[type(raw_base.cls)]["cls"]
                                                try:                            
                                                    value = type.__getattribute__(raw_base, name)                            
                                                    type.__delattr__(raw_base, name)
                                                    found = True
                                                except AttributeError:                                                   
                                                    continue
                                                except TypeError:
                                                    pass
                                                else:
                                                    type.__setattr__(raw_base, name, value)                           
                                                    is_builtin_new = name == "_new_" and value == object.__new__
                                                    is_builtin_new2 = name == "__new__" and value == object.__new__
                                                    is_builtin = type(value) == types.WrapperDescriptorType
                                                    if is_builtin_new or is_builtin_new2 or is_builtin:
                                                        continue
                                                    break
                                        if not found:
                                            raise AttributeError(name)
                                    except AttributeError:
                                        value = object.__getattribute__(self, name)
                                    else:                                            
                                        def is_ro_method(self, name, value):
                                            """We have to duplicate this method for performance reasons"""
                                            AccessEssentials = api_self.AccessEssentials
                                            if hasattr(AccessEssentials, name):
                                                function = getattr(AccessEssentials, name)
                                                if api_self.is_function(value) and api_self.is_function(function) and value.__code__ == function.__code__:
                                                    return True
                                            return False

                                        value2 = value
                                        value = None
                                        cls = all_hidden_values[type(secure_class)]["cls"]
                                        index = 0
                                        wrapped_cls = cls
                                        while True:                                            
                                            try:                        
                                                value = getattr(cls, name)
                                            except PrivateError as e:
                                                e.caller_name = sys._getframe(1).f_code.co_name
                                                e.inherited = True
                                                raise
                                            except AttributeError:
                                                cls = wrapped_cls.__mro__[index]
                                                index += 1
                                                continue                                            
                                            if value is not value2:
                                                cls = wrapped_cls.__mro__[index]
                                                index += 1
                                            else:
                                                break

                                        is_raw_class = False
                                        try:
                                            protected_gate = type.__getattribute__(cls, "protected_gate")
                                            delattr(cls, "protected_gate")
                                        except AttributeError:
                                            has_own_attr = False
                                        else:
                                            setattr(cls, "protected_gate", protected_gate)
                                            has_own_attr = True                            
                                        if has_own_attr:
                                            cls = type.__getattribute__(cls, "protected_gate").cls
                                        else:
                                            if hasattr(cls, "secure_class"):
                                                cls = cls.secure_class
                                            else:
                                                is_raw_class = True
                                        if not is_raw_class:
                                            base = cls
                                            all_hidden_values2 = base.own_all_hidden_values
                                            wrapped_cls = all_hidden_values2[type(base)]["cls"]
                                            _privates_ = wrapped_cls._privates_                       
                                            base_protecteds = wrapped_cls.base_protecteds
                                            base_privates = wrapped_cls.base_privates
                                            check_caller = types.MethodType(all_hidden_values2[type(base)]["AccessEssentials2"].check_caller, base)
                                            is_subclass_method = types.MethodType(all_hidden_values2[type(base)]["AccessEssentials2"].is_subclass_method, base)
                                            _protecteds_ = wrapped_cls._protecteds_
                                            raise_PrivateError2 = all_hidden_values2[type(base)]["raise_PrivateError2"]
                                            raise_ProtectedError2 = all_hidden_values2[type(base)]["raise_ProtectedError2"]
                                            create_secure_method = all_hidden_values2[type(base)]["create_secure_method"]
                                            is_subclass_method2 = all_hidden_values2[type(base)]["is_subclass_method2"]
                                            InsecureRestrictor = all_hidden_values2[type(base)]["InsecureRestrictor"]
                                                
                                            public_names = ["_privates_",
                                                            "_protecteds_",
                                                            "_publics_",
                                                            "__bases__",
                                                            "__mro__",
                                                            "_bases",
                                                            "_mro",
                                                            "__dict__",
                                                            "base_publics",
                                                            "base_protecteds",
                                                            "base_privates",
                                                            "protected_bases",
                                                            "private_bases"]

                                            is_private = name in _privates_ or (not wrapped_cls.is_public(name) and not wrapped_cls.is_protected(name))                        
                                            authorized_caller = check_caller(all_hidden_values2, depth = 1, name = name)                       
                                            has_protected_access = authorized_caller or is_subclass_method(all_hidden_values2, depth = 1)                            
                                            ism, subclass = is_subclass_method2(all_hidden_values2, wrapped_cls, depth = 1)
                                            only_private = name in _privates_ and name not in _protecteds_
                                            only_private = only_private or name in base_privates
                                            if not only_private:
                                                orig_redirect_access = all_hidden_values2[type(base)]["redirect_access"]
                                                orig_own_redirect_access = type(base).own_redirect_access                                                
                                                all_hidden_values2[type(base)]["redirect_access"] = True
                                                type(base).own_redirect_access = True
                                                try:
                                                    if subclass is not None:
                                                        for base2 in subclass.__mro__:
                                                            if hasattr(base2, "base_privates") and name in base2.base_privates:
                                                                raise PrivateError(sys._getframe(1).f_code.co_name, name, base2.__name__, class_attr = True, inherited = True)
                                                finally:
                                                    all_hidden_values2[type(base)]["redirect_access"] = orig_redirect_access
                                                    type(base).own_redirect_access = orig_own_redirect_access
                                            
                                            inherited = False
                                            if not is_private and not wrapped_cls.is_public(name):
                                                is_private = name in base_protecteds
                                                inherited = True

                                            if is_private and name not in public_names and name not in _protecteds_ and not inherited and not authorized_caller:
                                                raise_PrivateError2(name, depth = 1)
                                            elif is_private and name not in public_names and not authorized_caller:
                                                raise_ProtectedError2(name, depth = 1)
                                            elif name in ["_privates_",
                                                          "_protecteds_",
                                                          "_publics_",
                                                          "base_publics",
                                                          "base_protecteds",
                                                          "base_privates",
                                                          "protected_bases",
                                                          "private_bases"]:
                                                value = list(value)
                                            elif name in ["__bases__", "__mro__", "_bases", "_mro"]:
                                                is_access_essentials = InsecureRestrictor.is_access_essentials
                                                value = api_self.get_secure_bases(wrapped_cls, is_access_essentials, value, for_subclass = has_protected_access)
                                            elif name == "mro":
                                                bases = wrapped_cls.__mro__
                                                is_access_essentials = InsecureRestrictor.is_access_essentials
                                                bases = api_self.get_secure_bases(wrapped_cls, is_access_essentials, bases, for_subclass = has_protected_access)
                                                def mro():
                                                    return list(bases)
                                                value = mro                            
                                            elif name == "__dict__":
                                                new_dict = dict(value)
                                                for key in value:
                                                    if key in _protecteds_:
                                                        new_dict[key] = ProtectedError("protected member")
                                                    elif key in _privates_:
                                                        new_dict[key] = PrivateError("private member")                                    
                                                value = new_dict
                                            elif is_ro_method(base, name, value):
                                                value = getattr(api_self.AccessEssentials, name)                                                                              
                                    return value
                                finally:
                                    if obj_will_redirect:
                                        hidden_values["redirect_access"] = True                                          
                                    if cls_will_redirect:
                                        type(self).own_redirect_access = True

                            def __str__(self):
                                secure_class = object.__getattribute__(self, "secure_class")
                                get_private = object.__getattribute__(secure_class, "get_private")                                
                                no_redirect2 = types.MethodType(api_self.AccessEssentials.no_redirect2, secure_class)
                                @no_redirect2(get_private("hidden_values"))  
                                def __str__(self):
                                    secure_class = object.__getattribute__(self, "secure_class")
                                    super = builtins.super
                                    return str(super(secure_class.cls, secure_class.cls))
                                    
                                return __str__(self)
                            
                        all_hidden_values[AccessEssentials]["auth_codes"].add(object.__getattribute__(super, "__getattribute__").__code__)                        
                        self.authorize(super)
                        return super(self)

                    return super(self)

                def raise_PrivateError2(self, name, depth = 3, inherited = False):
                    depth += 1
                    raise PrivateError(sys._getframe(depth).f_code.co_name, name, self.cls.__name__, class_attr = True, inherited = inherited)

                def raise_ProtectedError2(self, name, depth = 3):
                    depth += 1               
                    raise ProtectedError(sys._getframe(depth).f_code.co_name, name, self.cls.__name__, class_attr = True)                

                def is_ro_method(self, name, value):
                    if hasattr(super(), name):
                        function = getattr(super(), name)
                        if api_self.is_function(value) and api_self.is_function(function) and value.__code__ == function.__code__:
                            return True
                    return False

                def create_secure_method(self, method):
                    hidden_method = self.internal_get_hidden_value(self.all_hidden_values, method)
                    def secure_method(*args, **kwargs):
                        """wrap the method to prevent possible bypasses through its __self__ attribute"""
                        try:
                            return hidden_method.value(*args, **kwargs)
                        except AccessError as e:
                            e.caller_name = sys._getframe(1).f_code.co_name
                            raise                       
                    self.authorize(secure_method)
                    return secure_method

                def is_subclass_method2(self, all_hidden_values, cls, depth = 1):
                    def get_all_subclasses(cls):
                        """We have to duplicate this function for performance reasons"""
                        all_subclasses = []
                        for subclass in type.__getattribute__(cls, "__subclasses__")():
                            all_subclasses.append(subclass)
                            all_subclasses.extend(get_all_subclasses(subclass))
                        all_subclasses = list(set(all_subclasses))
                        return all_subclasses

                    def get_all_subclasses2(cls):
                        """We have to duplicate this function for performance reasons"""
                        all_subclasses = []
                        for subclass in cls._subclasses_:
                            all_subclasses.append(subclass)
                        all_subclasses = list(set(all_subclasses))
                        return all_subclasses
                    
                    def is_function(func):
                        """We have to duplicate this function for performance reasons"""
                        try:
                            code = object.__getattribute__(func, "__code__")
                        except AttributeError:
                            has_code = type(func) == types.MethodType
                        else:
                            has_code = True
                        if callable(func) and has_code and type(func.__code__) == types.CodeType:
                            return True
                        else:
                            return False
                        
                    depth += 1          
                    caller = sys._getframe(depth).f_code
                    subclasses = get_all_subclasses(cls)                  
                    for subclass in subclasses:
                        for member in subclass.__dict__.values():
                            if is_function(member) and member.__code__ == caller:
                                return True, subclass.cls.own_hidden_values["cls"]
                    subclasses = get_all_subclasses2(cls)                    
                    for subclass in subclasses:
                        try:
                            member = type.__getattribute__(subclass, caller.co_name)
                        except AttributeError:
                            pass
                        else:                           
                            if is_function(member) and type(member) != types.MethodType and member.__code__ == caller:                                
                                return True, subclass
                            try:
                                type.__getattribute__(subclass, "_new_")
                            except AttributeError:
                                pass
                            else:
                                member = subclass._new_
                                if is_function(member) and member.__code__ == caller:
                                    return True, subclass
                    return False, None                
                    
                def _getattribute_(self, name):
                    def no_redirect(self, all_hidden_values):
                        def factory(func):
                            def redirection_stopper(*args, **kwargs):
                                obj_will_redirect = "redirect_access" in all_hidden_values[type(self)] and all_hidden_values[type(self)]["redirect_access"] == True
                                try:
                                    cls_will_redirect = type.__getattribute__(type(self), "redirect_access")
                                except AttributeError:
                                    cls_will_redirect = False
                                if obj_will_redirect:
                                    all_hidden_values[type(self)]["redirect_access"] = False                                          
                                if cls_will_redirect:
                                    type(self).own_redirect_access = False
                                try:
                                    return func(*args, **kwargs)
                                finally:
                                    if obj_will_redirect:
                                        all_hidden_values[type(self)]["redirect_access"] = True                                          
                                    if cls_will_redirect:
                                        type(self).own_redirect_access = True
                            
                            caller = sys._getframe(1).f_code
                            for cls in all_hidden_values:
                                if caller in all_hidden_values[cls]["auth_codes"]:
                                    break
                            else:
                                raise ProtectedError(sys._getframe(1).f_code.co_name, "no_redirect", type(self).__name__)                                                                                                                  
                            redirection_stopper.func = func
                            all_hidden_values[cls]["auth_codes"].add(func.__code__)
                            all_hidden_values[cls]["auth_codes"].add(redirection_stopper.__code__)
                            return redirection_stopper                    
                        return factory
                    
                    get_private = object.__getattribute__(self, "get_private")
                    no_redirect = types.MethodType(no_redirect, self)
                    all_hidden_values = get_private("all_hidden_values")
                    @no_redirect(all_hidden_values)
                    def _getattribute_(self, name):
                        def is_function(func):
                            """We have to duplicate this method for performance reasons"""
                            try:
                                code = object.__getattribute__(func, "__code__")
                            except AttributeError:
                                has_code = type(func) == types.MethodType
                            else:
                                has_code = True
                            if callable(func) and has_code and type(func.__code__) == types.CodeType:
                                return True
                            else:
                                return False
                        
                        def is_ro_method(self, name, value):
                            """We have to duplicate this method for performance reasons"""
                            if hasattr(super(), name):
                                function = getattr(super(), name)
                                if is_function(value) and is_function(function) and value.__code__ == function.__code__:
                                    return True
                            return False
                        
                        wrapped_cls = all_hidden_values[type(self)]["cls"]
                        _privates_ = wrapped_cls._privates_                       
                        base_protecteds = wrapped_cls.base_protecteds
                        base_privates = wrapped_cls.base_privates
                        check_caller = types.MethodType(all_hidden_values[type(self)]["AccessEssentials2"].check_caller, self)
                        is_subclass_method = types.MethodType(all_hidden_values[type(self)]["AccessEssentials2"].is_subclass_method, self)
                        _protecteds_ = wrapped_cls._protecteds_
                        raise_PrivateError2 = all_hidden_values[type(self)]["raise_PrivateError2"]
                        raise_ProtectedError2 = all_hidden_values[type(self)]["raise_ProtectedError2"]
                        create_secure_method = all_hidden_values[type(self)]["create_secure_method"]
                        is_subclass_method2 = all_hidden_values[type(self)]["is_subclass_method2"]
                        InsecureRestrictor = all_hidden_values[type(self)]["InsecureRestrictor"]
                        
                        try:                        
                            value = getattr(wrapped_cls, name)
                        except PrivateError as e:
                            e.caller_name = sys._getframe(5).f_code.co_name
                            e.inherited = True
                            raise
                            
                        public_names = ["_privates_",
                                        "_protecteds_",
                                        "_publics_",
                                        "__bases__",
                                        "__mro__",
                                        "_bases",
                                        "_mro",
                                        "__dict__",
                                        "base_publics",
                                        "base_protecteds",
                                        "base_privates",
                                        "protected_bases",
                                        "private_bases"]
                        is_private = name in _privates_ or (not wrapped_cls.is_public(name) and not wrapped_cls.is_protected(name))                        
                        authorized_caller = check_caller(all_hidden_values, depth = 5, name = name)
                        has_protected_access = authorized_caller or is_subclass_method(all_hidden_values, depth = 5)                            
                        ism, subclass = is_subclass_method2(all_hidden_values, wrapped_cls, depth = 5)
                        only_private = name in _privates_ and name not in _protecteds_
                        only_private = only_private or name in base_privates
                        if not only_private:
                            all_hidden_values[type(self)]["redirect_access"] = True
                            type(self).own_redirect_access = True
                            try:
                                if subclass is not None:
                                    for base in subclass.__mro__:
                                        if hasattr(base, "base_privates") and name in base.base_privates:
                                            raise PrivateError(sys._getframe(5).f_code.co_name, name, base.__name__, class_attr = True, inherited = True)
                            finally:
                                all_hidden_values[type(self)]["redirect_access"] = False
                                type(self).own_redirect_access = False

                        inherited = False
                        if not is_private and not wrapped_cls.is_public(name):
                            is_private = name in base_protecteds
                            inherited = True

                        if is_private and name not in public_names and name not in _protecteds_ and not inherited and not authorized_caller:
                            raise_PrivateError2(name, depth = 5)
                        elif is_private and name not in public_names and not authorized_caller:
                            raise_ProtectedError2(name, depth = 5)
                        elif name in ["_privates_",
                                      "_protecteds_",
                                      "_publics_",
                                      "base_publics",
                                      "base_protecteds",
                                      "base_privates",
                                      "protected_bases",
                                      "private_bases"]:
                            value = list(value)
                        elif name in ["__bases__", "__mro__", "_bases", "_mro"]:
                            is_access_essentials = InsecureRestrictor.is_access_essentials
                            value = api_self.get_secure_bases(wrapped_cls, is_access_essentials, value, for_subclass = has_protected_access)
                        elif name == "mro":
                            bases = wrapped_cls.__mro__
                            is_access_essentials = InsecureRestrictor.is_access_essentials
                            bases = api_self.get_secure_bases(wrapped_cls, is_access_essentials, bases, for_subclass = has_protected_access)
                            def mro():
                                return list(bases)
                            value = mro                            
                        elif name == "__dict__":
                            new_dict = dict(value)
                            for key in value:
                                if key in _protecteds_:
                                    new_dict[key] = ProtectedError("protected member")
                                elif key in _privates_:
                                    new_dict[key] = PrivateError("private member")                                    
                            value = new_dict
                        elif is_ro_method(self, name, value):
                            value = getattr(api_self.AccessEssentials, name)
                        return value
                    
                    return _getattribute_(self, name)

                def control_access(self, name):                    
                    if name in ["get_private",
                                "__getattribute__",
                                "__setattr__",
                                "__delattr__"]:
                        raise PrivateError(f"Modifying {name} is disallowed")                    
                    all_hidden_values = self.own_all_hidden_values
                    check_caller = types.MethodType(all_hidden_values[type(self)]["AccessEssentials2"].check_caller, self)
                    is_meta_method = types.MethodType(all_hidden_values[type(self)]["AccessEssentials2"].is_meta_method, self)                    
                    authorized_caller = check_caller(all_hidden_values, depth = 6, name = name)
                    try:
                        value = getattr(self.cls, name)                        
                    except PrivateError:
                        defined = False
                    except AttributeError:
                        defined = False
                    else:
                        defined = True
                    if name in self.cls._privates_ and name not in self.cls._protecteds_ and not authorized_caller:
                        self.raise_PrivateError2(name, depth = 6)
                    elif name in self.cls._privates_ and not authorized_caller:
                        self.raise_ProtectedError2(name, depth = 6)
                    elif defined and self.is_ro_method(name, value):
                        raise PrivateError("methods inherited from AccessEssentials are read only")
                    if name not in self.cls._privates_ and name not in self.cls._publics_:
                        if api_self.default.__code__ == api_self.private.__code__:
                            self.cls.set_class_private("temp", None)
                            authorized_caller = check_caller(all_hidden_values, depth = 6, name = "temp")
                            delattr(self.cls, "temp")
                            if not authorized_caller:
                                self.raise_PrivateError2(name, depth = 6)
                        elif api_self.default.__code__ == api_self.protected.__code__:
                            self.cls.set_class_protected("temp", None)
                            authorized_caller = check_caller(all_hidden_values, depth = 6, name = "temp")
                            delattr(self.cls, "temp")
                            if not authorized_caller:
                                self.raise_ProtectedError2(name, depth = 6)
                    
                def _setattr_(self, name, value):
                    get_private = object.__getattribute__(self, "get_private")                    
                    no_redirect = types.MethodType(api_self.AccessEssentials.no_redirect, self)
                    @no_redirect(get_private("all_hidden_values"))
                    def _setattr_(self, name, value):
                        self.control_access(name)                       
                        if api_self.is_function(value):
                            untrusted_func = value
                            def trusted_method(itself, *args, **kwargs):
                                self = object.__getattribute__(itself, "_self_")
                                del itself # if we don't delete it, untrusted_func can look at the call stack and obtain the raw object
                                return untrusted_func(self, *args, **kwargs)
                            #value = trusted_method
                        setattr(self.cls, name, value)
                        
                    _setattr_(self, name, value)                        

                def _delattr_(self, name):
                    get_private = object.__getattribute__(self, "get_private")                    
                    no_redirect = types.MethodType(api_self.AccessEssentials.no_redirect, self)
                    @no_redirect(get_private("all_hidden_values"))
                    def _delattr_(self, name):
                        self.control_access(name)
                        delattr(self.cls, name)
                    _delattr_(self, name)

            return SecureClass                


        @property
        def SecureInstance(api_self):
            class SecureInstance(metaclass = api_self.InsecureRestrictor):
                class_id = "access_modifiers.SecureInstance"
                
                def __init__(self, inst):
                    get_private = object.__getattribute__(self, "get_private")                    
                    no_redirect2 = types.MethodType(api_self.AccessEssentials.no_redirect2, self)
                    hidden_values = get_private("hidden_values")

                    obj_will_redirect = "redirect_access" in get_private("hidden_values") and get_private("hidden_values")["redirect_access"] == True
                    try:
                        cls_will_redirect = type.__getattribute__(type(self), "redirect_access")
                    except AttributeError:
                        cls_will_redirect = False
                    if obj_will_redirect:
                        get_private("hidden_values")["redirect_access"] = False                                          
                    if cls_will_redirect:
                        type(self).own_redirect_access = False
                    try:
                        self.private.inst = inst
                        self.private.raise_PrivateError2 = self.raise_PrivateError2
                        self.private.raise_ProtectedError2 = self.raise_ProtectedError2
                        self.private.create_secure_method = self.create_secure_method
                        self.authorize(api_self.InsecureRestrictor.modify_attr)
                        object.__setattr__(inst, "_self_", self)
                        if not hasattr(type(inst), "class_id") or type(inst).class_id != "access_modifiers.SecureApi":
                            get_private("hidden_values")["redirect_access"] = True
                            try:
                                all_hidden_values = inst.all_hidden_values
                                AccessEssentials = list(all_hidden_values.keys())[-1]                                
                                set_private = inst.set_private
                                set_protected = inst.set_protected
                                set_public = inst.set_public
                                get_private("hidden_values")["redirect_access"] = False
                            except AttributeError:
                                pass
                            else:
                                if type(set_private) == types.MethodType:
                                    wrapped_set_private = self.create_secure_method(set_private)
                                    wrapped_set_protected = self.create_secure_method(set_protected)
                                    wrapped_set_public = self.create_secure_method(set_public)
                                else:
                                    wrapped_set_private = set_private
                                    wrapped_set_protected = set_protected
                                    wrapped_set_public = set_public
                                for cls in all_hidden_values:
                                    if wrapped_set_private.__code__ in all_hidden_values[cls]["auth_codes"]:
                                        all_hidden_values[cls]["auth_codes"].remove(wrapped_set_private.__code__)
                                    if wrapped_set_protected.__code__ in all_hidden_values[cls]["auth_codes"]:
                                        all_hidden_values[cls]["auth_codes"].remove(wrapped_set_protected.__code__)
                                    if wrapped_set_public.__code__ in all_hidden_values[cls]["auth_codes"]:
                                        all_hidden_values[cls]["auth_codes"].remove(wrapped_set_public.__code__)
                                all_hidden_values[AccessEssentials]["auth_codes"].add(wrapped_set_private.__code__)
                                all_hidden_values[AccessEssentials]["auth_codes"].add(wrapped_set_protected.__code__)
                                all_hidden_values[AccessEssentials]["auth_codes"].add(wrapped_set_public.__code__)
                                get_private("hidden_values")["redirect_access"] = True
                                for cls in all_hidden_values:
                                    if cls == AccessEssentials or cls in AccessEssentials._subclasses_:
                                        def __setattr__(self, name, value):
                                            setter = object.__getattribute__(self, "setter")
                                            setter(name, value, depth = 2)                                        
                                        set_private_modifier = api_self.Modifier(wrapped_set_private)
                                        set_protected_modifier = api_self.Modifier(wrapped_set_protected)
                                        set_public_modifier = api_self.Modifier(wrapped_set_public)
                                        type(set_private_modifier).__setattr__ = __setattr__
                                        type(set_protected_modifier).__setattr__ = __setattr__
                                        type(set_public_modifier).__setattr__ = __setattr__
                                        set_private("private", set_private_modifier, cls = cls) 
                                        set_private("protected", set_protected_modifier, cls = cls) 
                                        set_private("public", set_public_modifier, cls = cls)
                                get_private("hidden_values")["redirect_access"] = False
                    finally:
                        if obj_will_redirect:
                            get_private("hidden_values")["redirect_access"] = True                                          
                        if cls_will_redirect:
                            type(self).own_redirect_access = True                            

                def super(self):
                    get_private = object.__getattribute__(self, "get_private")                    
                    no_redirect2 = types.MethodType(api_self.AccessEssentials.no_redirect2, self)
                    @no_redirect2(get_private("hidden_values"))                    
                    def super(self):
                        class super:
                            __slots__ = ["secure_instance"]
                            
                            def __init__(self, secure_instance):
                                self.secure_instance = secure_instance
                                
                            def __getattribute__(self, name):
                                secure_instance = object.__getattribute__(self, "secure_instance")
                                get_private = object.__getattribute__(secure_instance, "get_private")
                                hidden_values = get_private("hidden_values")
                                obj_will_redirect = "redirect_access" in hidden_values and hidden_values["redirect_access"] == True
                                try:
                                    cls_will_redirect = type.__getattribute__(type(self), "redirect_access")
                                except AttributeError:
                                    cls_will_redirect = False
                                if obj_will_redirect:
                                    hidden_values["redirect_access"] = False                                          
                                if cls_will_redirect:
                                    type(self).own_redirect_access = False
                                try:
                                    secure_instance = object.__getattribute__(self, "secure_instance")
                                    caller = sys._getframe(1).f_code
                                    bases = list(type(secure_instance.inst).__mro__)
                                    bases.insert(0, type(secure_instance.inst))
                                    bases = tuple(bases)
                                    broken = False
                                    for base in bases:                                        
                                        try:
                                            protected_gate = type.__getattribute__(base, "protected_gate")
                                            delattr(base, "protected_gate")
                                        except AttributeError:
                                            has_own_attr = False
                                        else:
                                            setattr(base, "protected_gate", protected_gate)
                                            has_own_attr = True                            
                                        if has_own_attr:
                                            base = type.__getattribute__(base, "protected_gate").cls
                                        if hasattr(base, "static_dict"):
                                            dct = base.static_dict
                                        else:
                                            dct = base.__dict__
                                        for member_name in dct:
                                            member = dct[member_name]
                                            if api_self.is_function(member) and member.__code__ == caller:
                                                if isinstance(base, type):
                                                    cls = base
                                                else:
                                                    cls = base.own_all_hidden_values[type(base)]["cls"]
                                                broken = True
                                                break
                                        if broken:
                                            break
                                    else:                                    
                                        cls = type(secure_instance.inst)                                                                   
                                    try:
                                        bases = type.__getattribute__(cls, "__mro__")
                                        AccessEssentials = type.__getattribute__(cls, "__mro__")[-2]
                                        found = False
                                        if name in AccessEssentials.__dict__ and api_self.is_function(getattr(AccessEssentials, name)):
                                            value = getattr(AccessEssentials, name)
                                            found = True
                                        else:                                                                                                                                            
                                            for base2 in bases:                        
                                                try:
                                                    raw_base = type.__getattribute__(base2, "protected_gate")
                                                except AttributeError:
                                                    raw_base = base2                            
                                                else:
                                                    raw_base = raw_base.cls.own_all_hidden_values[type(raw_base.cls)]["cls"]
                                                try:                            
                                                    value = type.__getattribute__(raw_base, name)                            
                                                    type.__delattr__(raw_base, name)
                                                    found = True
                                                except AttributeError:                                                   
                                                    continue
                                                except TypeError:
                                                    pass
                                                else:
                                                    type.__setattr__(raw_base, name, value)                           
                                                    is_builtin_new = name == "_new_" and value == object.__new__
                                                    is_builtin_new2 = name == "__new__" and value == object.__new__
                                                    is_builtin = type(value) == types.WrapperDescriptorType
                                                    if is_builtin_new or is_builtin_new2 or is_builtin:
                                                        continue
                                                    break
                                        if not found:
                                            raise AttributeError(name)
                                    except AttributeError:
                                        value = object.__getattribute__(self, name)
                                    else:                                            
                                        def is_ro_method(self, name, value):
                                            """We have to duplicate this method for performance reasons"""
                                            AccessEssentials = api_self.AccessEssentials
                                            if hasattr(AccessEssentials, name):
                                                function = getattr(AccessEssentials, name)
                                                if api_self.is_function(value) and api_self.is_function(function) and value.__code__ == function.__code__:
                                                    return True
                                            return False

                                        value2 = value
                                        value = None
                                        index = 0
                                        wrapped_cls = cls
                                        while True:                                            
                                            try:                        
                                                value = getattr(cls, name)
                                            except PrivateError as e:
                                                e.caller_name = sys._getframe(1).f_code.co_name
                                                e.inherited = True
                                                e.class_attr = False
                                                raise
                                            except AttributeError:
                                                cls = wrapped_cls.__mro__[index]
                                                index += 1
                                                continue
                                            if value is not value2:
                                                cls = wrapped_cls.__mro__[index]
                                                index += 1
                                            else:
                                                break

                                        is_raw_class = False
                                        try:
                                            protected_gate = type.__getattribute__(cls, "protected_gate")
                                            delattr(cls, "protected_gate")
                                        except AttributeError:
                                            has_own_attr = False
                                        else:
                                            setattr(cls, "protected_gate", protected_gate)
                                            has_own_attr = True                            
                                        if has_own_attr:
                                            cls = type.__getattribute__(cls, "protected_gate").cls
                                        else:
                                            if hasattr(cls, "secure_class"):
                                                cls = cls.secure_class
                                            else:
                                                is_raw_class = True
                                        if not is_raw_class:
                                            base = cls
                                            all_hidden_values2 = base.own_all_hidden_values
                                            wrapped_cls = all_hidden_values2[type(base)]["cls"]
                                            _privates_ = wrapped_cls._privates_                       
                                            base_protecteds = wrapped_cls.base_protecteds
                                            base_privates = wrapped_cls.base_privates
                                            check_caller = types.MethodType(all_hidden_values2[type(base)]["AccessEssentials2"].check_caller, base)
                                            is_subclass_method = types.MethodType(all_hidden_values2[type(base)]["AccessEssentials2"].is_subclass_method, base)
                                            _protecteds_ = wrapped_cls._protecteds_
                                            raise_PrivateError2 = all_hidden_values2[type(base)]["raise_PrivateError2"]
                                            raise_ProtectedError2 = all_hidden_values2[type(base)]["raise_ProtectedError2"]
                                            create_secure_method = all_hidden_values2[type(base)]["create_secure_method"]
                                            is_subclass_method2 = all_hidden_values2[type(base)]["is_subclass_method2"]
                                            InsecureRestrictor = all_hidden_values2[type(base)]["InsecureRestrictor"]
                                                
                                            public_names = ["_privates_",
                                                            "_protecteds_",
                                                            "_publics_",
                                                            "__bases__",
                                                            "__mro__",
                                                            "_bases",
                                                            "_mro",
                                                            "__dict__",
                                                            "base_publics",
                                                            "base_protecteds",
                                                            "base_privates",
                                                            "protected_bases",
                                                            "private_bases"]

                                            is_private = name in _privates_ or (not wrapped_cls.is_public(name) and not wrapped_cls.is_protected(name))                        
                                            authorized_caller = check_caller(all_hidden_values2, depth = 1, name = name)                       
                                            has_protected_access = authorized_caller or is_subclass_method(all_hidden_values2, depth = 1)                            
                                            ism, subclass = is_subclass_method2(all_hidden_values2, wrapped_cls, depth = 1)
                                            only_private = name in _privates_ and name not in _protecteds_
                                            only_private = only_private or name in base_privates
                                            if not only_private:
                                                orig_redirect_access = all_hidden_values2[type(base)]["redirect_access"]
                                                orig_own_redirect_access = type(base).own_redirect_access                                                                                                
                                                all_hidden_values2[type(base)]["redirect_access"] = True
                                                type(base).own_redirect_access = True
                                                try:
                                                    if subclass is not None:
                                                        for base2 in subclass.__mro__:
                                                            if hasattr(base2, "base_privates") and name in base2.base_privates:
                                                                raise PrivateError(sys._getframe(1).f_code.co_name, name, base2.__name__, class_attr = True, inherited = True)
                                                finally:
                                                    all_hidden_values2[type(base)]["redirect_access"] = orig_redirect_access
                                                    type(base).own_redirect_access = orig_own_redirect_access
                                            
                                            inherited = False
                                            if not is_private and not wrapped_cls.is_public(name):
                                                is_private = name in base_protecteds
                                                inherited = True

                                            if is_private and name not in public_names and name not in _protecteds_ and not inherited and not authorized_caller:
                                                raise PrivateError(sys._getframe(1).f_code.co_name, name, wrapped_cls.__name__)
                                            elif is_private and name not in public_names and not authorized_caller:
                                                raise ProtectedError(sys._getframe(1).f_code.co_name, name, wrapped_cls.__name__)
                                            elif name in ["_privates_",
                                                          "_protecteds_",
                                                          "_publics_",
                                                          "base_publics",
                                                          "base_protecteds",
                                                          "base_privates",
                                                          "protected_bases",
                                                          "private_bases"]:
                                                value = list(value)
                                            elif name in ["__bases__", "__mro__", "_bases", "_mro"]:
                                                is_access_essentials = InsecureRestrictor.is_access_essentials
                                                value = api_self.get_secure_bases(wrapped_cls, is_access_essentials, value, for_subclass = has_protected_access)
                                            elif name == "mro":
                                                bases = wrapped_cls.__mro__
                                                is_access_essentials = InsecureRestrictor.is_access_essentials
                                                bases = api_self.get_secure_bases(wrapped_cls, is_access_essentials, bases, for_subclass = has_protected_access)
                                                def mro():
                                                    return list(bases)
                                                value = mro                            
                                            elif name == "__dict__":
                                                new_dict = dict(value)
                                                for key in value:
                                                    if key in _protecteds_:
                                                        new_dict[key] = ProtectedError("protected member")
                                                    elif key in _privates_:
                                                        new_dict[key] = PrivateError("private member")                                    
                                                value = new_dict
                                            elif is_ro_method(base, name, value):
                                                value = getattr(api_self.AccessEssentials, name)                                                                             
                                    if api_self.is_function(value):
                                        value = types.MethodType(value, secure_instance.inst)
                                        value = secure_instance.create_secure_method(value)
                                    return value
                                finally:
                                    if obj_will_redirect:
                                        hidden_values["redirect_access"] = True                                          
                                    if cls_will_redirect:
                                        type(self).own_redirect_access = True                                                    

                            def __str__(self):
                                secure_instance = object.__getattribute__(self, "secure_instance")
                                get_private = object.__getattribute__(secure_instance, "get_private")                                
                                no_redirect2 = types.MethodType(api_self.AccessEssentials.no_redirect2, secure_instance)
                                @no_redirect2(get_private("hidden_values"))                    
                                def __str__(self):
                                    secure_instance = object.__getattribute__(self, "secure_instance")
                                    super = builtins.super
                                    return str(super(type(secure_instance.inst), secure_instance.inst))
                                    
                                return __str__(self)

                        self.authorize(super)
                        return super(self)

                    return super(self)                    

                def raise_PrivateError2(self, name, depth = 3, inherited = False):
                    depth += 1
                    raise PrivateError(sys._getframe(depth).f_code.co_name, name, type(self.inst).__name__, inherited = inherited)

                def raise_ProtectedError2(self, name, depth = 3):
                    depth += 1
                    raise ProtectedError(sys._getframe(depth).f_code.co_name, name, type(self.inst).__name__)

                def is_ro_method(self, name, value):
                    if hasattr(super(), name):
                        function = getattr(super(), name)
                        if api_self.is_function(value) and api_self.is_function(function) and value.__code__ == function.__code__:
                            return True
                    return False

                def create_secure_method(self, method):
                    all_hidden_values = self.all_hidden_values
                    AccessEssentials = list(all_hidden_values.keys())[-1]
                    caller = sys._getframe(4).f_code
                    method_name = method.__code__.co_name
                    if not self.is_ro_method(method_name, method) and method_name not in ["get_private",
                                                                                          "__getattribute__",
                                                                                          "__setattr__",
                                                                                          "__delattr__",
                                                                                          "_getattribute_",
                                                                                          "_setattr_",
                                                                                          "_delattr_"]:
                        if method.__self__ is self.inst:
                            method = method.__func__
                            method = types.MethodType(method, self)
                        return method                      
                    hidden_method = self.internal_get_hidden_value(all_hidden_values, method)
                    hidden_inst_all_hidden_values = self.internal_get_hidden_value(all_hidden_values, self.inst.own_all_hidden_values)
                    def secure_method(*args, **kwargs):
                        """wrap the method to prevent possible bypasses through its __self__ attribute"""
                        value = hidden_method.value(*args, **kwargs)
                        if type(value) == types.MethodType:
                            self.own_all_hidden_values[type(self)]["redirect_access"] = False
                            value = self.create_secure_method(value)
                            caller = sys._getframe(3).f_code
                            inst_all_hidden_values = hidden_inst_all_hidden_values.value
                            if hasattr(value, "is_secure_method") and value.is_secure_method == True:
                                for cls in inst_all_hidden_values:
                                    if caller in inst_all_hidden_values[cls]["auth_codes"]:
                                        inst_all_hidden_values[cls]["auth_codes"].discard(value.__code__)                                    
                                caller = sys._getframe(1).f_code
                                for cls in inst_all_hidden_values:
                                    if caller in inst_all_hidden_values[cls]["auth_codes"]:
                                        inst_all_hidden_values[cls]["auth_codes"].add(value.__code__)
                            self.own_all_hidden_values[type(self)]["redirect_access"] = True
                        return value
                    code2 = dill.loads(dill.dumps(secure_method.__code__))
                    secure_method.__code__ = code2
                    secure_method.is_secure_method = True
                    all_hidden_values[AccessEssentials]["auth_codes"].add(secure_method.__code__)
                    for cls in self.inst.own_all_hidden_values:
                        if caller in self.inst.own_all_hidden_values[cls]["auth_codes"]:
                            self.inst.own_all_hidden_values[cls]["auth_codes"].add(secure_method.__code__)                            
                    return secure_method
                    
                def _getattribute_(self, name):
                    get_private = object.__getattribute__(self, "get_private")
                    obj_will_redirect = "redirect_access" in get_private("hidden_values") and get_private("hidden_values")["redirect_access"] == True
                    try:
                        cls_will_redirect = type.__getattribute__(type(self), "redirect_access")
                    except AttributeError:
                        cls_will_redirect = False
                    if obj_will_redirect:
                        get_private("hidden_values")["redirect_access"] = False                                          
                    if cls_will_redirect:
                        type(self).own_redirect_access = False
                    AccessEssentials = list(get_private("all_hidden_values").keys())[-1]
                    get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value._getattribute_ = self._getattribute_
                    if hasattr(get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value, "inst_auth_codes"):
                        get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value.inst_auth_codes.add(get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value._getattribute_.__code__)
                    get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value.inst_all_hidden_values = get_private("hidden_values")["inst"].own_all_hidden_values
                    AccessEssentials2 = list(get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value.inst_all_hidden_values.keys())[-1]                    
                    get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value.inst_auth_codes = get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value.inst_all_hidden_values[AccessEssentials2]["auth_codes"]                    
                    caller = sys._getframe(3).f_code
                    for cls in get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value.inst_all_hidden_values:
                        if caller in get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value.inst_all_hidden_values[cls]["auth_codes"]:
                            get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value.inst_all_hidden_values[cls]["auth_codes"].add(get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value._getattribute_.__code__)
                            cls_found = True
                            break
                    else:
                        cls_found = False
                    get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value.inst_auth_codes.remove(get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value._getattribute_.__code__)
                    if "called" not in get_private("hidden_values"):
                        get_private("hidden_values")["called"] = True
                        get_private("hidden_values")["classes"] = [cls]
                        get_private("hidden_values")["duplicate_classes"] = []
                        this_is_starter = True
                    else:
                        this_is_starter = False
                        if cls in get_private("hidden_values")["classes"]:
                            get_private("hidden_values")["duplicate_classes"].append(cls)
                        get_private("hidden_values")["classes"].append(cls) 
                    try:
                        get_private("hidden_values")["redirect_access"] = True
                        if cls_will_redirect:
                            type(self).own_redirect_access = True
                        try:                            
                            value = getattr(get_private("hidden_values")["inst"], name)
                        except AccessError as e:                            
                            e.caller_name = sys._getframe(3).f_code.co_name
                            raise
                        finally:
                            get_private("hidden_values")["redirect_access"] = False
                        if type(value) == types.MethodType:
                            value = self.create_secure_method(value)
                        return value
                    finally:
                        if cls_found and cls not in get_private("hidden_values")["duplicate_classes"]:
                            get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value.inst_all_hidden_values[cls]["auth_codes"].discard(get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value._getattribute_.__code__)
                            get_private("hidden_values")["classes"].remove(cls)
                        elif cls_found:
                            get_private("hidden_values")["duplicate_classes"].remove(cls)
                            get_private("hidden_values")["classes"].remove(cls)
                        if this_is_starter:
                            get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value.inst_auth_codes.add(get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value._getattribute_.__code__)
                            del get_private("hidden_values")["called"]
                            del get_private("hidden_values")["classes"]
                            del get_private("hidden_values")["duplicate_classes"]
                        if obj_will_redirect:
                            get_private("hidden_values")["redirect_access"] = True                                          
                        if cls_will_redirect:
                            type(self).own_redirect_access = True                        
                

                def _setattr_(self, name, value):
                    get_private = object.__getattribute__(self, "get_private")
                    hidden_values = get_private("hidden_values")
                    obj_will_redirect = "redirect_access" in hidden_values and hidden_values["redirect_access"] == True
                    try:
                        cls_will_redirect = type.__getattribute__(type(self), "redirect_access")
                    except AttributeError:
                        cls_will_redirect = False
                    if obj_will_redirect:
                        hidden_values["redirect_access"] = False                                          
                    if cls_will_redirect:
                        type(self).own_redirect_access = False
                    AccessEssentials = list(get_private("all_hidden_values").keys())[-1]
                    AccessEssentials2 = list(get_private("hidden_values")["inst"].own_all_hidden_values.keys())[-1]                    
                    get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value.inst_auth_codes = get_private("hidden_values")["inst"].own_all_hidden_values[AccessEssentials2]["auth_codes"]
                    caller = sys._getframe(3).f_code
                    for cls in get_private("hidden_values")["inst"].own_all_hidden_values:
                        if caller in get_private("hidden_values")["inst"].own_all_hidden_values[cls]["auth_codes"]:
                            get_private("hidden_values")["inst"].own_all_hidden_values[cls]["auth_codes"].add(self._setattr_.__code__)
                            cls_found = True
                            break
                    else:
                        cls_found = False
                    get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value.inst_auth_codes.remove(self._setattr_.__code__)                                            
                    try:
                        get_private("hidden_values")["redirect_access"] = True
                        if cls_will_redirect:
                            type(self).own_redirect_access = True                        
                        try:                            
                            setattr(get_private("hidden_values")["inst"], name, value)
                        except PrivateError:
                            get_private("hidden_values")["redirect_access"] = False
                            self.raise_PrivateError2(name, depth = 3)
                        except ProtectedError:
                            get_private("hidden_values")["redirect_access"] = False
                            self.raise_ProtectedError2(name, depth = 3)
                        finally:
                            get_private("hidden_values")["redirect_access"] = False                            
                    finally:
                        get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value.inst_auth_codes.add(self._setattr_.__code__)
                        if cls_found:
                            get_private("hidden_values")["inst"].own_all_hidden_values[cls]["auth_codes"].remove(self._setattr_.__code__)                                                
                        if obj_will_redirect:
                            hidden_values["redirect_access"] = True                                          
                        if cls_will_redirect:
                            type(self).own_redirect_access = True
                            

                def _delattr_(self, name):
                    get_private = object.__getattribute__(self, "get_private")
                    hidden_values = get_private("hidden_values")                    
                    obj_will_redirect = "redirect_access" in hidden_values and hidden_values["redirect_access"] == True
                    try:
                        cls_will_redirect = type.__getattribute__(type(self), "redirect_access")
                    except AttributeError:
                        cls_will_redirect = False
                    if obj_will_redirect:
                        hidden_values["redirect_access"] = False                                          
                    if cls_will_redirect:
                        type(self).own_redirect_access = False
                    AccessEssentials = list(get_private("all_hidden_values").keys())[-1]
                    AccessEssentials2 = list(get_private("hidden_values")["inst"].own_all_hidden_values.keys())[-1]                    
                    get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value.inst_auth_codes = get_private("hidden_values")["inst"].own_all_hidden_values[AccessEssentials2]["auth_codes"]
                    caller = sys._getframe(3).f_code
                    for cls in get_private("hidden_values")["inst"].own_all_hidden_values:
                        if caller in get_private("hidden_values")["inst"].own_all_hidden_values[cls]["auth_codes"]:
                            get_private("hidden_values")["inst"].own_all_hidden_values[cls]["auth_codes"].add(self._delattr_.__code__)
                            cls_found = True
                            break
                    else:
                        cls_found = False                    
                    get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value.inst_auth_codes.remove(self._delattr_.__code__)                                                                    
                    try:
                        get_private("hidden_values")["redirect_access"] = True
                        if cls_will_redirect:
                            type(self).own_redirect_access = True                        
                        try:
                            delattr(get_private("hidden_values")["inst"], name)
                        except PrivateError:
                            get_private("hidden_values")["redirect_access"] = False
                            self.raise_PrivateError2(name, depth = 3)
                        except ProtectedError:
                            get_private("hidden_values")["redirect_access"] = False
                            self.raise_ProtectedError2(name, depth = 3)
                        finally:
                            get_private("hidden_values")["redirect_access"] = False                            
                    finally:
                        get_private("all_hidden_values")[AccessEssentials]["hidden_store"].value.inst_auth_codes.add(self._delattr_.__code__)
                        if cls_found:
                            get_private("hidden_values")["inst"].own_all_hidden_values[cls]["auth_codes"].remove(self._delattr_.__code__)                                                                        
                        if obj_will_redirect:
                            hidden_values["redirect_access"] = True                                          
                        if cls_will_redirect:
                            type(self).own_redirect_access = True                    
                   
            return SecureInstance

            
        @property
        def Restrictor(api_self):            
            class Restrictor(api_self.InsecureRestrictor):                    
                @classmethod
                def remove_base_leaks(metacls, obj):
                    cls = type(obj)
                    #cls._bases = metacls.remove_access_essentials(cls.__bases__)                                    
                    #cls._mro = metacls.remove_access_essentials(cls.__mro__)                    
                    
                def __new__(metacls, name, bases, dct):
                    new_class = super(metacls, metacls).__new__(metacls, name, bases, dct)
                    modifier_backup = api_self.default
                    api_self.set_default(api_self.public)                    
                    secure_class = api_self.SecureClass(new_class)
                    api_self.set_default(modifier_backup)
                    metacls.remove_base_leaks(secure_class)
                    return secure_class 

            return Restrictor


        @property
        def create_base(api_self):
            def create_base(name = "Restricted", metaclass = api_self.Restrictor):
                @classmethod
                def get_real_class(cls):
                    try:
                        cls = cls.own_hidden_values["cls"]
                    except AttributeError:
                        pass
                    return cls

                modifier_backup = api_self.default
                api_self.set_default(api_self.public)                    
                Base = metaclass(name, (), {"get_real_class": get_real_class})
                api_self.set_default(modifier_backup)
                Base = Base.get_real_class()                
                del Base.get_real_class                
                return Base

            return create_base

            
        @property
        def Restricted(api_self):
            return api_self.create_base()      
            

        @property
        def HalfRestricted(api_self):
            return api_self.create_base(name = "HalfRestricted", metaclass = api_self.InsecureRestrictor)


        @property
        def hook_meta_new(api_self):
            def hook_meta_new(meta_dct, default_bases, default_dct):
                default_bases = list(default_bases)
                original_new = meta_dct["__new__"].__func__
                def __new__(metacls, name, bases, dct):
                    bases = list(bases)
                    bases = bases + default_bases
                    bases = tuple(bases)
                    for default_name in default_dct:
                        if default_name not in dct:
                            dct[default_name] = []                        
                        dct[default_name].extend(default_dct[default_name])
                    return original_new(metacls, name, bases, dct)
                
                meta_dct["__new__"] = __new__

            return hook_meta_new


        @property
        def extract_values(api_self):
            def extract_values(bases, dct, member_group):                
                if member_group == "base_privates":
                    value_type = api_self.PrivateValue
                    base_group = "private_bases"
                elif member_group == "base_protecteds":
                    value_type = api_self.ProtectedValue
                    base_group = "protected_bases"
                else:
                    value_type = api_self.PublicValue                    
                new_bases = []                
                for base in bases:                    
                    both_has = hasattr(type(base), "class_id") and hasattr(value_type, "class_id")                    
                    if both_has and type(base).class_id == value_type.class_id:
                        base = base.value
                        if member_group == "base_privates" or member_group == "base_protecteds":
                            names = []
                            if hasattr(base, "_protecteds_"):
                                names.extend(base._protecteds_)
                            if hasattr(base, "base_protecteds"):
                                names.extend(base.base_protecteds)                            
                            if hasattr(base, "base_publics"):
                                bb_publics = list(base.base_publics)
                                try:
                                    base._new_
                                except AccessError:
                                    pass
                                else:
                                    if base._new_ == object.__new__ and "_new_" in bb_publics:
                                        bb_publics.remove("_new_")
                                        bb_publics.remove("__new__")
                                names.extend(bb_publics)
                            base_publics = list(base.__dict__.keys())
                            try:
                                hasattr(base, "_new_")
                            except AccessError:
                                pass
                            else:                            
                                if hasattr(base, "_new_") and base._new_ == object.__new__:
                                    base_publics.remove("_new_")
                                    base_publics.remove("__new__")
                            for name in list(base_publics):
                                if isinstance(base.__dict__[name], AccessError):
                                    base_publics.remove(name)
                            names.extend(base_publics)
                            if member_group == "base_privates":
                                for protected_name in api_self.AccessEssentials._protecteds_:
                                    while protected_name in names:                                      
                                        names.remove(protected_name)
                            for name in names:                        
                                dct[member_group].append(name)
                            dct[base_group].append(base)
                    new_bases.append(base)
                if member_group == "base_privates" or member_group == "base_protecteds":
                    dct[member_group] = list(set(dct[member_group]))
                return new_bases

            return extract_values
        

        @property
        def create_restrictor(api_self):
            def create_restrictor(*bases, insecure = False):
                default_dct = {"base_privates": [], "base_protecteds": [], "private_bases": [], "protected_bases": []}
                bases = api_self.extract_values(bases, default_dct, "base_privates")                
                bases = api_self.extract_values(bases, default_dct, "base_protecteds")
                bases = api_self.extract_values(bases, default_dct, "publics")
                modifier_backup = api_self.default
                api_self.set_default(api_self.public)                
                bases = api_self.make_real_bases(bases)
                api_self.set_default(modifier_backup)
                if not insecure:                    
                    Restrictor = api_self.Restrictor                
                    InsecureRestrictor = Restrictor.__bases__[0]
                    needed = InsecureRestrictor.get_needed_mbases(bases)
                    meta_bases = needed + list(InsecureRestrictor.__bases__)
                    meta_bases = tuple(meta_bases)
                    meta_dct = dict(InsecureRestrictor.__dict__)
                    InsecureRestrictor = type("InsecureRestrictor", meta_bases, meta_dct)
                    
                    needed = Restrictor.get_needed_mbases(bases)
                    meta_bases = [InsecureRestrictor] + needed
                    meta_bases = tuple(meta_bases)
                    meta_dct = dict(Restrictor.__dict__)
                    api_self.hook_meta_new(meta_dct, bases, default_dct)
                    Restrictor = type("Restrictor", meta_bases, meta_dct)                    
                    return Restrictor
                else:
                    InsecureRestrictor = api_self.InsecureRestrictor
                    needed = InsecureRestrictor.get_needed_mbases(bases)
                    meta_bases = needed + list(InsecureRestrictor.__bases__)
                    meta_bases = tuple(meta_bases)
                    meta_dct = dict(InsecureRestrictor.__dict__)
                    api_self.hook_meta_new(meta_dct, bases, default_dct)                   
                    InsecureRestrictor = type("InsecureRestrictor", meta_bases, meta_dct)
                    return InsecureRestrictor                    
                
            return create_restrictor

    return Api


raw_api = create_api()()
class SecureApi(metaclass = raw_api.Restrictor):
    """api represents the whole library. If you monkeypatch it, that means you are no longer using this library."""
    class_id = "access_modifiers.SecureApi"
    
    def create_secure_closure(self, func):
        """prevents access to raw api using functions' __closure__ attribute"""
        @property
        def secure_closure(api_self):
            return func(self)
        return secure_closure        
        
    def __init__(self):
        hidden_values = self.hidden_values
        hidden_values["redirect_access"] = False
        Api = create_api()
        create_secure_closure = self.create_secure_closure
        for member_name in Api.__dict__:
            member = getattr(Api, member_name)
            if isinstance(member, property):
                member = member.fget
                secure_closure = create_secure_closure(member)
                setattr(Api, member_name, secure_closure)                
            if not member_name.startswith("__"):
                self.set_private(member_name, member)                
                
        self.set_private("api", Api())
        hidden_values["redirect_access"] = True

    def _getattribute_(self, name):
        get_private = object.__getattribute__(self, "get_private")
        hidden_values = get_private("hidden_values")
        hidden_values["redirect_access"] = True
        try:
           get_private("api")
        except AttributeError:
            hidden_values["redirect_access"] = False
            getter = self.create_getattribute()
            value = getter(name)
        else:
            value = getattr(get_private("api"), name)
        return value

api = SecureApi()      
