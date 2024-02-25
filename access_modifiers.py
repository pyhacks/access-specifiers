import sys
import types


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
        
    def init2(self, caller_name, member_name, class_name, class_attr = False, inherited = False, private = True):
        self.recreate = True
        if private:
            self.modifier = "private"
        else:
            self.modifier = "protected"
        self.caller_name = caller_name
        self.member_name = member_name
        self.class_name = class_name
        self.base_name = class_name
        self.class_attr = class_attr
        self.inherited = inherited
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
        @property
        def is_same_dict(api_self): # TODO: only check functions
            def is_same_dict(dict1, dict2):                                    
                if dict1.keys() != dict2.keys():
                    return False                    
                for member_name, member in dict1.items():
                    if api_self.is_function(member):
                        func_name = member.__code__.co_name
                        try:                        
                            function = dict2[func_name]
                        except AttributeError:                                    
                            return False
                        if not api_self.is_function(function):                                        
                            return False
                        elif not member.__code__ == function.__code__:
                            return False
                    elif member != dict2[member_name]:
                        return False
                return True

            return is_same_dict


        @property
        def is_same_class(api_self):
            def is_same_class(cls1, cls2):
                return api_self.is_same_dict(cls1.__dict__, cls2.__dict__)

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
                if callable(func) and hasattr(func, "__code__") and type(func.__code__) == types.CodeType:
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
        def Modifier(api_self):
            class Modifier:
                def __init__(self, setter):
                    object.__setattr__(self, "setter", setter)
                    
                def __getattribute__(self, name):
                    raise RuntimeError("this is a modifier, not a namespace")

                def __setattr__(self, name, value):
                    setter = object.__getattribute__(self, "setter")
                    setter(name, value)

                def __delattr__(self, name):
                    raise RuntimeError("this is a modifier, not a namespace")
            return Modifier


        class PrivateModifier:
            pass


        class ProtectedModifier:
            pass


        class PublicModifier:
            pass


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
                blacklists = api_self.get_blacklists(cls, is_access_essentials, bases, for_subclass)
                bases = api_self.replace_base(bases, blacklists[0], "NotAccessEssentials")
                bases = api_self.replace_base(bases, blacklists[1], "PrivateBaseClass")
                bases = api_self.replace_base(bases, blacklists[2], "ProtectedBaseClass")
                if not for_subclass:
                    bases = api_self.close_gates(bases)                
                return bases

            return get_secure_bases


        @property
        def super(api_self):
            def super(obj_or_cls):
                if isinstance(obj_or_cls, type):                    
                    raise TypeError("This function can't be used inside the class. Use self.super() instead.")
                try:
                    public_super = object.__getattribute__(obj_or_cls, "public_super")
                except AttributeError:
                    public_super = obj_or_cls.public_super
                return public_super()

            return super

        
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
                _protecteds_ = ["get_methods",
                                "no_redirect",

                                # Must be protected to guarantee an exception is raised.
                                # Otherwise it could be monkeypatched to suppress and that could cause a bypass:
                                # if caller_is_not_authorized:
                                #     self.raise_PrivateError() # must break control flow
                                # return private_member
                                "raise_PrivateError",
                                "raise_ProtectedError",

                                "get_base_attr",                                                                  
                                "get_attr",
                                "super",
                                "get_member",
                                "is_subclass_method",
                                "search_bases",
                                "check_caller",
                                "authorize",
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

                _privates_ = ["Api",
                              "_getattribute_",
                              "_setattr_",
                              "_delattr_",
                              "_privates_",
                              "_protecteds_",
                              "redirect_access",
                              "static_dict",
                              "AccessEssentials",
                              "InsecureRestrictor",
                              "base_publics",
                              "base_protecteds"]

                base_publics = []
                base_protecteds = []
                
                def get_methods(self):
                    """Get all the methods of this object, including all the public and protected methods coming from its ancestors"""
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")
                    methods = {}
                    all_names = object.__dir__(self) + self._protecteds_ + self.base_publics + self.base_protecteds # don't trust self.__dir__
                    all_names = list(set(all_names))                    
                    is_function = api_self.is_function
                    for member_name in all_names:                        
                        try:
                            member = getattr(self, member_name)                            
                        except AttributeError:                
                            continue
                        except PrivateError:
                            continue                        
                        if is_function(member):                            
                            methods[member_name] = member.__code__
                    if "__init__" not in methods:
                        for base in type(self).__mro__:
                            member = base.__init__
                            if is_function(member):
                                methods["__init__"] = member.__code__
                                break
                    return methods

                def no_redirect(self, hidden_values):
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

                        hidden_values["auth_codes"].add(func.__code__)
                        hidden_values["auth_codes"].add(redirection_stopper.__code__)
                        return redirection_stopper                    
                    return factory                            
                            
                def raise_PrivateError(self, name, depth = 1):
                    depth += 1
                    raise PrivateError(sys._getframe(depth).f_code.co_name, name, type(self).__name__)

                def raise_ProtectedError(self, name, depth = 1):
                    depth += 1
                    raise ProtectedError(sys._getframe(depth).f_code.co_name, name, type(self).__name__)                

                def get_base_attr(self, name):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")                  
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
                        value = object.__getattribute__(self, name)
                    except AttributeError as e:
                        try:
                            value = AccessEssentials.get_base_attr(self, name)
                        except AttributeError:
                            raise e
                        except PrivateError as e:
                            e.caller_name = sys._getframe(1).f_code.co_name
                            raise
                    return value

                def super(self, obj_or_cls = None):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")
                    if obj_or_cls is None:
                        obj_or_cls = self                    
                    class super:
                        __slots__ = ["obj_or_cls"]

                        def __init__(self, obj_or_cls):
                            self.obj_or_cls = obj_or_cls
                            
                        def __getattribute__(self, name): # Duplication is deliberate. We need different code objects to prevent a bypass.
                            obj_or_cls = object.__getattribute__(self, "obj_or_cls")
                            try:
                                if not isinstance(obj_or_cls, type):
                                    value = obj_or_cls.get_base_attr(name)
                                else:
                                    value = obj_or_cls.get_unbound_base_attr(name)
                            except AttributeError:
                                value = object.__getattribute__(self, name)
                            except PrivateError as e:
                                pg = type.__getattribute__(obj_or_cls.last_class, "protected_gate")                                      
                                try:
                                    getattr(pg.cls, name)
                                except PrivateError as e:
                                    e.caller_name = sys._getframe(1).f_code.co_name
                                    if not isinstance(obj_or_cls, type):
                                        e.class_attr = False
                                    raise
                            return value

                        def __str__(self):
                            obj_or_cls = object.__getattribute__(self, "obj_or_cls")
                            super = __builtins__["super"]
                            if not isinstance(obj_or_cls, type):
                                return str(super(type(obj_or_cls), obj_or_cls))
                            else:
                                return str(super(obj_or_cls, obj_or_cls))

                    self.authorize(super.__getattribute__)
                    return super(obj_or_cls)

                def public_super(self, obj_or_cls = None):
                    if obj_or_cls is None:
                        obj_or_cls = self
                    super = type(self.super())
                    def __getattribute__(self, name): # Duplication is deliberate. We need different code objects to prevent a bypass.
                        obj_or_cls = object.__getattribute__(self, "obj_or_cls")
                        try:
                            if not isinstance(obj_or_cls, type):
                                value = obj_or_cls.get_base_attr(name)
                            else:
                                value = obj_or_cls.get_unbound_base_attr(name)
                        except AttributeError:
                            value = object.__getattribute__(self, name)
                        except AccessError as e:
                            if type(e) == ProtectedError:
                                raise ProtectedError("This function can't be used with this object. Use self.super() instead.")
                            pg = type.__getattribute__(obj_or_cls.last_class, "protected_gate")                                      
                            try:
                                getattr(pg.cls, name)
                            except PrivateError as e:
                                e.caller_name = sys._getframe(1).f_code.co_name
                                if not isinstance(obj_or_cls, type):
                                    e.class_attr = False                                
                                raise
                        return value                        
                    
                    super.__getattribute__ = __getattribute__
                    return super(obj_or_cls)

                def get_member(self, hidden_values, name):
                    if name in hidden_values:
                        return hidden_values[name]
                    elif hasattr(AccessEssentials, name):
                        func = getattr(AccessEssentials, name)
                        if api_self.is_function(func) and type(func) != types.MethodType:                            
                            return types.MethodType(func, self)
                    return object.__getattribute__(self, name)

                def is_subclass_method(self, depth = 1):
                    depth += 1          
                    caller = sys._getframe(depth).f_code                
                    subclasses = api_self.get_all_subclasses(type(self))
                    is_function = api_self.is_function                  
                    for subclass in subclasses:
                        for member in subclass.__dict__.values():
                            if is_function(member) and member.__code__ == caller:
                                return True                            
                    return False

                def search_bases(self, bases, caller, name):
                    """return True if caller is authorized by a base (not necessarily a base method)"""
                    for base in bases:
                        try:
                            pg = type.__getattribute__(base, "protected_gate")                            
                        except AttributeError:                            
                            continue # no need to repeat the work of get_methods()
                        hidden_values = pg.cls.own_hidden_values
                        if name not in pg.cls._privates_:
                            if self.search_bases(hidden_values["cls"].__bases__, caller, name):
                                return True
                            continue
                        if caller in hidden_values["auth_codes"]:
                            return True
                        elif self.search_bases(hidden_values["cls"].__bases__, caller, name):
                            return True                        
                    return False

                def check_caller(self, hidden_values, depth = 1, name = "hidden_values"):
                    """Go depth frames back in stack and check if the associated caller is authorized to access the name

                    Name is assumed to be either private or protected.
                    This function should not be called if the name is public.
                    Because even if it's public, it'll be treated as if it were private.
                    In that case, return value will probably be wrong."""
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
                        is_function = api_self.is_function                        
                        if is_function(value) and type(value) != types.MethodType:
                            value = types.MethodType(value, self)
                        elif type(value) == types.MethodType:
                            raise AttributeError(name)
                        return value
                    
                    depth += 1          
                    caller = sys._getframe(depth).f_code                        
                    if "_protecteds_" in hidden_values:
                        _protecteds_ = hidden_values["_protecteds_"]
                    else:
                        _protecteds_ = object.__getattribute__(self, "_protecteds_")
                    if "base_protecteds" in hidden_values:
                        base_protecteds = hidden_values["base_protecteds"]
                    else:
                        base_protecteds = object.__getattribute__(self, "base_protecteds")
                    is_protected = name in _protecteds_ or name in base_protecteds
                    inherited_private = False
                    if name not in hidden_values and name != "hidden_values":
                        try:
                            get_base_attr(name)
                        except AttributeError:
                            pass
                        except PrivateError:
                            inherited_private = True
                    if caller in hidden_values["auth_codes"] and not inherited_private:
                        return True
                    if "is_subclass_method" in hidden_values:
                        is_subclass_method = hidden_values["is_subclass_method"]
                    else:
                        is_subclass_method = types.MethodType(AccessEssentials.is_subclass_method, self)                   
                    if is_protected and is_subclass_method(depth = depth):                                                  
                        return True
                    if name not in hidden_values and name != "hidden_values":
                        if "search_bases" in hidden_values:
                            search_bases = hidden_values["search_bases"]
                        else:
                            search_bases = types.MethodType(AccessEssentials.search_bases, self)
                        bases = type.__getattribute__(type(self), "__bases__")
                        if search_bases(bases, caller, name):
                            return True
                    return False

                def call(self, func, *args, **kwargs):
                    """If func is authorized, call it by passing this (raw) object as the first argument"""
                    if api_self.SecureInstance(self).call.__code__ == func.__code__:
                        func = func.__closure__[0].cell_contents.value
                    if func.__code__ in self.auth_codes:
                        return func(self, *args, **kwargs)
                    else:
                        raise PrivateError(f"\"{func.__code__.co_name}\" is not authorized by the \"{type(self).__name__}\" object")
                        
                def authorize(self, func_or_cls): # Do we really need a deauthorize() function as well?
                    """Allow func_or_cls to access private/protected members of this object

                    This function acts like the "friend" keyword of c++.
                    Note that this function will not find and authorize the SecureInstance objects wrapping this object.
                    That means func_or_cls should use a raw object, not a SecureInstance object.
                    If you can't directly pass a raw object, call() function can do it for you."""
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")
                    get_private = object.__getattribute__(self, "get_private")
                    hidden_values = get_private("hidden_values")                    
                    if api_self.is_function(func_or_cls):
                        hidden_values["auth_codes"].add(func_or_cls.__code__)
                    else:
                        for name, member in func_or_cls.__dict__.items():
                            if isinstance(member, AccessError):
                                member = getattr(func_or_cls.own_hidden_values["cls"], name)
                            if api_self.is_function(member):
                                hidden_values["auth_codes"].add(member.__code__)
                    
                def get_hidden_value(self, hidden_values, value):
                    check_caller = self.check_caller
                    class CellProtector:
                        def __get__(self, instance, owner):
                            if check_caller(hidden_values) and type(instance) == HiddenValue:
                                return value
                            else:
                                raise PrivateError("__closure__ cell access is disallowed")
                 
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

                def create_get_private(self, hidden_values, enforce = True):
                    hidden_store = self.get_private("hidden_store")                                          
                    def get_private(self, name):
                        """Return the requested private/protected member if the caller is authorized to access it."""
                        def get_base_attr(hidden_values, name):
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
                            
                        def get_attr(hidden_values, name):
                            """static_dict check would cause infinite recursion, so we have to duplicate this function."""
                            try:
                                value = object.__getattribute__(self, name)
                            except AttributeError as e:
                                try:
                                    value = get_base_attr(hidden_values, name)
                                except AttributeError:
                                    raise e
                                except PrivateError as e:
                                    e.caller_name = sys._getframe(1).f_code.co_name
                                    raise
                            return value                                          

                        def force_get_attr(bases, name):
                            """We have to duplicate this function because it can't be a part of the library api.
                            Otherwise that would cause a loophole"""
                            for base in bases:
                                try:
                                    pg = type.__getattribute__(base, "protected_gate")                            
                                except AttributeError:                            
                                    continue
                                hidden_values = pg.cls.own_hidden_values
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
                                    elif type(value) == types.MethodType:
                                        continue
                                    return value                                    
                            raise AttributeError(name)                                          
                            
                        def search_bases(bases, caller, name):
                            """We have to duplicate this function because we can't trust hidden_values["search_bases"]
                            This function must be read only, not even private.
                            Otherwise derived classes could bypass private members of their bases.
                            There is no such thing as "read only" in python so we completely hide it this way."""
                            for base in bases:
                                try:
                                    pg = type.__getattribute__(base, "protected_gate")                            
                                except AttributeError:                            
                                    continue # no need to repeat the work of get_methods()
                                hidden_values = pg.cls.own_hidden_values
                                if caller in hidden_values["auth_codes"]:
                                    return True
                                elif search_bases(hidden_values["cls"].__bases__, caller, name):
                                    return True               
                            return False

                        def check_caller(hidden_values, depth = 1, name = "hidden_values"):
                            """We have to duplicate this function because we can't trust hidden_values["check_caller"]
                            This function must be read only, not even private.
                            Otherwise derived classes could bypass private members of their bases.
                            There is no such thing as "read only" in (pure) python so we completely hide it this way."""                            
                            depth += 1          
                            caller = sys._getframe(depth).f_code
                            if "_protecteds_" in hidden_values:
                                _protecteds_ = hidden_values["_protecteds_"]
                            else:
                                _protecteds_ = object.__getattribute__(self, "_protecteds_")
                            if "base_protecteds" in hidden_values:
                                base_protecteds = hidden_values["base_protecteds"]
                            else:
                                base_protecteds = object.__getattribute__(self, "base_protecteds")
                            is_protected = name in _protecteds_ or name in base_protecteds
                            inherited_private = False
                            if name not in hidden_values and name != "hidden_values":
                                try:
                                    get_base_attr(hidden_values, name)
                                except AttributeError:
                                    pass
                                except PrivateError:
                                    inherited_private = True
                            if caller in hidden_values["auth_codes"] and not inherited_private:
                                return True
                            if "is_subclass_method" in hidden_values:
                                is_subclass_method = hidden_values["is_subclass_method"]
                            else:
                                is_subclass_method = types.MethodType(AccessEssentials.is_subclass_method, self)                   
                            if is_protected and is_subclass_method(depth = depth):                                                  
                                return True                               
                            if search_bases(type(self).__bases__, caller, name):
                                return True
                            return False

                        def get_private(self, hidden_values, name):                            
                            authorized_caller = check_caller(hidden_values, depth = 2, name = name)

                            if name != "hidden_values":
                                try:
                                    value = hidden_values[name]
                                except KeyError:
                                    try:
                                        value = get_base_attr(hidden_values, name)
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
                            else:
                                value = hidden_values
                            if authorized_caller or enforce == False:              
                                return value
                            elif name in self._protecteds_ or name in self.base_protecteds:
                                self.raise_ProtectedError(name, depth = 2)
                            else:
                                self.raise_PrivateError(name, depth = 2)

                        hidden_values = hidden_store.value.hidden_values
                        hidden_values["auth_codes"].add(force_get_attr.__code__)
                        hidden_values["auth_codes"].add(search_bases.__code__)
                        hidden_values["auth_codes"].add(get_private.__code__)
                        
                        # unrolling no_redirect for performance reasons
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
                            return get_private(self, hidden_values, name)
                        finally:
                            if obj_will_redirect:
                                hidden_values["redirect_access"] = True                                          
                            if cls_will_redirect:
                                type(self).own_redirect_access = True

                    hidden_values["auth_codes"].add(get_private.__code__)
                    get_private(self, "hidden_values")
                    return get_private                    

                def create_getattribute(self, depth = 1, enforce = True):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")                    
                    get_private = object.__getattribute__(self, "get_private")
                    no_redirect = get_private("no_redirect")
                    hidden_values = get_private("hidden_values")
                    hidden_store = hidden_values["hidden_store"]
                    @no_redirect(hidden_values)                    
                    def create_getattribute(self, depth = 1, enforce = True):                    
                        depth += 4
                        def _getattribute_(self, name):
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
                                return value

                            def force_get_attr(bases, name):
                                """We have to duplicate this function because it can't be a part of the library api.
                                Otherwise that would cause a loophole"""
                                for base in bases:
                                    try:
                                        pg = type.__getattribute__(base, "protected_gate")                            
                                    except AttributeError:                            
                                        continue
                                    hidden_values = pg.cls.own_hidden_values
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
                                        elif type(value) == types.MethodType:
                                            continue
                                        return value                                    
                                raise AttributeError(name)
                            
                            def search_bases(bases, caller, name):
                                """We have to duplicate this function because we can't trust hidden_values["search_bases"]
                                This function must be read only, not even private.
                                Otherwise derived classes could bypass private members of their bases.
                                There is no such thing as "read only" in python so we completely hide it this way."""                            
                                for base in bases:
                                    try:
                                        pg = type.__getattribute__(base, "protected_gate")                            
                                    except AttributeError:                            
                                        continue # no need to repeat the work of get_methods()
                                    hidden_values = pg.cls.own_hidden_values
                                    if caller in hidden_values["auth_codes"]:
                                        return True
                                    elif search_bases(hidden_values["cls"].__bases__, caller, name):
                                        return True               
                                return False

                            def check_caller(hidden_values, depth = 1, name = "hidden_values"):
                                """We have to duplicate this function because we can't trust hidden_values["check_caller"]
                                This function must be read only, not even private.
                                Otherwise derived classes could bypass private members of their bases.
                                There is no such thing as "read only" in (pure) python so we completely hide it this way."""                            
                                depth += 1                                
                                caller = sys._getframe(depth).f_code
                                if "_protecteds_" in hidden_values:
                                    _protecteds_ = hidden_values["_protecteds_"]
                                else:
                                    _protecteds_ = object.__getattribute__(self, "_protecteds_")
                                if "base_protecteds" in hidden_values:
                                    base_protecteds = hidden_values["base_protecteds"]
                                else:
                                    base_protecteds = object.__getattribute__(self, "base_protecteds")
                                is_protected = name in _protecteds_ or name in base_protecteds
                                inherited_private = False
                                if name not in hidden_values and name != "hidden_values":
                                    try:
                                        get_base_attr(name)
                                    except AttributeError:
                                        pass
                                    except PrivateError:
                                        inherited_private = True
                                if caller in hidden_values["auth_codes"] and not inherited_private:
                                    return True
                                if "is_subclass_method" in hidden_values:
                                    is_subclass_method = hidden_values["is_subclass_method"]
                                else:
                                    is_subclass_method = types.MethodType(AccessEssentials.is_subclass_method, self)                   
                                if is_protected and is_subclass_method(depth = depth):                                                  
                                    return True
                                if search_bases(type(self).__bases__, caller, name):
                                    return True
                                return False
                                                        
                            hidden_values = hidden_store.value.hidden_values
                            hidden_values["auth_codes"].add(force_get_attr.__code__)
                            hidden_values["auth_codes"].add(search_bases.__code__)
                            def _getattribute_(self, name):
                                public_names = ["_privates_",
                                                "_protecteds_",
                                                "_class_",
                                                "__bases__",
                                                "__mro__",
                                                "_mro",
                                                "_bases",
                                                "base_publics",
                                                "base_protecteds"]
                                is_private = name in hidden_values or name == "hidden_values"
                                inherited = False
                                if not is_private:
                                    try:
                                        object.__getattribute__(self, name)
                                    except AttributeError:
                                        if "base_protecteds" in hidden_values:
                                            base_protecteds = hidden_values["base_protecteds"]
                                        else:
                                            base_protecteds = self.base_protecteds
                                        is_private = name in base_protecteds
                                        inherited = True
                                if "_protecteds_" in hidden_values:
                                    _protecteds_ = hidden_values["_protecteds_"]
                                else:
                                    _protecteds_ = object.__getattribute__(self, "_protecteds_")                                        
                                authorized_caller = check_caller(hidden_values, depth = depth, name = name)                                
                                if enforce and is_private and not authorized_caller and name not in public_names and name not in _protecteds_ and not inherited:
                                    hidden_values["raise_PrivateError"](name, depth)
                                elif enforce and is_private and not authorized_caller and name not in public_names:
                                    hidden_values["raise_ProtectedError"](name, depth)
                                elif is_private and not authorized_caller and name == "_class_":                                    
                                    value = get_attr("_class_")
                                elif is_private and not authorized_caller and name in ["base_publics", "base_protecteds", "_privates_", "_protecteds_"]:
                                    value = list(hidden_values[name])
                                elif is_private and not authorized_caller and name in ["__bases__", "__mro__", "_mro", "_bases"]:
                                    value = api_self.get_secure_bases(type(self), self.InsecureRestrictor.is_access_essentials, hidden_values[name])
                                elif name in hidden_values:
                                    value = hidden_values[name]
                                elif name == "hidden_values":
                                    value = hidden_values
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

                            # unrolling no_redirect for performance reasons
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
                                return _getattribute_(self, name)
                            finally:
                                if obj_will_redirect:
                                    hidden_values["redirect_access"] = True                                          
                                if cls_will_redirect:
                                    type(self).own_redirect_access = True

                        self.authorize(_getattribute_)
                        _getattribute_ = types.MethodType(_getattribute_, self)
                        return _getattribute_
                    
                    return create_getattribute(self, depth = depth, enforce = enforce)

                def create_setattr(self, depth = 1):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")                    
                    get_private = object.__getattribute__(self, "get_private")
                    no_redirect = get_private("no_redirect")
                    @no_redirect(get_private("hidden_values"))                    
                    def create_setattr(self, depth = 1):                    
                        depth += 5
                        def _setattr_(self, name, value):
                            get_private = object.__getattribute__(self, "get_private")
                            hidden_values = get_private("hidden_values")
                            no_redirect = get_private("no_redirect")
                            @no_redirect(hidden_values)
                            def _setattr_(self, name, value):
                                is_private = name in hidden_values or name == "hidden_values"
                                authorized_caller = AccessEssentials.check_caller(self, hidden_values, depth = depth, name = name)
                                if is_private and not authorized_caller and name not in self._protecteds_:
                                    self.raise_PrivateError(name, depth)
                                elif is_private and not authorized_caller:
                                    self.raise_ProtectedError(name, depth)
                                elif name in hidden_values:
                                    hidden_values[name] = value
                                elif name == "hidden_values":
                                    hidden_values.clear()
                                    hidden_values.update(value)
                                elif hasattr(self, name):                                
                                    object.__setattr__(self, name, value)
                                else:
                                    authorized_caller = AccessEssentials.check_caller(self, hidden_values, depth = depth, name = name)
                                    if not authorized_caller and api_self.default.__code__ == api_self.private.__code__:
                                        self.raise_PrivateError(name, depth)
                                    elif not authorized_caller and api_self.default.__code__ == api_self.protected.__code__:
                                        self.raise_ProtectedError(name, depth)
                                    elif api_self.default.__code__ == api_self.private.__code__:
                                        self.set_private(name, value)
                                    elif api_self.default.__code__ == api_self.protected.__code__:
                                        self.set_protected(name, value)
                                    else:
                                        object.__setattr__(self, name, value)
                                    
                            _setattr_(self, name, value)

                        self.authorize(_setattr_)
                        _setattr_ = types.MethodType(_setattr_, self)
                        return _setattr_
                    
                    return create_setattr(self, depth = depth)

                def create_delattr(self, depth = 1):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")                    
                    get_private = object.__getattribute__(self, "get_private")
                    no_redirect = get_private("no_redirect")
                    @no_redirect(get_private("hidden_values"))                    
                    def create_delattr(self, depth = 1):                    
                        depth += 5
                        def _delattr_(self, name):
                            get_private = object.__getattribute__(self, "get_private")
                            hidden_values = get_private("hidden_values")
                            no_redirect = get_private("no_redirect")
                            @no_redirect(hidden_values)
                            def _delattr_(self, name):
                                is_private = name in hidden_values or name == "hidden_values"
                                authorized_caller = AccessEssentials.check_caller(self, hidden_values, depth = depth, name = name)
                                if is_private and not authorized_caller and name not in self._protecteds_:
                                    self.raise_PrivateError(name, depth)
                                elif is_private and not authorized_caller:
                                    self.raise_ProtectedError(name, depth)                                    
                                object.__delattr__(self, name)                            
                                if name in hidden_values:
                                    del hidden_values[name]
                                elif name == "hidden_values":
                                    hidden_values.clear()
                            _delattr_(self, name)

                        self.authorize(_delattr_)
                        _delattr_ = types.MethodType(_delattr_, self)
                        return _delattr_
                    
                    return create_delattr(self, depth = depth)                
                
                def mask_public_face(self, hidden_values):
                    """Make interaction with private members more intuitive"""
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")                             
                    hidden_store = self.get_private("hidden_store")
                    
                    def check_caller(self, depth = 2, name = "hidden_values"):
                        depth += 1
                        return AccessEssentials.check_caller(self, hidden_values, depth = depth, name = name)

                    def own_raise_PrivateError(self, name, depth = 3):                        
                        depth += 1
                        if "raise_PrivateError" in hidden_values:
                            raise_PrivateError = hidden_values["raise_PrivateError"]
                        else:
                            raise_PrivateError = types.MethodType(AccessEssentials.raise_PrivateError, self)
                        if "no_redirect" in hidden_values:
                            no_redirect = hidden_values["no_redirect"]
                        else:
                            no_redirect = types.MethodType(AccessEssentials.no_redirect, self)
                        factory = no_redirect(hidden_values)
                        raise_PrivateError = factory(raise_PrivateError)
                        raise_PrivateError(name, depth)

                    default_getter = self.create_getattribute(depth = 0)
                    default_insecure_getter = self.create_getattribute(depth = 0, enforce = False)
                    def create_getter(default_getter):
                        def getter(self, name):                        
                            maybe_redirect = "redirect_access" in hidden_values and hidden_values["redirect_access"] == True
                            should_redirect = maybe_redirect and name != "__class__" and name != "own_hidden_values"
                            if should_redirect:
                                _getattribute_ = AccessEssentials.get_member(self, hidden_values, "_getattribute_")
                                value = _getattribute_(name)               
                                return value
                            elif name == "own_hidden_values":                            
                                if not check_caller(self):                                
                                    own_raise_PrivateError(self, name)
                                return hidden_values                
                            else:
                                return default_getter(name)
                        return getter

                    secure_getter = create_getter(default_getter)
                    insecure_getter = create_getter(default_insecure_getter)
                    self.authorize(secure_getter)
                    hidden_store.value.secure_getter = secure_getter
                    def __getattribute__(self, name):                            
                        secure_getter = hidden_store.value.secure_getter
                        return secure_getter(self, name)
                    
                    self.authorize(__getattribute__)
                    type(self).__getattribute__ = __getattribute__

                    default_setter = self.create_setattr(depth = 0)
                    def setter(self, name, value):
                        maybe_redirect = "redirect_access" in hidden_values and hidden_values["redirect_access"] == True
                        should_redirect = maybe_redirect and name != "__class__" and name != "own_hidden_values"
                        if should_redirect:
                            _setattr_ = AccessEssentials.get_member(self, hidden_values, "_setattr_")
                            _setattr_(name, value)
                        elif name == "own_hidden_values":
                            if not check_caller(self):
                                own_raise_PrivateError(self, name)
                            hidden_values.clear()
                            hidden_values.update(value)
                        else:
                            default_setter(name, value)
                            
                    self.authorize(setter)
                    hidden_store.value.setter = setter                    
                    def __setattr__(self, name, value):
                        setter = hidden_store.value.setter         
                        setter(self, name, value)
                    
                    self.authorize(__setattr__)  
                    type(self).__setattr__ = __setattr__

                    default_deleter = self.create_delattr(depth = 0)      
                    def deleter(self, name):
                        maybe_redirect = "redirect_access" in hidden_values and hidden_values["redirect_access"] == True
                        should_redirect = maybe_redirect and name != "__class__" and name != "own_hidden_values"
                        if should_redirect:
                            _delattr_ = AccessEssentials.get_member(self, hidden_values, "_delattr_")
                            _delattr_(name)                            
                        elif name == "own_hidden_values":
                            if not check_caller(self):
                                own_raise_PrivateError(self, name)                             
                            object.__delattr__(self, name)
                            hidden_values.clear()
                        else:
                            default_deleter(name)

                    self.authorize(deleter)       
                    hidden_store.value.deleter = deleter                    
                    def __delattr__(self, name):
                        deleter = hidden_store.value.deleter           
                        deleter(self, name)
                        
                    self.authorize(__delattr__)
                    type(self).__delattr__ = __delattr__
                            
                def set_private(self, name, value):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")                    
                    get_private = object.__getattribute__(self, "get_private")
                    hidden_values = get_private("hidden_values")
                    if name != "hidden_values":
                        hidden_values[name] = value
                    else:
                        value = dict(value)
                        hidden_values.clear()
                        hidden_values.update(value)
                    def set_private(self, name, value):
                        if "_privates_" in hidden_values:
                            _privates_ = hidden_values["_privates_"]
                        else:
                            _privates_ = object.__getattribute__(self, "_privates_")
                        if "_protecteds_" in hidden_values:
                            _protecteds_ = hidden_values["_protecteds_"]
                        else:
                            _protecteds_ = object.__getattribute__(self, "_protecteds_")
                        if "authorize" in hidden_values:
                            authorize = hidden_values["authorize"]
                        else:
                            authorize = types.MethodType(AccessEssentials.authorize, self)                        
                        if name != "hidden_values" and name not in _privates_:
                            _privates_.append(name)
                        elif name in _protecteds_:
                            _protecteds_.remove(name)
                        if api_self.is_function(value):
                            authorize(value)
                        try:
                            object.__setattr__(self, name, PrivateError("private member"))
                        except AttributeError:
                            pass

                    # unrolling no_redirect for performance reasons
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
                        return set_private(self, name, value)
                    finally:
                        if obj_will_redirect:
                            hidden_values["redirect_access"] = True                                          
                        if cls_will_redirect:
                            type(self).own_redirect_access = True         

                def set_protected(self, name, value):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")                  
                    get_private = object.__getattribute__(self, "get_private")
                    hidden_values = get_private("hidden_values")
                    no_redirect = get_private("no_redirect")
                    @no_redirect(hidden_values)
                    def set_protected(self, name, value):
                        if "set_private" in hidden_values:
                            set_private = hidden_values["set_private"]
                        else:
                            set_private = types.MethodType(AccessEssentials.set_private, self)
                        if "_protecteds_" in hidden_values:
                            _protecteds_ = hidden_values["_protecteds_"]
                        else:
                            _protecteds_ = object.__getattribute__(self, "_protecteds_")
                        set_private(name, value)
                        if name not in _protecteds_:
                            _protecteds_.append(name)
                        try:
                            object.__setattr__(self, name, ProtectedError("protected member"))                        
                        except AttributeError:
                            pass
                    set_protected(self, name, value)

                def set_public(self, name, value):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")                   
                    if hasattr(self, name):                        
                        delattr(self, name)                        
                        if name in self._privates_:
                            self._privates_.remove(name)                        
                        if name in self._protecteds_:
                            self._protecteds_.remove(name)                    
                    object.__setattr__(self, name, value)                       
                    
                def start_access_check(self):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")                    
                    methods = self.get_methods()
                    hidden_values = {"auth_codes": set(methods.values())}
                    def get_private(self, name):
                        if name == "hidden_values":
                            return hidden_values
                        else:
                            return hidden_values[name]
                        
                    type(self).get_private = get_private                    
                    class HiddenStore:
                        pass                    
                    hidden_store = HiddenStore()
                    hidden_store = self.get_hidden_value(hidden_values, hidden_store)
                    hidden_values["hidden_store"] = hidden_store                    
                    hidden_store.value.hidden_values = hidden_values
                    type(self).get_private = self.create_get_private(hidden_values, enforce = True)
                    self.mask_public_face(hidden_values)

                def ready_to_redirect(self):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")                    
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
                    
                    self.set_private("_privates_", self._privates_)
                    self.set_private("_protecteds_", self._protecteds_)
                    self.set_private("AccessEssentials", self.AccessEssentials)
                    self.set_private("InsecureRestrictor", self.InsecureRestrictor)
                    self.set_private("Api", self.Api)
                    if hasattr(self, "_getattribute_"):
                        self.set_private("_getattribute_", self._getattribute_)                        
                    if hasattr(self, "_setattr_"):
                        self.set_private("_setattr_", self._setattr_)
                    if hasattr(self, "_delattr_"):
                        self.set_private("_delattr_", self._delattr_)                      
                    
                    self.set_private("private", api_self.Modifier(self.set_private))
                    self.set_private("protected", api_self.Modifier(self.set_protected))
                    self.set_private("public", api_self.Modifier(self.set_public))
                    if hasattr(self, "secure_class"):
                        self.private._class_ = self.secure_class.cls                        
                    self.ready_to_redirect()            
                    
                def pre_init(self):
                    try:
                        self.static_dict
                    except PrivateError:
                        raise ProtectedError("class level access is disallowed for this function")
                    self._privates_ = list(self._privates_)
                    self._protecteds_ = list(self._protecteds_)
                    self.AccessEssentials = api_self.AccessEssentials
                    self.InsecureRestrictor = api_self.InsecureRestrictor
                    try:
                        get_private = object.__getattribute__(api_self, "get_private")
                    except AttributeError:
                        self.Api = api_self
                    else:
                        self.Api = get_private("api")
                    self.start_access_check()                    
                    self.init_privates()
                    
                                        
            return AccessEssentials  


        @property
        def create_protected_gate(api_self):
            def create_protected_gate(base):
                class ProtectedGate(type(base)):
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
               
                return ProtectedGate()
            
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
                    AccessEssentials = api_self.AccessEssentials
                    is_function = api_self.is_function
                    for name in AccessEssentials.__dict__:
                        try:
                            if not hasattr(base, name):
                                return False
                        except PrivateError:
                            continue
                        member = getattr(base, name)
                        ae_member = getattr(AccessEssentials, name)
                        both_function = is_function(member) and is_function(ae_member)
                        if both_function and member.__code__ != ae_member.__code__:                                
                            return False                                                          
                    return True

                @classmethod
                def is_access_essentials(metacls, base):
                    if not metacls.acts_access_essentials(base):
                        return False
                    try:
                        hasattr(base, "static_dict")
                    except PrivateError:
                        return False
                    else:
                        return True

                @classmethod
                def remove_access_essentials(metacls, bases):
                    new_bases = list(bases)
                    for base in bases:
                        if metacls.is_access_essentials(base):
                            new_bases.remove(base)
                    return tuple(new_bases)

                @classmethod
                def add_access_essentials(metacls, bases):
                    bases = metacls.remove_access_essentials(bases)
                    bases = list(bases)
                    bases.insert(0, api_self.AccessEssentials)
                    bases = tuple(bases)                                       
                    return bases                    
                    
                @classmethod
                def has_access_essentials(metacls, bases):
                    AccessEssentials = api_self.AccessEssentials 
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
                    meta_dct["__new__"] = InsecureRestrictor.__new__ # some not-so-fun time has been spent here
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
                                   "base_publics"]
                    for list_name in lists_names:
                        if list_name not in dct:
                            dct[list_name] = []
                    
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
                        if not name.startswith("__"):
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
                            if metacls.is_access_essentials(base):
                                dct["_protecteds_"].extend(base._protecteds_)                           
                        if hasattr(base, "base_publics"):
                            dct["base_publics"].extend(base.base_publics)                        
                        names = list(base.__dict__.keys())
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
                        special_names = ["_privates_",
                                       "_protecteds_",
                                       "_publics_",
                                       "_new_",
                                       "private_bases",
                                       "protected_bases",
                                       "base_protecteds",
                                       "base_publics"]                        
                        if no_modifier and member_name not in special_names and dct["_publics_"] == []:
                            dct[member_name] = api_self.default(member)
                    metacls.extract_values(dct, "_privates_", api_self.PrivateValue)
                    metacls.extract_values(dct, "_protecteds_", api_self.ProtectedValue)
                    metacls.extract_values(dct, "_publics_", api_self.PublicValue)
                    metacls.extract_modifier(dct, api_self.PrivateModifier, "_privates_")
                    metacls.extract_modifier(dct, api_self.ProtectedModifier, "_protecteds_")
                    metacls.extract_modifier(dct, api_self.PublicModifier, "_publics_")                          
                    metacls.apply_base_rules(bases, dct)                                          
                    _privates_ = dct["_privates_"] + dct["_protecteds_"] + api_self.AccessEssentials._privates_
                    _privates_ += ["__dict__",
                                   "__bases__",
                                   "_bases",
                                   "__mro__",
                                   "_mro",
                                   "last_class",
                                   "private_bases",
                                   "protected_bases"]
                    dct["_protecteds_"] = list(set(dct["_protecteds_"]))                
                    dct["_privates_"] = list(set(_privates_))
                    dct["_publics_"] = list(set(dct["_publics_"]))  

                @classmethod
                def set_accessors(metacls, dct):
                    if "__getattribute__" in dct:
                        dct["_getattribute_"] = dct["__getattribute__"]
                        dct["__getattribute__"] = object.__getattribute__
                    if "__setattr__" in dct:
                        dct["_setattr_"] = dct["__setattr__"]
                        dct["__setattr__"] = object.__setattr__
                    if "__delattr__" in dct:
                        dct["_delattr_"] = dct["__delattr__"]
                        dct["__delattr__"] = object.__delattr__                                          

                @classmethod
                def get_new(metacls):
                    def __new__(cls, *args, **kwargs):
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
                            raise PrivateError(sys._getframe(1).f_code.co_name, "__new__", new_cls.__name__)
                        elif "_new_" in new_cls._privates_ and "_new_" not in new_cls._protecteds_:
                            raise PrivateError(sys._getframe(1).f_code.co_name, "_new_", new_cls.__name__)
                        elif "__new__" in new_cls._protecteds_:
                            raise ProtectedError(sys._getframe(1).f_code.co_name, "__new__", new_cls.__name__)
                        elif "_new_" in new_cls._protecteds_:
                            raise ProtectedError(sys._getframe(1).f_code.co_name, "_new_", new_cls.__name__)                                

                        new_obj = new_cls._new_(new_cls)                
                        if type(new_obj) == new_cls:
                            if "__init__" in new_cls._privates_ and "__init__" not in new_cls._protecteds_:
                                raise PrivateError(sys._getframe(1).f_code.co_name, "__init__", new_cls.__name__)
                            elif "__init__" in new_cls._protecteds_:
                                raise ProtectedError(sys._getframe(1).f_code.co_name, "__init__", new_cls.__name__)                                
                            
                            new_obj.pre_init()
                                                           
                            __init__ = new_obj.__init__
                            if not api_self.is_function(__init__):
                                for base in new_cls.__mro__:
                                    if api_self.is_function(base.__init__):
                                        __init__ = base.__init__
                                        new_cls.__init__ = __init__
                                        __init__ = types.MethodType(__init__, new_obj)                                        
                                        break
                            new_obj.private.redirect_access = True
                            __init__(*args, **kwargs)                            
                        return new_obj
                    return __new__
                    
                @classmethod
                def set_new(metacls, dct, bases):
                    if "__new__" in dct:
                        dct["_new_"] = dct["__new__"]
                    elif "_new_" not in dct:                           
                        mro = metacls.get_mro(bases)
                        for base in mro:
                            if hasattr(base, "_new_"):
                                if base._new_ != object.__new__:                                    
                                    dct["_new_"] = base._new_
                                    break
                            elif hasattr(base, "__new__"):
                                if base.__new__ != object.__new__:
                                    dct["_new_"] = base.__new__
                                    break
                        else:                            
                            dct["_new_"] = object.__new__                            
                    dct["__new__"] = metacls.get_new()                

                @classmethod
                def get_stub_class(metacls, stub_cache, cls):
                    """yield a mro-equivalent with no metaclass side-effects"""
                    if cls is object:
                        return object
                    stub_bases = []
                    bases = cls.__bases__
                    for base in bases:
                        stub_bases.append(metacls.get_stub_class(stub_cache, base))
                    if cls not in stub_cache:
                        stub_cache[cls] = type(cls.__name__, tuple(stub_bases), {})
                    return stub_cache[cls]

                @classmethod
                def get_future_mro(metacls, stub_cache, bases):
                    """https://stackoverflow.com/questions/52341247/how-to-recover-the-mro-of-a-class-given-its-bases"""
                    stub_bases = tuple(metacls.get_stub_class(stub_cache, base) for base in bases)
                    stub_cls = type("TempClass", stub_bases, {})
                    reversed_cache = {value:key for key, value in stub_cache.items()}
                    return [reversed_cache[mro_base] for mro_base in stub_cls.__mro__[1:]]

                @classmethod
                def get_mro(metacls, bases):
                    mro = metacls.get_future_mro({object: object}, bases) 
                    return tuple(mro)                  
                
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
                    
                def __new__(metacls, name, bases, dct):
                    bases = api_self.make_real_bases(bases)                    
                    bases = metacls.add_access_essentials(bases)                    
                    if metacls.has_conflicts(bases):
                        InsecureRestrictor = metacls.resolve_conflicts(bases)
                        return InsecureRestrictor(name, bases, dct)
                    else:
                        return metacls.create_class(name, bases, dct)               

                @property
                def __bases__(cls):
                    return cls._bases

                @property
                def __mro__(cls):
                    return cls._mro
                
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
                    if bases is None:
                        bases = type.__getattribute__(cls, "__bases__")
                    for base in bases:                        
                        try:
                            value = type(base).__getattribute__(base, name)
                        except AttributeError:
                            continue
                        except PrivateError as e:
                            e.caller_name = sys._getframe(1).f_code.co_name
                            cls.last_class = base
                            e.class_name = e.base_name
                            raise
                        else:
                            if not return_base:
                                return value
                            else:
                                return value, base
                    raise AttributeError(name)

                def has_own_attr(cls, name):
                    try:
                        type.__getattribute__(cls, name)
                    except AttributeError:
                        return False
                    else:
                        return True

                def is_public(cls, name):
                    has_public = cls.has_own_attr(name)
                    if not has_public:
                        try:
                            _, cls = cls.get_unbound_base_attr(name, return_base = True)
                        except PrivateError:
                            return False
                    if name in cls._privates_:
                        return False
                    elif not has_public and name in cls.base_protecteds:
                        return False
                    else:
                        return True
                    
                def __getattribute__(cls, name):
                    should_redirect = type.__getattribute__(cls, "should_redirect")
                    if should_redirect(name):
                        cls = type.__getattribute__(cls, "proxy")
                        try:                            
                            return getattr(cls, name)
                        except PrivateError as e:
                            inherited = hasattr(e, "inherited") and e.inherited == True
                            raise PrivateError(sys._getframe(1).f_code.co_name, name, cls.__name__, class_attr = True, inherited = inherited)
                    else:                        
                        if name == "own_redirect_access":
                            name = "redirect_access"
                        try:                                                 
                            return type.__getattribute__(cls, name)
                        except AttributeError as e:
                            get_unbound_base_attr = type.__getattribute__(cls, "get_unbound_base_attr")
                            try:                                
                                return get_unbound_base_attr(name)
                            except AttributeError:
                                raise e
                            except PrivateError as e:
                                e.caller_name = sys._getframe(1).f_code.co_name
                                raise

                def modify_attr(cls, name, delete = False, value = None):
                    should_redirect = type.__getattribute__(cls, "should_redirect")                   
                    if should_redirect(name):                                
                        try:
                            cls.own_redirect_access = False                            
                            if not delete:
                                setattr(cls.proxy, name, value)
                            else:
                                delattr(cls.proxy, name)
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
                            type.__setattr__(cls, name, value)
                            if hasattr(cls, "secure_class") and name not in names:
                                setattr(cls.secure_class, name, value)
                        else:
                            if hasattr(cls, "secure_class") and name not in names:
                                delattr(cls.secure_class, name)
                            else:
                                type.__delattr__(cls, name)
                    
                def __setattr__(cls, name, value):
                    modify_attr = type.__getattribute__(cls, "modify_attr")
                    modify_attr(name, value = value)                                        

                def __delattr__(cls, name):
                    modify_attr = type.__getattribute__(cls, "modify_attr") 
                    modify_attr(name, delete = True)

            return InsecureRestrictor


        @property
        def SecureClass(api_self):
            class SecureClass(metaclass = api_self.InsecureRestrictor):
                def __init__(self, cls):
                    get_private = object.__getattribute__(self, "get_private")
                    no_redirect = get_private("no_redirect")
                    @no_redirect(get_private("hidden_values"))
                    def __init__(self, cls):
                        private = self.private
                        private.raw_objs = []
                        private.cls = cls
                        private._privates_ = cls._privates_
                        private._protecteds_ = cls._protecteds_
                        private.base_publics = cls.base_publics
                        private.base_protecteds = cls.base_protecteds
                        all_names = dir(self.cls) + self._protecteds_ + self.base_publics + self.base_protecteds
                        all_names = list(set(all_names))
                        cls = self.cls
                        authorize = self.authorize
                        is_function = api_self.is_function
                        for member_name in all_names:                        
                            try:
                                member = getattr(cls, member_name)
                            except AttributeError:                
                                continue
                            except PrivateError:
                                continue                
                            if is_function(member):
                                authorize(member)
                        authorize(api_self.InsecureRestrictor.modify_attr)

                        private.raise_PrivateError2 = self.raise_PrivateError2
                        private.raise_ProtectedError2 = self.raise_ProtectedError2
                        private.is_ro_method = self.is_ro_method
                        private.is_meta_method = self.is_meta_method
                        private.create_secure_method = self.create_secure_method
                        private.control_access = self.control_access
                        
                    __init__(self, cls)

                def __call__(self, *args, **kwargs):
                    get_private = object.__getattribute__(self, "get_private")
                    no_redirect = get_private("no_redirect")
                    @no_redirect(get_private("hidden_values"))
                    def __call__(self, *args, **kwargs):                        
                        self.cls.secure_class = self                        
                        try:
                            obj = self.cls(*args, **kwargs)
                        except AccessError as e:
                            e.caller_name = sys._getframe(3).f_code.co_name
                            raise
                        object.__setattr__(obj, "_class_", self)
                        self.raw_objs.append(obj)
                        modifier_backup = api_self.default
                        api_self.set_default(api_self.public)                                        
                        SecureInstance = api_self.SecureInstance
                        api_self.set_default(modifier_backup)
                        SecureInstance.proxy = self            
                        obj = SecureInstance(obj)
                        api_self.Restrictor.remove_base_leaks(obj)
                        type(obj).redirect_access = True                        
                        return obj

                    return __call__(self, *args, **kwargs)

                def public_super(self):
                    get_private = object.__getattribute__(self, "get_private")
                    no_redirect = get_private("no_redirect")
                    @no_redirect(get_private("hidden_values"))
                    def public_super(self):
                        class super:
                            __slots__ = ["secure_class"]
                            
                            def __init__(self, secure_class):
                                self.secure_class = secure_class
                                
                            def __getattribute__(self, name):
                                secure_class = object.__getattribute__(self, "secure_class")
                                get_private = object.__getattribute__(secure_class, "get_private")
                                no_redirect = get_private("no_redirect")
                                @no_redirect(get_private("hidden_values"))
                                def __getattribute__(self, name):
                                    secure_class = object.__getattribute__(self, "secure_class")                               
                                    try:
                                        value, base = secure_class.cls.get_unbound_base_attr(name, return_base = True)
                                    except AttributeError:
                                        value = object.__getattribute__(self, name)
                                    except PrivateError as e:
                                        pg = type.__getattribute__(secure_class.cls.last_class, "protected_gate")                                      
                                        try:
                                            getattr(pg.cls, name)
                                        except PrivateError as e:
                                            e.caller_name = sys._getframe(3).f_code.co_name
                                            raise
                                    else:
                                        pg = type.__getattribute__(base, "protected_gate")                                            
                                    if hasattr(base, "_privates_"):
                                        is_private = name in base._privates_
                                        inherited = False
                                        if not is_private and not base.has_own_attr(name):
                                            inherited = True
                                            is_private = name in base.base_protecteds
                                    else:
                                        is_private = False
                                    if is_private and name not in base._protecteds_ and not inherited: # if raw class
                                        raise PrivateError(sys._getframe(3).f_code.co_name, name, base.__name__, class_attr = True)                                        
                                    elif is_private:
                                        raise ProtectedError(sys._getframe(3).f_code.co_name, name, base.__name__, class_attr = True)
                                    if hasattr(secure_class.cls, "private_bases") and pg.cls in secure_class.cls.private_bases:
                                        return object.__getattribute__(self, name)
                                    elif hasattr(secure_class.cls, "protected_bases") and pg.cls in secure_class.cls.protected_bases:
                                        return object.__getattribute__(self, name)                                    
                                    return value

                                return __getattribute__(self, name)

                            def __str__(self):
                                secure_class = object.__getattribute__(self, "secure_class")
                                get_private = object.__getattribute__(secure_class, "get_private")
                                no_redirect = get_private("no_redirect")
                                @no_redirect(get_private("hidden_values"))
                                def __str__(self):
                                    secure_class = object.__getattribute__(self, "secure_class")
                                    super = __builtins__["super"]
                                    return str(super(secure_class.cls, secure_class.cls))
                                    
                                return __str__(self)

                        self.authorize(super)
                        return super(self)

                    return public_super(self)

                def raise_PrivateError2(self, name, depth = 3, inherited = False):
                    depth += 1
                    raise PrivateError(sys._getframe(depth).f_code.co_name, name, self.cls.__name__, class_attr = True, inherited = inherited)

                def raise_ProtectedError2(self, name, depth = 3):
                    depth += 1               
                    raise ProtectedError(sys._getframe(depth).f_code.co_name, name, self.cls.__name__, class_attr = True)                

                def is_ro_method(self, name, value):
                    hidden_values = self.own_hidden_values
                    if hasattr(super(), name):
                        function = getattr(super(), name)
                        if api_self.is_function(value) and api_self.is_function(function) and value.__code__ == function.__code__:
                            return True
                    return False

                def is_meta_method(self, name, value):
                    if hasattr(self.InsecureRestrictor, name):
                        function = getattr(self.InsecureRestrictor, name)
                        if api_self.is_function(value) and value.__code__ == function.__code__:
                            return True
                    return False

                def create_secure_method(self, method):
                    hidden_method = self.get_hidden_value(self.hidden_values, method)
                    def secure_method(*args, **kwargs):
                        """wrap the method to prevent possible bypasses through its __self__ attribute"""
                        try:
                            return hidden_method.value(*args, **kwargs)
                        except AccessError as e:
                            e.caller_name = sys._getframe(1).f_code.co_name
                            raise                       
                    self.authorize(secure_method)
                    return secure_method
                    
                def _getattribute_(self, name):
                    get_private = object.__getattribute__(self, "get_private")
                    no_redirect = get_private("no_redirect")
                    @no_redirect(get_private("hidden_values"))
                    def _getattribute_(self, name):
                        hidden_values = self.hidden_values
                        wrapped_cls = hidden_values["cls"]
                        _privates_ = hidden_values["_privates_"]                        
                        base_protecteds = hidden_values["base_protecteds"]
                        check_caller = self.check_caller
                        is_subclass_method = self.is_subclass_method
                        _protecteds_ = hidden_values["_protecteds_"]
                        raise_PrivateError2 = hidden_values["raise_PrivateError2"]
                        raise_ProtectedError2 = hidden_values["raise_ProtectedError2"]
                        create_secure_method = hidden_values["create_secure_method"]
                        InsecureRestrictor = hidden_values["InsecureRestrictor"]
                        is_ro_method = hidden_values["is_ro_method"]
                        AccessEssentials = hidden_values["AccessEssentials"]
                        Api = hidden_values["Api"]
                        if name == "__getattribute__":
                            raise PrivateError("__getattribute__ method is disallowed")                        
                        def is_meta_method(self, hidden_values, name, value):
                            """We have to duplicate this function for performance reasons.
                            __getattribute__ calls are big overheads"""                            
                            if hasattr(InsecureRestrictor, name):
                                function = getattr(InsecureRestrictor, name)
                                same_function = Api.is_function(value) and Api.is_function(function) and value.__code__ == function.__code__
                                if same_function:
                                    return True
                            return False
                                                
                        try:                        
                            value = getattr(wrapped_cls, name)
                        except PrivateError as e:
                            e.caller_name = sys._getframe(5).f_code.co_name
                            e.inherited = True
                            raise

                        real_caller = sys._getframe(7).f_code
                        internal_callers = [InsecureRestrictor.set_new.__code__, InsecureRestrictor.get_new().__code__]
                        if real_caller in internal_callers:
                            return value
                        public_names = ["_privates_",
                                        "_protecteds_",
                                        "__bases__",
                                        "__mro__",
                                        "_bases",
                                        "_mro",
                                        "__dict__",
                                        "base_publics",
                                        "base_protecteds",
                                        "protected_bases"]
                        is_private = name in _privates_
                        inherited = False
                        if not is_private:
                            try:
                                type.__getattribute__(self.cls, name)
                            except AttributeError:
                                is_private = name in base_protecteds
                                inherited = True
                        authorized_caller = check_caller(hidden_values, depth = 5, name = name)
                        has_protected_access = is_subclass_method(depth = 5)                                
                        if is_private and name not in public_names and name not in _protecteds_ and not inherited:                            
                            raise_PrivateError2(name, depth = 5)
                        elif is_meta_method(self, hidden_values, name, value) and name != "has_own_attr":
                            raise PrivateError(sys._getframe(5).f_code.co_name, name, type(self.cls).__name__)
                        elif is_private and name not in public_names and not authorized_caller:
                            raise_ProtectedError2(name, depth = 5)
                        elif name == "protected_bases" and not has_protected_access:
                            raise_ProtectedError2(name, depth = 5)
                        elif is_meta_method(self, hidden_values, name, value):
                            value = create_secure_method(value)
                        elif name in ["_privates_", "_protecteds_", "_publics_", "base_publics", "base_protecteds", "protected_bases"]:
                            value = list(value)
                        elif name in ["__bases__", "__mro__", "_bases", "_mro"]:
                            is_access_essentials = InsecureRestrictor.is_access_essentials
                            value = api_self.get_secure_bases(wrapped_cls, is_access_essentials, value, for_subclass = has_protected_access)
                        elif name == "__dict__":
                            new_dict = dict(value)
                            for key in value:
                                if key in _protecteds_:
                                    new_dict[key] = ProtectedError("protected member")
                                elif key in self._privates_:
                                    new_dict[key] = PrivateError("private member")                                    
                            value = new_dict
                        elif is_ro_method(name, value):
                            value = getattr(AccessEssentials, name)
                        return value
                    
                    return _getattribute_(self, name)

                def control_access(self, name):
                    if name in ["get_private", "__getattribute__", "__setattr__", "__delattr__"]:
                        raise PrivateError(f"Modifying {name} is disallowed")
                    hidden_values = self.own_hidden_values
                    authorized_caller = self.check_caller(self.hidden_values, depth = 6, name = name)
                    if name in self._privates_ and not authorized_caller and name not in self._protecteds_:
                        self.raise_PrivateError2(name, depth = 6)
                    elif name in self._privates_ and not authorized_caller:
                        self.raise_ProtectedError2(name, depth = 6)
                    elif name in self._privates_:
                        try:
                            value = getattr(self.cls, name)
                        except PrivateError:
                            return
                        if self.is_ro_method(name, value):                        
                            raise PrivateError("methods inherited from AccessEssentials are read only") # prevents subclasses to bypass private members of their bases             
                    
                def _setattr_(self, name, value):
                    get_private = object.__getattribute__(self, "get_private")
                    no_redirect = get_private("no_redirect")
                    @no_redirect(get_private("hidden_values"))
                    def _setattr_(self, name, value):
                        self.control_access(name)                       
                        if api_self.is_function(value):
                            untrusted_func = value
                            def trusted_method(itself, *args, **kwargs):
                                self = object.__getattribute__(itself, "_self_")
                                return untrusted_func(self, *args, **kwargs)
                            value = trusted_method
                        type.__setattr__(self.cls, name, value)
                        for obj in self.raw_objs:
                            type.__setattr__(type(obj), name, value)
                        
                    _setattr_(self, name, value)                        

                def _delattr_(self, name):
                    get_private = object.__getattribute__(self, "get_private")
                    no_redirect = get_private("no_redirect")
                    @no_redirect(get_private("hidden_values"))
                    def _delattr_(self, name):
                        self.control_access(name)                     
                        type.__delattr__(self.cls, name)
                        for obj in self.raw_objs:
                            type.__delattr__(type(obj), name)
                    _delattr_(self, name)

            return SecureClass                


        @property
        def SecureInstance(api_self):
            class SecureInstance(metaclass = api_self.InsecureRestrictor):
                def __init__(self, inst):
                    get_private = object.__getattribute__(self, "get_private")
                    no_redirect = get_private("no_redirect")
                    @no_redirect(get_private("hidden_values"))
                    def __init__(self, inst):
                        self.private.inst = inst
                        self.private.raise_PrivateError2 = self.raise_PrivateError2
                        self.private.raise_ProtectedError2 = self.raise_ProtectedError2
                        self.private.create_secure_method = self.create_secure_method
                        self.private.get_class_attr = self.get_class_attr
                        modifier_backup = api_self.default
                        api_self.set_default(api_self.public)                                        
                        inst._self_ = self
                        api_self.set_default(modifier_backup)                                                

                    __init__(self, inst)

                def public_super(self):
                    get_private = object.__getattribute__(self, "get_private")
                    no_redirect = get_private("no_redirect")
                    @no_redirect(get_private("hidden_values"))
                    def public_super(self):
                        class super:
                            __slots__ = ["secure_instance"]
                            
                            def __init__(self, secure_instance):
                                self.secure_instance = secure_instance
                                
                            def __getattribute__(self, name):
                                secure_instance = object.__getattribute__(self, "secure_instance")
                                get_private = object.__getattribute__(secure_instance, "get_private")
                                no_redirect = get_private("no_redirect")
                                @no_redirect(get_private("hidden_values"))
                                def __getattribute__(self, name):
                                    secure_instance = object.__getattribute__(self, "secure_instance")
                                    cls = type(secure_instance.inst)                                                                   
                                    try:
                                        value, base = cls.get_unbound_base_attr(name, return_base = True)                                        
                                    except AttributeError:
                                        return object.__getattribute__(self, name)
                                    except PrivateError as e:
                                        pg = type.__getattribute__(cls.last_class, "protected_gate")                                      
                                        try:
                                            getattr(pg.cls, name)
                                        except PrivateError as e:
                                            if not e.class_attr:
                                                return object.__getattribute__(self, name)                                            
                                            e.caller_name = sys._getframe(3).f_code.co_name
                                            e.class_attr = False
                                            raise
                                    else:
                                        pg = type.__getattribute__(base, "protected_gate")    
                                    inherited = False
                                    if hasattr(base, "_privates_"):
                                        is_private = name in base._privates_                                        
                                        if not is_private and not base.has_own_attr(name):
                                            inherited = True
                                            is_private = name in base.base_protecteds
                                    else:
                                        is_private = False
                                    if is_private and name not in base._protecteds_ and not inherited: # if raw class
                                        raise PrivateError(sys._getframe(3).f_code.co_name, name, base.__name__)                                        
                                    elif is_private:
                                        raise ProtectedError(sys._getframe(3).f_code.co_name, name, base.__name__)
                                    if hasattr(cls, "private_bases") and pg.cls in cls.private_bases:
                                        return object.__getattribute__(self, name)
                                    elif hasattr(cls, "protected_bases") and pg.cls in cls.protected_bases:
                                        return object.__getattribute__(self, name)
                                    if api_self.is_function(value):
                                        value = types.MethodType(value, secure_instance.inst)
                                        value = secure_instance.create_secure_method(value)
                                    return value

                                return __getattribute__(self, name)

                            def __str__(self):
                                secure_instance = object.__getattribute__(self, "secure_instance")
                                get_private = object.__getattribute__(secure_instance, "get_private")
                                no_redirect = get_private("no_redirect")
                                @no_redirect(get_private("hidden_values"))
                                def __str__(self):
                                    secure_instance = object.__getattribute__(self, "secure_instance")
                                    super = __builtins__["super"]
                                    return str(super(type(secure_instance.inst), secure_instance.inst))
                                    
                                return __str__(self)

                        self.authorize(super)
                        return super(self)

                    return public_super(self)                    

                def raise_PrivateError2(self, name, depth = 3, inherited = False):
                    depth += 1
                    raise PrivateError(sys._getframe(depth).f_code.co_name, name, type(self.inst).__name__, inherited = inherited)

                def raise_ProtectedError2(self, name, depth = 3):
                    depth += 1
                    raise ProtectedError(sys._getframe(depth).f_code.co_name, name, type(self.inst).__name__)

                def create_secure_method(self, method):
                    hidden_method = self.get_hidden_value(self.hidden_values, method)
                    def secure_method(*args, **kwargs):
                        """wrap the method to prevent possible bypasses through its __self__ attribute"""
                        return hidden_method.value(*args, **kwargs)
                    self.authorize(secure_method)
                    return secure_method

                def get_class_attr(self, name):
                    try:
                        value = getattr(self.proxy, name)
                    except AccessError as e:
                        e.caller_name = sys._getframe(4).f_code.co_name
                        e.class_attr = False
                        raise                        
                    if api_self.is_function(value) and type(value) != types.MethodType:
                        value = types.MethodType(value, self.inst)
                    return value
                    
                def _getattribute_(self, name):
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
                    try:
                        if name == "__getattribute__":
                            raise PrivateError("__getattribute__ method is disallowed")                        
                        if hasattr(type(self.inst), "_getattribute_"):                            
                            getattribute = type(self.inst)._getattribute_
                        else:
                            getattribute = getattr
                        try:                            
                            value = getattribute(self.inst, name)                            
                        except PrivateError as e:
                            e.caller_name = sys._getframe(3).f_code.co_name
                            raise
                        except ProtectedError:                           
                            self.raise_ProtectedError2(name, depth = 3)                            
                        except AttributeError as e:
                            try:
                                value = self.get_class_attr(name)
                            except AttributeError:
                                raise e
                        try:
                            delattr(self.inst, name)
                        except AttributeError:
                            generated_codes = [self.__getattribute__.__code__,
                                               self.__setattr__.__code__,
                                               self.__delattr__.__code__,
                                               self.create_getattribute().__code__,
                                               self.create_setattr().__code__,
                                               self.create_delattr().__code__,
                                               self.get_private.__code__]
                            if not api_self.is_function(value) or value.__code__ not in generated_codes:
                                value = self.get_class_attr(name)
                        except AccessError:
                            pass
                        else:
                            object.__setattr__(self.inst, name, value)                        
                        if type(value) == types.MethodType:
                            value = self.create_secure_method(value)
                        return value
                    finally:
                        if obj_will_redirect:
                            hidden_values["redirect_access"] = True                                          
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
                    try:                                            
                        if hasattr(type(self.inst), "_setattr_"):
                            setter = type(self.inst)._setattr_                            
                        else:
                            setter = setattr                        
                        try:
                            setter(self.inst, name, value)
                        except PrivateError:
                            self.raise_PrivateError2(name, depth = 3)
                        except ProtectedError:                           
                            self.raise_ProtectedError2(name, depth = 3)
                    finally:
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
                    try:
                        if hasattr(type(self.inst), "_delattr_"):
                            deleter = type(self.inst)._delattr_
                        else:
                            deleter = delattr                        
                        try:
                            deleter(self.inst, name)
                        except PrivateError:
                            self.raise_PrivateError2(name, depth = 3)
                        except ProtectedError:                           
                            self.raise_ProtectedError2(name, depth = 3)
                    finally:
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
                    cls._bases = metacls.remove_access_essentials(cls.__bases__)                                    
                    cls._mro = metacls.remove_access_essentials(cls.__mro__)                    
                    
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
                        dct[default_name] = list(set(dct[default_name]))
                    return original_new(metacls, name, bases, dct)
                
                meta_dct["__new__"] = __new__

            return hook_meta_new


        @property
        def extract_values(api_self):
            def extract_values(bases, dct, member_group):                
                if member_group == "_privates_":
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
                        if member_group == "_privates_" or member_group == "base_protecteds":
                            names = []
                            if hasattr(base, "_protecteds_"):
                                names.extend(base._protecteds_)
                            if hasattr(base, "base_protecteds"):
                                names.extend(base.base_protecteds)                            
                            if hasattr(base, "base_publics"):
                                names.extend(base.base_publics)
                            base_publics = list(base.__dict__.keys())
                            base_publics.remove("__new__")
                            if base.__dict__["_new_"] == object.__new__:
                                base_publics.remove("_new_")
                            names.extend(base_publics)                            
                            for name in names:                        
                                dct[member_group].append(name)
                            dct[base_group].append(base)
                    new_bases.append(base)
                if member_group == "_privates_" or member_group == "base_protecteds":
                    dct[member_group] = list(set(dct[member_group]))
                return new_bases

            return extract_values
        

        @property
        def create_restrictor(api_self):
            def create_restrictor(*bases, insecure = False):
                default_dct = {"_privates_": [], "base_protecteds": [], "private_bases": [], "protected_bases": []}                
                bases = api_self.extract_values(bases, default_dct, "_privates_")                
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
    def create_secure_closure(self, func):
        @property
        def secure_closure(api_self):
            return func(self)
        return secure_closure        
        
    def __init__(self):
        self.own_hidden_values["redirect_access"] = False
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
        self.set_private("redirect_access", True)

    def _getattribute_(self, name):
        get_private = object.__getattribute__(self, "get_private")
        value = getattr(get_private("api"), name)        
        return value

api = SecureApi()


if __name__ == "__main__":
    import tests
