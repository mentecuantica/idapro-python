import idaapi
from idc import *
from idautils import *
from idaapi import *
from pprint import pprint as pp
import cPickle

def merge_two_dicts(x, y):
    z = x.copy()  # start with x's keys and values
    z.update(y)  # modifies z with y's keys and values & returns None
    return z


def merge_dicts(*dict_args):
    """
    Given any number of dicts, shallow copy and merge into a new dict,
    precedence goes to key value pairs in latter dicts.
    """
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result

def pickling(fObj):
    file = 'fobj.p'
    pp(["fOriginal", fObj])

    f = open(file, 'wb')
    cPickle.dump(fObj, f, -1)
    f.close()

    f = open(file, 'rb')
    fLoadedObj = cPickle.load(f)
    f.close()

    pp(['unpickled', fLoadedObj])
    pp(fLoadedObj.xrefs())

class Fnc:
    def __init__(self, ea, name=None, ordinal=0, callOfFunction=None):
        self.ea = ea
        if name is None:
            name = Fnc.getNameAt(ea)
        self.name = name
        self.ordinal = ordinal
        self.is_import = 0
        self.xref_to_status = False
        self.call_to_status = False
        self.calls_in_xrefs = []
        self.xrefs_to_function = []
        self.called_in_count = 0
        self.calledCount = 0
        self.xrefsCount = 0
        self.start = ea
        self.end = Fnc.getEnd(ea)
        self.args_num = self.getArgsNum()
        self.type = self.getType()
        self.is_import = 1
        self._xrefs = None
        self._code_refs = None
        self.op = GetMnem(ea).lower()
        if callOfFunction is not None:
            self.call_ref = callOfFunction
            self.is_import = 0

    @staticmethod
    def create_at_addr(faddr):
        return Fnc(faddr)

    def get_size(self):
        diff = self.ea - self.end
        return diff

    def get_keys(self):
        return ['address', 'name', 'ordinal', 'object']

    def get_values(self):
        return self.ea, self.name, self.ordinal, self

    def parse_function_type(self, end=None):
        frame = idc.GetFrame(self.ea)
        if frame == None:
            return ""
        if end == None:  # try to find end
            func = Fnc.at(self.ea)
            if not func:
                return "?"
            end = PrevAddr(GetFunctionAttr(func, FUNCATTR_END))
        end_addr = end
        mnem = GetDisasm(end_addr)

        if not "ret" in mnem:
            # it's not a real end, get instruction before...
            end_addr = PrevAddr(end)
            if end_addr == BADADDR:
                # cannot get the real end
                return ""
            mnem = GetDisasm(end_addr)

        if not "ret" in mnem:
            # cannot get the real end
            return ""

        op = GetOpType(end_addr, 0)
        if op == o_void:
            # retn has NO parameters
            return "__cdecl"
        # retn has parameters
        return "__stdcall"

    def getType(self):
        type = GetType(self.ea)
        if type == None:
            return self.parse_function_type(self.end)
        args_start = type.find('(')
        if not args_start == None:
            type = type[:args_start]
        return type

    def getArgsDescription(self):
        name = Demangle(GetFunctionName(self.ea), GetLongPrm(INF_SHORT_DN))  # get from mangled name
        if not name:
            name = GetType(self.ea)  # get from type
            if not name:
                return Fnc.parse_function_args(self.ea)  # cannot get params from the mangled name
        args_start = name.find('(')
        if args_start != None and args_start != (-1):
            return name[args_start:]
        return ""

    def getArgsNum(self):
        args = self.getArgsDescription()
        if not args:
            return 0
        delimiter = ','
        args_list = args.split(delimiter)
        args_num = 0
        for arg in args_list:
            if arg == "()" or arg == "(void)":
                continue
            args_num += 1
        return args_num


    def __getFormatString(self):
        tpl = "'A:%s;E:%s; N:%s;C:%s; '"
        value = tpl % (hex(self.ea), hex(self.end), self.name, str(self.calledCount))
        return value

    def __str__(self):
        return self.__getFormatString()

    def __repr__(self):
        return self.__getFormatString()

    def get_map_dict(self):
        return {
            'address': self.ea,
            'name': self.name,
            'ordinal': self.ordinal,
            'object': self
        }

    def contains(self, addr):
        """Check if the given address lies inside the function.  """
        ea = self.ea
        end = self.end
        # swap if order is opposite:
        if self.start > self.end:
            end = self.start
            start = self.end
        if addr >= ea and addr < ea:
            return True
        return False

    @staticmethod
    def isMangled(faddr):
        name = GetFunctionName(faddr)
        disable_mask = GetLongPrm(INF_SHORT_DN)
        if Demangle(name, disable_mask) == None:
            return False
        return True

    @staticmethod
    def getStart(addr):
        return GetFunctionAttr(addr, FUNCATTR_START)

    @staticmethod
    def getEnd(addr):
        return PrevAddr(GetFunctionAttr(addr, FUNCATTR_END))

    @staticmethod
    def from_addr(faddr):
        return Fnc(Fnc.getStart(faddr), Fnc.getNameAt(faddr))

    @staticmethod
    def getNameAt(faddr):
        name = GetFunctionName(faddr)
        disable_mask = GetLongPrm(INF_SHORT_DN)
        demangled_name = Demangle(name, disable_mask)
        if demangled_name == None:
            return name
        args_start = demangled_name.find('(')
        if args_start == None:
            return demangled_name
        return demangled_name[:args_start]

    @staticmethod
    def at(faddr):
        functions = Functions(faddr)
        for func in Functions():
            return func
        return None

    @staticmethod
    def parse_function_args(faddr):
        local_variables = []
        arguments = []
        current = local_variables

        frame = idc.GetFrame(faddr)
        arg_string = ""
        if frame == None:
            return ""

        start = idc.GetFirstMember(frame)
        end = idc.GetLastMember(frame)
        count = 0
        max_count = 10000
        args_str = ""
        while start <= end and count <= max_count:
            size = idc.GetMemberSize(frame, start)
            count = count + 1
            if size == None:
                start = start + 1
                continue

            name = idc.GetMemberName(frame, start)
            start += size

            if name in [" r", " s"]:
                # Skip return address and base pointer
                current = arguments
                continue
            arg_string += " " + name
            current.append(name)
        args_str = ", ".join(arguments)
        if len(args_str) == 0:
            args_str = "void"
        return "(" + args_str + ")"

    @staticmethod
    def rva_to_va(rva):
        base = idaapi.get_imagebase()
        return rva + base

    @staticmethod
    def va_to_rva(va):
        base = idaapi.get_imagebase()
        return va - base