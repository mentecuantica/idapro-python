import string
from collections import OrderedDict
from collections import Counter
import random
import idaapi, idc, idautils, ida_kernwin
import sark
import json

start = 0x01440E80
end = 0x01594280
CONST_LEN = 6
VFTABLE_LEN = 12
METHODS_LIMIT = 1040
COLOR_GREEN = 0x008000
COLOR_DARK_CYAN = 0x8B8B00
COLOR_ORANGE = 0x00A5FF  # FFA500
lines = sark.lines(start, end)


class VtableClass:
    def __init__(self, line):
        self.class_lines = []
        self.ea = line.ea
        self.line = line
        self.current_line = line
        self.functions_addr = []
        self.functions = {}
        self.get_base_name()
        self.get_methods()

    def get_base_name(self):
        self.raw_name = self.line.name
        n = self.line.demangled
        name = n.replace('::', '_').replace('<', '_').replace('>', '_').replace(',', '_').replace(' ', '_').replace('*',
                                                                                                                    '_').replace(
            "`vftable'", '').replace('___', '_').replace('__', '_').strip('_')

        self.base_name = name[CONST_LEN::]
        return self.base_name

    def get_methods(self):
        start = self.line.ea

        for i in range(METHODS_LIMIT):
            nl = sark.Line(start)

            o = GetOpnd(nl.ea, 0)

            if o.startswith('offset'):
                val = o.split("offset ")[1]
                type, addr = val[:4], val[4:]
                if type in ['sub_']: # , 'loc_'
                    
                    if addr.find("+")>0:
                        print("\n ------ \n",addr,type,o)
                        
                    else:
                        func_addr = int(addr, 16)
                        self.functions_addr.append(func_addr)
                        self.class_lines.append(start)
                        self.functions[GetFunctionName(func_addr)] = func_addr
                if val.strip() == '__purecall':
                    self.class_lines.append(start)
                # print(o)

            else:
                self.end_line = start
                break
            start += 4

        return self.functions_addr

    def s(self):
        l = self.line
        functions = ",".join([hex(a) for a in self.functions_addr])

        function_names = ",".join(self.functions.keys())

        return "%s \n%s, size:%d,type:%s,name:%s, subs:%d\n%s \n\n" % (
            self.base_name, hex(l.ea), l.size, l.type, l.has_name, len(self.functions_addr), function_names)

    def __repr__(self):
        return self.s()

    def colorize(self):
        idc.set_color(self.ea - 4, CIC_ITEM, COLOR_ORANGE)
        for addr in self.class_lines:
            idc.set_color(addr, CIC_ITEM, COLOR_DARK_CYAN)

    @staticmethod
    def dump_names(list_of_vtbl):
        f = open('classes_rtii_autonaming_subs.txt', 'w+')
        for cls in list_of_vtbl:
            for n, a in cls.functions.items():
                idc.set_cmt(a, cls.base_name, 0)

            print(cls.base_name)
            f.write(cls.base_name + "\n")
        f.close()


class SaveClasses:
    def __init__(self, classes, file_name="rtii_autonaming_subs.json"):
        if len(classes) > 0:
            self.raw_data = classes
            self.file_name = file_name

    def create_dict(self):
        all = {}
        for cinfo in self.raw_data:
            all[cinfo.base_name] = {
                "addr": hex(cinfo.ea - 4),
                "subs": cinfo.functions
            }
        return all

    def json(self):
        with open(self.file_name, "w") as write_file:
            json.dump(self.create_dict(), write_file, indent=4)


class SubRenamer:
    def __init__(self, file_name="rtii_autonaming_subs.json"):
        self.file_name = file_name
        self.data = {}
        self.sorted_data = None
        self.rename_counter = 0

    def load_json(self):
        with open(self.file_name, "r") as write_file:
            self.data = json.load(write_file)
            return self.data

    def rename_functions(self):
        self.rename_counter = 0
        for name, details in self.data.items():
            i = 0
            prefix = details["new_name"]
            for name, func_addr in details['subs'].items():
                new_name = prefix + str(i)
                success = self.rename_stub(func_addr, str(new_name), name)
                if success:
                    self.rename_counter += 1

                i += 1

    def rename_stub(self, func_addr, new_name, name=''):
        r = MakeName(func_addr, new_name)
        if r:
            print("\n New name:")
            print(hex(func_addr), name, new_name)
            return r

        print("%s taken" % str(new_name))
        new_name = new_name + random.choice(string.ascii_letters)
        r = MakeName(func_addr, str(new_name))
        if r:
            print("\n New +rand name:")
            print(hex(func_addr), name, new_name)
        return r

    def prepare(self):
        for name, info in self.data.items():
            self.data[name]['count'] = len(info['subs'])
        self.sorted()
        temp_separated_dict = {name: name.lower().split('_') for name, val in self.sorted_data.items()}
        print(temp_separated_dict)

        clean_dict = {}
        for name, words in temp_separated_dict.items():
            clean_words = [self.clear_name(word) for word in words if len(word) > 2]
            clean_dict[name] = "s_" + "_".join(
                [word for word in clean_words if word not in self.fuck_words])
            self.data[name]['new_name'] = clean_dict[name]
        print(self.data)

        all_words = {name: self.clear_name(item.lower()) for name, sublist in temp_separated_dict.items() for item in
                     sublist if
                     len(item) > 2}
        # print(all_words)
        self.by_count(all_words)

    def sorted(self):
        self.sorted_data = OrderedDict(sorted(self.data.items(), key=lambda v: v[1]['count'], reverse=True))
        return self.sorted_data

    def by_count(self, all_words, limit=100):
        a = Counter(all_words)

        j = 0

        popular_names = []
        for n, i in sorted(a.items(), key=lambda v: v[1], reverse=True):
            # print(n, i)
            if len(n) > 1:
                popular_names.append(n)
            j = j + 1
            if j >= limit:
                break
        return popular_names

    @staticmethod
    def disemvowel(word):
        words = list(word)
        new_letters = []
        for i in words:
            if i.upper() == "A" or i.upper() == "E" or i.upper() == "I" or i.upper() == "O" or i.upper() == "U":
                pass
            else:
                new_letters.append(i)
        return ''.join(new_letters)

    # @property
    # def rename_counter(self):
    #     return self._rename_counter

    @staticmethod
    def clear_name(name):
        name_clean = ''.join(
            c for c in name if c.isalpha())  # not c.isdigit() and c not in string.punctuation and )
        return name_clean

    @property
    def fuck_words(self):
        return [u'class', u'detail', u'counted', u'struct', u'atl', u'std', u'char', u'wchar', u'ctl', u'traits',
                u'int', u'const', u'private', u'unsigned',
                u'public', u'basic', u'factory',
                u'void', u'allocator', u'string', u'long', u'block',
                u'table', u'ptr', u'bool', u'bad', u'win', u'regex', u'stdcall', u'injector', u'anonymous',
                u'value', u'namespace',
                u'proxy', u'func', u'idx', u'thiscall', u'static',
                u'hwnd', u'shared', u'pool', u'functor',
                u'guid', u'cdecl', u'clone', u'data', u'hash', u'format',
                u'handle', u'vector']


cls = []

for l in lines:
    if l.type == "data" and l.demangled.find('vftable') > 0:
        cls.append(VtableClass(l))

print("\n%d classes identified\n\n" % len(cls))


def do_the_deal():
    for c in cls:
        c.colorize()
        print(c)
    ipo = SaveClasses(cls)
    ipo.json()
    sr = SubRenamer()
    sr.load_json()
    sr.prepare()
    sr.rename_functions()
    return sr.rename_counter


f_count = sum([len(c.functions) for c in cls])

to_proceed = bool(ida_kernwin.ask_yn(1, "Identified %d classes %d unnamed subs. Wanna proceed?" % (len(cls), f_count)))
print("to proceed?", to_proceed)
if to_proceed:
    qty_of_success = do_the_deal()
    ida_kernwin.ask_yn(1, "Renamed %d of %d" % (qty_of_success, f_count))
else:
    print("I am done")
