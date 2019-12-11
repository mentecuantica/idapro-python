#!/usr/bin/env python
# Based on original script
# IFL - Interactive Functions List
# by https://github.com/hasherezade/ida_ifl
# how to install: copy the script into plugins directory, i.e: C:\Program Files\IDA <version>\plugins
# then:
# run from IDA menu: View -> PLUGIN_NAME
# or press: PLUGIN_HOTKEY
#
__VERSION__ = '0.0.2'
__AUTHOR__ = 'mentequantica'

PLUGIN_NAME = "IIL - Awesome Imports"
PLUGIN_HOTKEY = "Ctrl-Alt-F"

from mentequantica.base_api import *
import cPickle
import ida_kernwin
#from idaapi import register_action, action_handler_t, action_desc_t, attach_action_to_menu

# from idaapi import PluginForm

from PyQt5 import QtGui, QtCore, QtWidgets
from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot

VERSION_INFO = "IKL v" + str(__VERSION__)


class FExtrn(Fnc):
    def __init__(self, ea, name=None, ordinal=0, callOfFunction=None ):
        Fnc.__init__(self,ea, name, ordinal, callOfFunction)
        self.is_import = 1
        self.xrefs_raw = []
        self.xrefs_functions = None

    @staticmethod
    def create_at_addr(faddr):
        return FExtrn(faddr)

    # XrefsTo(addr,True) results as generator() of obj(xref)
    # xref.frm - address in which func(addr) is called
    # xref.to  - points to the func(addr)
    def xrefs(self):
        if self.xref_to_status == True and self.xrefsCount > 0:
            print("xrefs readdy",self)
            return self.xrefs_functions

        self.xrefsCount = 0
        xrefs = []

        for xref in self.xrefs_to():
            self.xrefsCount=self.xrefsCount+1
            xrefs.append(xref.frm)

        self.called_in_count = len(set(xrefs))
        self.xref_to_status = True
        self.xrefs_raw = xrefs
        self.xrefs_functions =  {faddr:Fnc.create_at_addr(faddr) for faddr in xrefs}
        #print("call count",self.called_in_count)
        #print("xrefs",self.xrefs_functions)
        return self.xrefs_functions


    def xrefs_to(self):
        return XrefsTo(self.ea, True)

    def coderefs_to(self):
        return CodeRefsTo(self.ea, True)

    def get_xrefs_count(self):
        return self.xrefsCount

    def get_called_in_count(self):
        return self.called_in_count

    def __getFormatString(self):
        tpl = "'A:%s;E:%s; N:%s;C:%s; '"
        value = tpl % (hex(self.ea), hex(self.end), self.name, str(self.get_xrefs_count()))
        return value

    def as_json(self):
        print(json.dump(self,False))


    def calls(self, coderefs=True):
        if self.call_to_status == True and self.calledCount > 0:
            return self.calls_in_xrefs

        for xref in self.coderefs_to():
            self.calledCount += 1
            name = GetFunctionName(xref)
            op = idc.GetMnem(xref).lower()
            if op == "call":
                ref_f = Fnc(xref, name, callOfFunction=self)
                self.calls_in_xrefs.append(ref_f)

        self.call_to_status = True

        return self.calls_in_xrefs




class ImportModule:
    dll_imports = None
    current_module = None
    current_module_functions = {}
    dlls_list = []
    FILE_NAME = 'address_table.p'
    imported_functions = {}

    def __init__(self, dll_names_to_ordinal=None):
        self._addressTable = {}
        if dll_names_to_ordinal is None:
            self.dll_imports = ImportModule.get_imported_dll_names()

    def get_imports_by_idanum(self, ordinal):
        idaapi.enum_import_names(ordinal, self.enumCallback)
        return self.current_module_functions

    @staticmethod
    def add_current_module_function(importFunction):
        keys = importFunction.get_keys()
        values = importFunction.get_values()
        return zip(keys, values)

    def getModulesWithApiCounts(self):
        fImports = self.get_all_imports()
        self.modules = [{x: len(fImports[x])} for x in fImports.keys()]
        return self.modules

    @staticmethod
    def get_dict_function_from(importFunction):
        keys = importFunction.get_keys()
        values = importFunction.get_values()
        return dict(zip(keys, values))

    def get_all_imports(self):
        for v, k in self.dll_imports.items():
            imports_for_dll = self.get_imports_by_dllname(v.upper())

        # print("All Imports\n", self.imported_functions)
        return self.imported_functions

    def set_dlls(self, names='wldap32, wininet, gdi32'):
        self.dlls_list = [x.strip().upper() for x in names.split(',')]
        return self.dlls_list

    def get_dlls_list(self):
        return self.dlls_list

    def analyze_imports_all(self, filterByDLL=False):
        self.get_all_imports()

        # i = [{x['module']:x['names']} for x in self.imported_functions.values()]
        # a = [x['names'] for i,x in self.imported_functions.values() if x['module'] in self.get_dlls_list()]
        modulesFilterList = None
        if filterByDLL is True:
            filterList = self.get_dlls_list()
            functions_dicts = [v for k, v in self.imported_functions.items() if k in filterList]

        else:
            functions_dicts = [v for k, v in self.imported_functions.items()]


        for import_dll in functions_dicts:
            module_imports = import_dll.items()
            print("---------------------/n\n")
            for name, fObj in module_imports:
                fObj.xrefs()

        return self.imported_functions

    def analyze_imports_module(self, dllname):
        imports = self.get_all_imports()[dllname.upper()]
        for fName in imports:
            fObj = imports[fName]
            fObj.calls()


    @staticmethod
    def pickleit(address_table):
        f = open(ImportModule.FILE_NAME,'wb')
        cPickle.dump(address_table,f,-1)
        f.close()

    @staticmethod
    def unpickle():
        f = open(ImportModule.FILE_NAME, 'rb')
        address_table = cPickle.load(f)
        f.close()
        return address_table


    def analyze_imports_function(self, fName, dllName):
        pass

    def get_imports_by_dllname(self, dllname):  # , ea, name, ordinal, idaordinal):
        self.current_module = dllname.upper()
        self.current_module_functions = {}
        # if we already imported them
        already_imported = self.imported_functions.get(self.current_module, None)
        if already_imported is not None:
            return self.imported_functions[self.current_module]

            # else check the module
        ordinal = self.dll_imports.get(self.current_module, False)
        if ordinal is False:
            print("Name with: " + dllname + " not found")

        self.get_imports_by_idanum(ordinal)
        self.imported_functions[self.current_module] = self.current_module_functions

        return self.imported_functions[self.current_module]

    @staticmethod
    def get_imported_modules_count():
        return idaapi.get_import_module_qty()

    @staticmethod
    def get_imported_dll_names():
        dlls = {}
        for idaord in range(0, ImportModule.get_imported_modules_count()):
            dllname = idaapi.get_import_module_name(idaord)
            if not dllname:
                continue
            dlls[dllname.upper()] = idaord
        return dlls

    def enumCallback(self, ea, name, ordinal):
        idaFunctionObj = FExtrn(ea, name, ordinal)
        self.current_module_functions[idaFunctionObj.name] = idaFunctionObj
        return True

    def searchFunction(self, name):
        print(self.imported_functions)

    def getFunctionsAsNameTable(self):
        imported_functions_filtered = [v for k, v in self.imported_functions.items()]
        if len(imported_functions_filtered) > 1:
            tableByName = merge_dicts(*imported_functions_filtered)
            return tableByName
        return imported_functions_filtered

    def getFunctionsAsAddressTable(self,load = False):

        if load:
            address_table = ImportModule.unpickle()
            self._addressTable = address_table
            return self._addressTable


        addressTable = {}
        imported_functions_filtered = [v for k, v in self.imported_functions.items()]

        if len(imported_functions_filtered) > 1:
            tableByName = merge_dicts(*imported_functions_filtered)
            for fobj in tableByName.values():
                fobj.xrefs()
                addressTable[fobj.ea]=fobj

            self._addressTable = addressTable
            ImportModule.pickleit(addressTable)

        return self._addressTable


class FunctionInfo_t(FExtrn):
    def __init__(self, ea, name, ordinal=0):
        FExtrn.__init__(ea, name, ordinal)


class DataManager(QObject):
    updateSignal = pyqtSignal()

    def __init__(self, parent=None):
        QtCore.QObject.__init__(self, parent=parent)
        self.currentRva = long(BADADDR)

    def setFunctionName(self, start, func_name):
        flags = idaapi.SN_NOWARN | idaapi.SN_NOCHECK
        if idc.MakeNameEx(start, func_name, flags):
            self.updateSignal.emit()
            return True
        return False

    def setCurrentRva(self, rva):
        if rva is None:
            rva = long(BADADDR)
        self.currentRva = long(rva)
        self.updateSignal.emit()

    def refreshData(self):
        self.updateSignal.emit()


class TableModel_t(QtCore.QAbstractTableModel):
    """The model for the top view: storing all the functions. """
    COL_START = 0
    COL_NAME = 1
    COL_TYPE = 2
    COL_CALLS = 3
    COL_CALLS_COUNT = 4
    columns = [COL_START, COL_NAME, COL_TYPE, COL_CALLS, COL_CALLS_COUNT]
    header_names = ['Addr', 'Name', 'Type', 'Called from', 'Call count']
    hc = dict(zip(columns, header_names))

    def _displayHeader(self, orientation, col):
        if orientation == QtCore.Qt.Vertical:
            return None
        return self.hc.get(col, None)

    def _displayData(self, row, col):
        func_info = self.imports_list.values()[row]
        if col == self.COL_START:
            return "%08x" % func_info.ea
        if col == self.COL_TYPE:
            return func_info.type
        if col == self.COL_NAME:
            return func_info.name
        if col == self.COL_CALLS:
            return func_info.get_called_in_count()
        if col == self.COL_CALLS_COUNT:
            return func_info.get_xrefs_count()
        return None

    def _displayToolTip(self, row, col):
        func_info = self.imports_list.values()[row]
        if col == self.COL_START:
            return "Double Click to follow"
        if col == self.COL_NAME:
            return "Double Click to edit"
        if col == self.COL_CALLS:
            return func_info.get_called_in_count()
        if col == self.COL_CALLS_COUNT:
            return func_info.get_xrefs_count()  # _listRefs(func_info.calls())
        return ""

    def _displayBackground(self, row, col):
        color = "khaki"
        func_info = self.imports_list.values()[row]
        if col == self.COL_START: #  or self.COL_END:
            color = "lightblue"
        if col == self.COL_NAME:
            if func_info.is_import:
                color = "orange"
        return QtGui.QColor(color)

    @staticmethod
    def _listRefs(refs_list):
        str_list = []
        for ea, ea_to in refs_list:
            s = "%08x @ %s" % (ea, FExtrn.getNameAt(ea_to))
            str_list.append(s)

        print("_listRefs", str_list)
        return '\n'.join(str_list)

    def __init__(self, imports_list, parent=None, *args):
        super(TableModel_t, self).__init__()
        self.imports_list = imports_list

    def isFollowable(self, col):
        return {self.COL_START: True}.get(col, False)

    def rowCount(self, parent):
        return len(self.imports_list)

    def columnCount(self, parent):
        return len(self.columns)

    def setData(self, index, content, role):
        if not index.isValid():
            return False
        func_info = self.imports_list[index.row()][2]
        if index.column() == self.COL_NAME:
            MakeNameEx(func_info.start, str(content), SN_NOWARN)
            g_DataManager.refreshData()
        return True

    def data(self, index, role):
        if not index.isValid():
            return None
        col = index.column()
        row = index.row()
        func_info = self.imports_list.values()[row]

        if role == QtCore.Qt.UserRole:
            # if col == self.COL_END:
            #   return func_info.end
            return func_info.start
        elif role == QtCore.Qt.DisplayRole or role == QtCore.Qt.EditRole:
            return self._displayData(row, col)
        elif role == QtCore.Qt.ToolTipRole:
            return self._displayToolTip(row, col)
        elif role == QtCore.Qt.BackgroundColorRole:
            return self._displayBackground(row, col)
        return None

    def flags(self, index):
        if not index.isValid():
            return None
        flags = QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable
        if index.column() == self.COL_NAME:
            return flags | QtCore.Qt.ItemIsEditable
        return flags

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        if role == QtCore.Qt.DisplayRole:
            return self._displayHeader(orientation, section)
        return None


class RefsTableModel_t(QtCore.QAbstractTableModel):
    """The model for the bottom view: the references to the functions.  """
    COL_NAME = 0
    COL_ADDR = 1
    COL_TOADDR = 2

    hc = {
        COL_NAME: "Name",
        COL_ADDR: "From Address",

    }

    def _displayHeader(self, orientation, col):
        """Retrieves a field description to be displayed in the header.   """
        if orientation == QtCore.Qt.Vertical:
            return None
        return self.hc.get(col, None)

    def _getTargetAddr(self, row):
        """Retrieves the address from which function was referenced, or to which it references.  """
        target_addr = BADADDR
        target_addr = self.refs_list[row]  # fromaddr
        #print("getTargetAddr", hex(addr))

        return target_addr


    def _getForeignFuncName(self, row):
        """Retrieves a name of the foreign function or the details on the referenced address.   """

        target_addr = self._getTargetAddr(row)
        if GetMnem(target_addr) != "":
            func_name = FExtrn.getNameAt(target_addr)
            if func_name:
                return func_name

        addr_str = "[%08lx]" % target_addr
        return addr_str #+ " : " + GetDisasm(target_addr)

    def _displayData(self, row, col):
        """Retrieves the data to be displayed. appropriately to the row and column.  """
        if len(self.refs_list) <= row:
            return None

        curr_ref_fromaddr = self.refs_list[row]
        if col == self.COL_ADDR:
            return hex(curr_ref_fromaddr)
        if col == self.COL_NAME:
            return GetFunctionName(curr_ref_fromaddr)
        return None

    def _getAddrToFollow(self, row, col):
        """Retrieves the address that can be followed on click. """
        addr = BADADDR
        if col == self.COL_ADDR or col==self.COL_NAME:
            addr = self.refs_list[row] #[0]
        # if col == self.COL_TOADDR:
        #     addr = self.refs_list[row] #[1]
        print("e:addrToFollow", hex(addr))
        return addr

    def _displayBackground(self, row, col):
        if self.isFollowable(col):
            return QtGui.QColor("lightblue")
        return None

    def __init__(self, imports_list, is_refs_to=True, parent=None, *args):
        super(RefsTableModel_t, self).__init__()
        self.imports_list = imports_list
        self.curr_index = (-1)
        self.refs_list = []
        self.is_refs_to = is_refs_to

    def isFollowable(self, col):
        """Is the address possible to follow in the disassembly view? """
        return {self.COL_ADDR: True, self.COL_NAME: True}.get(col, False)

    def findOffsetIndex(self, data):
        index = -1
        if self.imports_list.has_key(data):
            index = data
        print('findoffsetindex',index)
        return index


    def setCurrentIndex(self, curr_index):
        self.curr_index = curr_index
        self.refs_list = []
        current_functions = self.imports_list.get(self.curr_index,False)
        if current_functions is not False:
            self.refs_list_raw = current_functions.xrefs_raw
            refs_list = []
            for fObj in current_functions.xrefs_functions.values():
                refs_list.append(fObj.ea)
            self.refs_list = refs_list

        #pp("xrefs_raw")
        #pp(map(hex,self.refs_list_raw))
        #pp("xrefs_functions")
        #pp(self.refs_list)

        self.reset()


    def reset(self):
        self.beginResetModel()
        self.endResetModel()

    # Qt API
    def rowCount(self, parent=None):
        return len(self.refs_list)

    def columnCount(self, parent):
        return len(self.hc.items())

    def data(self, index, role):
        if not index.isValid():
            return None
        col = index.column()
        row = index.row()


        if role == QtCore.Qt.UserRole:
            if self.isFollowable(col):
                return self._getAddrToFollow(row, col)
        elif role == QtCore.Qt.DisplayRole or role == QtCore.Qt.EditRole:
            return self._displayData(row, col)
        elif role == QtCore.Qt.BackgroundColorRole:
            return self._displayBackground(row, col)
        return None

    def flags(self, index):
        if not index.isValid():
            return None
        flags = QtCore.Qt.ItemIsEnabled | QtCore.Qt.ItemIsSelectable
        return flags

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        if role == QtCore.Qt.DisplayRole:
            return self._displayHeader(orientation, section)
        return None



COLOR_NORMAL = 0xFFFFFF


class FunctionsView_t(QtWidgets.QTableView):
    """The top view: listing all the functions. """

    def _set_segment_color(self, ea, color):
        seg = idaapi.getseg(ea)
        seg.color = COLOR_NORMAL
        seg.update()

    def __init__(self, dataManager, color_hilight, func_model, parent=None):
        super(FunctionsView_t, self).__init__(parent=parent)
        self.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.prev_addr = BADADDR
        self.color_hilight = color_hilight
        self.func_model = func_model
        self.dataManager = dataManager
        self.setMouseTracking(True)
        self.setAutoFillBackground(True)

    # Qt API
    def currentChanged(self, current, previous):
        index_data = self.get_index_data(current)
        print("CurrentChanged",index_data, current)
        self.dataManager.setCurrentRva(index_data)

    def hilight_addr(self, addr):
        if self.prev_addr != BADADDR:
            ea = self.prev_addr
            self._set_segment_color(ea, COLOR_NORMAL)
            SetColor(ea, CIC_ITEM, COLOR_NORMAL)
        if addr != BADADDR:
            ea = addr
            self._set_segment_color(ea, COLOR_NORMAL)
            SetColor(addr, CIC_ITEM, self.color_hilight)
        self.prev_addr = addr

    def get_index_data(self, index):
        if not index.isValid():
            return None
        try:
            data_val = index.data(QtCore.Qt.UserRole)
            print('data_val',data_val)
            if data_val is None:
                return None
            index_data = long(data_val)
            print('index_data',index_data)
        except ValueError:
            return None
        if not type(index_data) is long:
            return None
        return index_data

    def mousePressEvent(self, event):
        event.accept()
        index = self.indexAt(event.pos())
        data = self.get_index_data(index)
        print(data)
        super(QtWidgets.QTableView, self).mousePressEvent(event)

    def mouseDoubleClickEvent(self, event):
        event.accept()
        index = self.indexAt(event.pos())
        if not index.isValid():
            return
        data = self.get_index_data(index)
        if not data:
            super(QtWidgets.QTableView, self).mouseDoubleClickEvent(event)
            return
        col = index.column()
        if self.func_model.isFollowable(col):
            self.hilight_addr(data)
            Jump(data)
        super(QtWidgets.QTableView, self).mouseDoubleClickEvent(event)

    def mouseMoveEvent(self, event):
        index = self.indexAt(event.pos())
        if not index.isValid():
            return
        col = index.column()
        if self.func_model.isFollowable(col):
            self.setCursor(QtCore.Qt.PointingHandCursor)
        else:
            self.setCursor(QtCore.Qt.ArrowCursor)

    def leaveEvent(self, event):
        self.setCursor(QtCore.Qt.ArrowCursor)

    def OnDestroy(self):
        self.hilight_addr(BADADDR)


class FunctionsMapper_t(QObject):
    """The class keeping the mapping of all the functions."""

    @staticmethod
    def listRefsTo(func_obj):
        func_refs_to = func_obj.xrefs_to()
        refs = []
        for ref in func_refs_to:
            if idc.GetMnem(ref.frm) == "":
                continue
            refs.append((ref.frm, func_obj.start))
        return refs

    def _listRefsTo(self, start):
        return self.funcList[start].xrefs()

    def _getCallingOffset(self, func, called_list):
        """Lists the offsets from where the given function references the list of other function.        """
        f = FExtrn.create_at_addr(func)
        curr, end = f.ea, f.end
        calling_list = []
        while (True):
            if curr >= end:
                break
            op = GetOperandValue(curr, 0)
            if op in called_list:
                calling_list.append((curr, op))
            curr = NextAddr(curr)
        return calling_list

    def _listRefsFrom(self, func, start, end):
        """Make a list of all the references made from the given function.

        Args:
          func : The function inside of which we are searching.
          start : The function's start offset.
          end : The function's end offset.

        Returns:
          list : A list of tuples. Each tuple represents:
            0 : the offset from where the given function referenced the other entity
            1 : the address that was referenced
        """
        f = FExtrn.create_at_addr(func)
        diff, func_name = f.get_size(), f.name
        called_list = []

        for idx in xrange(0, diff):
            addr = f.ea + idx
            func_refs_from = XrefsFrom(addr, 1)
            for ref in func_refs_from:
                if FExtrn.getNameAt(ref.to) == func_name:
                    continue
                called_list.append(ref.to)
        calling_list = self._getCallingOffset(func, called_list)
        return calling_list

    def _loadLocals(self):
        to_load = bool(ida_kernwin.ask_yn(1, "load address table?"))
        addressTable = {}
        if to_load is 1:
            addressTable = ImportModule.unpickle()
        else:
            self.imInstance.analyze_imports_all()
            addressTable = self.imInstance.getFunctionsAsAddressTable(False)

        for addr,fObj in addressTable.items():
            self._functionsMap[Fnc.va_to_rva(addr)] = fObj
        self.funcList = addressTable

    def __init__(self, parent=None):
        super(FunctionsMapper_t, self).__init__(parent=parent)
        self._functionsMap = dict()
        self.imInstance = ImportModule()
        self.funcList = {}  # public
        self._loadLocals()

    def funcAt(self, rva):
        func_info = self._functionsMap[rva]
        return func_info


class FunctionsListForm_t(PluginForm):
    """The main form of the IFL plugin. """

    _COLOR_HILIGHT_FUNC = 0xFFDDBB  # BBGGRR
    _COLOR_HILIGHT_REFTO = 0xBBFFBB
    _COLOR_HILIGHT_REFFROM = 0xDDBBFF
    _LIVE_FILTER = True


    @staticmethod
    def _listFunctionsAddr():
        return ImportModule().analyze_imports_all(False)

    def _setup_sorted_model(self, view, model):
        """Connects the given sorted data model with the given view. """
        sorted_model = QtCore.QSortFilterProxyModel()
        sorted_model.setDynamicSortFilter(True)
        sorted_model.setSourceModel(model)
        view.setModel(sorted_model)
        view.setSortingEnabled(True)
        sorted_model.setParent(view)
        model.setParent(sorted_model)
        return sorted_model

    def _update_current_offset(self, view, refs_model, offset):
        """Update the given data model to follow given offset. """
        if offset:
            index = refs_model.findOffsetIndex(offset)
        else:
            index = (-1)

        refs_model.setCurrentIndex(index)
        refs_model.reset()
        view.reset()
        view.repaint()

    def _update_function_name(self, ea):
        """Sets on the displayed label the name of the function and it's arguments."""
        try:
            f = FExtrn.create_at_addr(FExtrn.va_to_rva(ea))
            self.refs_label.setText(f.type + " <b>" + f.name + "</b> " + f.getArgsDescription())
        except KeyError:
            return

    def _update_ref_tabs(self, ea):
        """Sets on the tabs headers the numbers of references to the selected function.        """
        tocount, fromcount = 0, 0
        try:
            func_info = self.funcMapper.funcList[ea]
            #func_info = FExtrn.create_at_addr(Fnc.va_to_rva(ea))
            func_info.xrefs()
            fromcount = func_info.xrefsCount
        except KeyError:
            pass
        self.refs_tabs.setTabText(0, "Is refered by %d:" % fromcount)


    def adjustColumnsToContents(self):
        self.addr_view.resizeColumnToContents(0)
        self.addr_view.resizeColumnToContents(1)
        self.addr_view.resizeColumnToContents(2)
        self.addr_view.resizeColumnToContents(5)
        self.addr_view.resizeColumnToContents(6)
        self.addr_view.resizeColumnToContents(7)

    # public
    # @pyqtSlot()
    def longoperationcomplete(self):
        """A callback executed when the current RVA has changed.      """
        data = g_DataManager.currentRva
        self.setRefOffset(data)

    def setRefOffset(self, data):
        """Updates the views to follow to the given RVA.  """
        if not data:
            return
        self._update_current_offset(self.refs_view, self.refsto_model, data)
        #self._update_current_offset(self.refsfrom_view, self.refsfrom_model, data)

        self._update_ref_tabs(data)
        self._update_function_name(data)

    def filterByColumn(self, col_num, str):
        """Applies a filter defined by the string on data model.  """

        filter_type = QtCore.QRegExp.FixedString
        sensitivity = QtCore.Qt.CaseInsensitive
        if self.criterium_id != 0:
            filter_type = QtCore.QRegExp.RegExp
        self.addr_sorted_model.setFilterRegExp(QtCore.QRegExp(str, sensitivity, filter_type))
        self.addr_sorted_model.setFilterKeyColumn(col_num)

    def filterChanged(self):
        """A wrapper for the function: filterByColumn(self, col_num, str)  """
        self.filterByColumn(self.filter_combo.currentIndex(), self.filter_edit.text())

    def filterKeyEvent(self, event=None):
        if event != None:
            QtWidgets.QLineEdit.keyReleaseEvent(self.filter_edit, event)
        if event and (
                self.is_livefilter == False and event.key() != QtCore.Qt.Key_Enter and event.key() != QtCore.Qt.Key_Return):
            return
        self.filterChanged()

    def criteriumChanged(self):
        self.criterium_id = self.criterium_combo.currentIndex()
        if self.criterium_id == 0:
            text = "keyword"
        else:
            text = "regex"
        self.filter_edit.setPlaceholderText(text)

    def liveSearchCheckBox(self):
        self.is_livefilter = self.livefilter_box.isChecked()
        if self.is_livefilter:
            self.filterByColumn(self.filter_combo.currentIndex(), self.filter_edit.text())

    def OnCreate(self, form):
        # init data structures:
        self.funcMapper = FunctionsMapper_t()
        self.criterium_id = 0

        self.parent = self.FormToPyQtWidget(form)

        # Create models
        self.subDataManager = DataManager()
        self.table_model = TableModel_t(self.funcMapper.funcList)

        # init
        self.addr_sorted_model = QtCore.QSortFilterProxyModel()
        self.addr_sorted_model.setDynamicSortFilter(True)
        self.addr_sorted_model.setSourceModel(self.table_model)
        self.addr_view = FunctionsView_t(g_DataManager, self._COLOR_HILIGHT_FUNC, self.table_model)
        self.addr_view.setModel(self.addr_sorted_model)
        self.addr_view.setSortingEnabled(True)
        self.addr_view.setWordWrap(False)
        self.addr_view.setAlternatingRowColors(True)
        self.addr_view.horizontalHeader().setStretchLastSection(False)
        self.addr_view.verticalHeader().show()

        self.adjustColumnsToContents()
        #
        self.refsto_model = RefsTableModel_t(self.funcMapper.funcList, True)
        self.refs_view = FunctionsView_t(self.subDataManager, self._COLOR_HILIGHT_REFTO, self.refsto_model)
        self._setup_sorted_model(self.refs_view, self.refsto_model)
        #self.refs_view.setColumnHidden(RefsTableModel_t.COL_TOADDR, True)
        self.refs_view.setWordWrap(False)
        self.refs_view.setAlternatingRowColors(True)

        font = self.refs_view.font()
        font.setPointSize(8)
        self.refs_view.setFont(font)
        self.refsfrom_model = RefsTableModel_t(self.funcMapper.funcList, False)
        self.refsfrom_view = FunctionsView_t(self.subDataManager, self._COLOR_HILIGHT_REFFROM, self.refsfrom_model)
        self._setup_sorted_model(self.refsfrom_view, self.refsfrom_model)
        #self.refsfrom_view.setColumnHidden(RefsTableModel_t.COL_TOADDR, True)
        self.refsfrom_view.setWordWrap(False)
        self.refsfrom_view.setAlternatingRowColors(True)

        # add a box to enable/disable live filtering
        # self.livefilter_box = QtWidgets.QCheckBox("Live filtering")
        # self.livefilter_box.setToolTip(
        #    "If live filtering is enabled, functions are searched as you type in the edit box.\nOtherwise they are searched when you press Enter.")
        # self.livefilter_box.setChecked(self._LIVE_FILTER)
        # self.is_livefilter = self._LIVE_FILTER
        # connect SIGNAL
        # self.livefilter_box.stateChanged.connect(self.liveSearchCheckBox)

        # important for proper order of objects destruction:
        self.table_model.setParent(self.addr_sorted_model)
        self.addr_sorted_model.setParent(self.addr_view)

        # connect SIGNAL
        g_DataManager.updateSignal.connect(self.longoperationcomplete)

        # Create a Tab widget for references:
        self.refs_tabs = QtWidgets.QTabWidget()
        self.refs_tabs.insertTab(0, self.refs_view, "Is refered by")
        self.refs_tabs.insertTab(1, self.refsfrom_view, "Refers to")

        # Create filter
        self.filter_edit = QtWidgets.QLineEdit()
        self.filter_edit.setPlaceholderText("keyword")
        self.filter_edit.keyReleaseEvent = self.filterKeyEvent

        self.filter_combo = QtWidgets.QComboBox()
        self.filter_combo.addItems(TableModel_t.header_names)
        self.filter_combo.setCurrentIndex(TableModel_t.COL_NAME)
        # connect SIGNAL
        self.filter_combo.activated.connect(self.filterChanged)

        self.criterium_combo = QtWidgets.QComboBox()
        criteria = ["contains", "matches"]
        self.criterium_combo.addItems(criteria)
        self.criterium_combo.setCurrentIndex(0)
        # connect SIGNAL
        self.criterium_combo.activated.connect(self.criteriumChanged)

        filter_panel = QtWidgets.QFrame()
        filter_layout = QtWidgets.QHBoxLayout()
        filter_layout.addWidget(QtWidgets.QLabel("Where "))
        filter_layout.addWidget(self.filter_combo)
        filter_layout.addWidget(self.criterium_combo)
        filter_layout.addWidget(self.filter_edit)

        filter_panel.setLayout(filter_layout)
        self.filter_edit.setFixedHeight(20)
        filter_panel.setFixedHeight(40)
        filter_panel.setAutoFillBackground(True)

        #
        self.refs_label = QtWidgets.QLabel("Function")
        self.refs_label.setTextFormat(QtCore.Qt.RichText)
        self.refs_label.setWordWrap(True)

        panel1 = QtWidgets.QFrame()
        layout1 = QtWidgets.QVBoxLayout()
        panel1.setLayout(layout1)

        layout1.addWidget(filter_panel)
        # layout1.addWidget(self.livefilter_box)
        layout1.addWidget(self.addr_view)
        layout1.setContentsMargins(0, 0, 0, 0)

        panel2 = QtWidgets.QFrame()
        layout2 = QtWidgets.QVBoxLayout()
        layout2.addWidget(self.refs_label)
        layout2.addWidget(self.refs_tabs)
        # layout2.addWidget(self._makeButtonsPanel())
        layout2.setContentsMargins(0, 10, 0, 0)
        panel2.setLayout(layout2)

        self.main_splitter = QtWidgets.QSplitter()
        self.main_splitter.setOrientation(QtCore.Qt.Vertical)
        self.main_splitter.addWidget(panel1)
        self.main_splitter.addWidget(panel2)

        # Populate PluginForm
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.main_splitter)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        self.parent.setLayout(layout)

        idaapi.set_dock_pos(PLUGIN_NAME, "IDA HExview-1", idaapi.DP_RIGHT)

    def OnClose(self, form):
        # clear last selection
        self.addr_view.hilight_addr(BADADDR)
        self.refs_view.hilight_addr(BADADDR)
        self.refsfrom_view.hilight_addr(BADADDR)
        del self
        print "Closed"

    def Show(self):
        return PluginForm.Show(self, PLUGIN_NAME, options=PluginForm.FORM_PERSIST)


def open_form():
    global m_functionInfoForm
    global g_DataManager
    try:
        g_DataManager
    except:
        g_DataManager = DataManager()
    try:
        m_functionInfoForm
    except:
        idaapi.msg("%s\nLoading Interactive Imports List...\n" % VERSION_INFO)
        m_functionInfoForm = FunctionsListForm_t()

    m_functionInfoForm.Show()


class MenuHandler(action_handler_t):
    def __init__(self):
        action_handler_t.__init__(self)

    @staticmethod
    def init_menu_actions(actions):
        [register_action(action_desc_t(*params)) for params in
         [(menu_key, PLUGIN_NAME, MenuHandler()) for menu_key in actions]]
        map(lambda action: attach_action_to_menu('View/', action, idaapi.SETMENU_APP), actions)

    def activate(self, ctx):
        open_form()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class AwesomeImports(plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Interactive Imports List"
    help = "Interactive Imports List. Comments? Remarks? Mail to: hasherezade@gmail.com"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ''
    menu_key = 'awsmimp:open'
    params = (menu_key, PLUGIN_NAME, MenuHandler())

    def init(self):
        MenuHandler.init_menu_actions(['awsmimp:open','awsmimp:hola'])
        return idaapi.PLUGIN_OK

    def run(self, arg):
        open_form()
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():
    return AwesomeImports()


if __name__ == "__main__":
    PLUGIN_ENTRY()
