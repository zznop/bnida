"""binja_import.py: imports analysis data into a BN databsae from a json file"""

__author__      = "zznop"
__copyright__   = "Copyright 2018, zznop0x90@gmail.com"
__license__     = "WTFPL"

import json
from binaryninja import *

class GetOptions:
    def __init__(self):
        json_file = OpenFileNameField("Import json file")
        get_form_input([json_file], "BN Import Options")
        if json_file.result == '':
            self.json_file = None
        else:
            self.json_file = json_file.result

class ImportIDAInBackground(BackgroundTaskThread):
    def __init__(self, bv, options):
        global task
        BackgroundTaskThread.__init__(self, "Importing data from IDA", False)
        self.json_file = options.json_file
        self.bv = bv
        self.options = options

    def run(self):
        (success, error_message) = import_ida(self.options.json_file, self.bv)
        if not success:
            log_error(error_message)

def base_addr_off_section(sections, bv, addr):
    """Adjust the address if there are differences in section base addresses
    """
    ida_section_start = None
    section_name = None
    for name, section in sections.iteritems():
        if addr >= int(section["start"]) and addr <= int(section["end"]):
            ida_section_start = int(section["start"])
            section_name = name
            break

    # make sure the section was found (this check should always pass)
    if section_name is None:
        print "Section not found in IDA analysis data for addr: {:08x}".format(addr)
        return None

    # retrieve section start in BN
    bn_section = bv.get_section_by_name(section_name)
    if bn_section is None:
        print "Section not found in BN - name:{} addr:{:08x}".format(section_name, addr)
        return None

    # adjust if needed
    return addr - ida_section_start + bn_section.start

def open_json_file(json_file):
    """Open the json file and load the json object
    """
    json_array = None
    if json_file is None:
        return json_array, "No json file specified"
    
    try:
        f = open(json_file, "rb")
        json_array = json.load(f)
    except Exception as e:
        return json_array, "Failed to parse json file {} {}".format(json_file, e)

    return json_array

def set_symbols(bv, names, sections):
    """Set IDA symbol names in BN database
    """
    for addr, name in names.iteritems():
        addr = base_addr_off_section(sections, bv, int(addr))
        if addr is None:
            continue

        bv.define_user_symbol(Symbol(SymbolType.DataSymbol, addr, name))

def set_comments(bv, comments, sections):
    """Set IDA comments in BN database
    """
    for func_addr, current_function in comments.iteritems():
        func_addr = base_addr_off_section(sections, bv, int(func_addr))
        if func_addr is None:
            continue

        func = bv.get_function_at(func_addr)

        # Make a function if it doesn't exist
        if func is None:
            bv.add_function(func_addr)
            func = bv.get_function_at(func_addr)
            if func is None:
                continue

        func.comment = current_function["comment"]
        for addr, instr_comment in current_function["comments"].iteritems():
            addr = base_addr_off_section(sections, bv, int(addr))
            if addr is None:
                continue

            func.set_comment_at(addr, instr_comment)

def import_ida(json_file, bv):
    """Import IDA analysis data into BN database
    """
    json_array = open_json_file(json_file)
    if json_array is None:
        return False

    # set function and instruction comments
    set_comments(bv, json_array["comments"], json_array["sections"])

    # set symbol names
    set_symbols(bv, json_array["names"], json_array["sections"])

    bv.update_analysis_and_wait()
    return True, None

def import_ida_in_background(bv):
    """Import IDA analysis data in background thread
    """
    options = GetOptions()
    background_task = ImportIDAInBackground(bv, options)
    background_task.start()

PluginCommand.register("Import data from IDA", "Import data from IDA", import_ida_in_background)
