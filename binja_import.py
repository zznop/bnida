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

def set_symbols(bv, names):
    """Set IDA symbol names in BN database
    """
    for addr, name in names.iteritems():
        bv.define_user_symbol(Symbol(SymbolType.DataSymbol, int(addr), name))

def set_comments(bv, comments):
    """Set IDA comments in BN database
    """
    for func_addr, current_function in comments.iteritems():
        func = bv.get_function_at(int(func_addr))
        if func is None:
            bv.add_function(int(func_addr))
            func = bv.get_function_at(int(func_addr))

        func.comment = current_function["comment"]
        for addr, instr_comment in current_function["comments"].iteritems():
            func.set_comment_at(int(addr), instr_comment)

def import_ida(json_file, bv):
    """Import IDA analysis data into BN database
    """
    json_array = open_json_file(json_file)
    if json_array is None:
        return False

    # set function and instruction comments
    set_comments(bv, json_array["comments"])

    # set symbol names
    set_symbols(bv, json_array["symbols"])

    bv.update_analysis_and_wait()
    return True, None

def import_ida_in_background(bv):
    """Import IDA analysis data in background thread
    """
    options = GetOptions()
    background_task = ImportIDAInBackground(bv, options)
    background_task.start()

PluginCommand.register("Import data from IDA", "Import data from IDA", import_ida_in_background)
