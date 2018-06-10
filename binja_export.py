"""binja_export.py: exports analysis data from a BN database to a json file"""

__author__      = "zznop"
__copyright__   = "Copyright 2018, zznop0x90@gmail.com"
__license__     = "WTFPL"

import json
from optparse import OptionParser
from binaryninja import *

class GetOptions:
    def __init__(self):
        json_file = SaveFileNameField("Export json file")
        get_form_input([json_file], "BN Export Options")
        if json_file.result == '':
            self.json_file = None
        else:
            self.json_file = json_file.result

class ExportBNInBackground(BackgroundTaskThread):
    def __init__(self, bv, options):
        global task
        BackgroundTaskThread.__init__(self, "Exporting data from BN", False)
        self.json_file = options.json_file
        self.options   = options
        self.bv        = bv
        task           = self

    def run(self):
        (success, error_message) = export_bn(self.options.json_file, self.bv)
        if not success:
            log_error(error_message)

def get_functions(bv):
    """Populate dictionary of function names and offsets
    """
    functions = {}
    for func in bv.functions:
        functions[func.start] = func.name
    return functions

def get_symbols(bv):
    """Populate dictionary of symbol names
    """
    symbols = {}
    for symbol in bv.get_symbols():
        symbols[symbol.address] = symbol.name
    return symbols

def get_comments(bv):
    """Populate dictionary of comments
    """
    comments = {}
    for func in bv:
        current_function = {}
        current_function["comment"] = func.comment
        current_function["comments"] = {}
        for addr in func.comments:
            current_function["comments"][addr] = func.get_comment_at(addr)
        comments[func.start] = current_function

    return comments

def get_sections(bv):
    """Populate dictionary of sections
    """
    sections = {}
    for section_name in bv.sections:
        section = bv.get_section_by_name(section_name)
        sections[section.name] = {
            'start' : section.start,
            'end' : section.end
        }

    return sections

def export_bn(json_file, bv):
    """Construct json array of everything we want to export
    """
    json_array              = {}
    json_array["sections"]  = get_sections(bv)
    json_array["names"]     = get_symbols(bv)
    json_array["comments"]  = get_comments(bv)

    try:
        with open(json_file, "wb+") as f:
            f.write(json.dumps(json_array, indent=4))
    except Exception as ex:
        return False, "Failed to create JSON file {} {}".format(json_file, ex)

    return True, None

def export_bn_in_background(bv):
    """Export data in background from BN UI
    """
    options = GetOptions()
    background_task = ExportBNInBackground(bv, options)
    background_task.start()

PluginCommand.register("Export data from BN", "Export data from BN", export_bn_in_background)
