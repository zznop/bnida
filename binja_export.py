#!/usr/bin/env python
#
# Copyright (c) 2018 zznop
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

import json
from optparse import OptionParser
from binaryninja import *

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
        for addr in func.comments:
            comments[addr] = func.get_comment_at(addr)
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
        with open(json_file, "wb") as f:
            f.write(json.dumps(json_array, indent=4))
    except Exception as ex:
        return False, "Failed to create JSON file {} {}".format(json_file, ex)

    return True, None

class GetOptions:
    def __init__(self, interactive=False):
        # from BN UI
        if interactive:
            json_file = OpenFileNameField("Export json file")
            get_form_input([json_file], "BN Export Options")
            if json_file.result == '':
                self.json_file = None
            else:
                self.json_file = json_file.result
            return 

        # headless
        usage            = "usage: %prog <bn_database.bndb> <ida_export.json>"
        parser           = OptionParser(usage=usage)
        (options, args)  = parser.parse_args()
        self.bn_database = args[0]
        self.json_file   = args[1]
        self.usage       = parser.get_usage()

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

def export_bn_headless():
    """Export data running as headless script
    """
    options = GetOptions(False)
    bv = BinaryViewType.get_view_of_file(options.bn_database)
    bv.update_analysis_and_wait()
    (success, error_message) = export_bn(options.json_file, bv)
    if not success:
        print "Error: {}".format(error_message)

def export_bn_in_background(bv):
    """Export data in background from BN UI
    """
    options = GetOptions(True)
    background_task = ExportBNInBackground(bv, options)
    background_task.start()

if __name__ == '__main__':
    export_bn_headless()
else:
    PluginCommand.register("Export data from BN", "Export data from BN", export_bn_in_background)
