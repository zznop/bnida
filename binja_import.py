#!/usr/bin/env python
#  Copyright (c) 2015-2017 Vector 35 LLC
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

from binaryninja.binaryview import BinaryViewType
from binaryninja.types import (Type, Symbol)
from binaryninja.enums import (SymbolType, IntegerDisplayType, InstructionTextTokenType)
from binaryninja.plugin import PluginCommand
from binaryninja.plugin import BackgroundTaskThread
from binaryninja.interaction import (ChoiceField, OpenFileNameField, get_form_input)
from binaryninja.log import log_error


def log(message, verbose):
    if task is None:
        if verbose:
            print message
    else:
        task.progress = message


def import_ida(json_file, bv, options):
    if json_file is None:
        return False, "No json file specified"

    imported = None

    try:
        f = open(json_file, "rb")
        imported = json.load(f)
    except Exception as e:
        return False, "Failed to parse json file {} {}".format(json_file, e)

    resolved_functions = imported["functions"]
    resolved_strings = imported["strings"]

    # TODO: import segments
    # TODO: Handle Conflicts

    if options.import_functions:
        log("Applying import data", options.verbose)
        for name, rec in resolved_functions.items():
            bv.add_function(rec["start"])
            func = bv.get_function_at(rec["start"])
            if name != ("sub_%x" % rec["start"]):
                func.name = name

            if options.import_comments:
                if "comment" in rec:
                    func.comment = rec["comment"]

                if "comments" in rec:
                    for comment, addr in rec["comments"].items():
                        func.set_comment_at(addr, comment)

            if "can_return" in rec:
                func.can_return = rec["can_return"]

        bv.update_analysis_and_wait()

    if options.import_strings:
        log("Importing string types", options.verbose)
        for addr, (name, length, t, data_refs) in resolved_strings.items():
            bv.define_user_data_var(int(addr), Type.array(Type.int(1, None, "char"), length))
            if options.import_strings_names:
                bv.define_user_symbol(Symbol(SymbolType.DataSymbol, int(addr), name))
            for ref in data_refs:  # references to this data
                for block in bv.get_basic_blocks_at(ref):  # find any references in code
                    for i in block.get_disassembly_text():  # go through all the instructions in the block
                        if i.address == ref:
                            for token in i.tokens:
                                if token.type == InstructionTextTokenType.PossibleAddressToken:
                                    print "setting token", i.address, token.value, token.operand, IntegerDisplayType.PointerDisplayType, block.arch
                                    block.function.set_int_display_type(i.address, token.value, token.operand, IntegerDisplayType.PointerDisplayType, block.arch)
                                    break

    log("Updating Analysis", options.verbose)
    bv.update_analysis_and_wait()
    return True, None


class GetOptions:
    def __init__(self, interactive=False):
        if interactive:
            import_strings_choice = ChoiceField("Import Strings", ["Yes", "No"])
            import_string_name_choice = ChoiceField("Import String Names", ["Yes", "No"])
            import_function_choice = ChoiceField("Import Functions", ["Yes", "No"])
            import_comment_choice = ChoiceField("Import Comments", ["Yes", "No"])
            json_file = OpenFileNameField("Import json file")
            get_form_input([json_file, import_strings_choice, import_string_name_choice, import_function_choice, 
                import_comment_choice], "IDA Import Options")

            self.import_strings = import_strings_choice.result == 0
            self.import_strings_names = import_string_name_choice.result == 0
            self.import_functions = import_function_choice.result == 0
            self.import_comments = import_comment_choice.result == 0
            self.verbose = True
            if json_file.result == '':
                self.json_file = None
            else:
                self.json_file = json_file.result
            self.output_name = None
        else:
            usage = "usage: %prog [options] <ida_export.json> <file|bndb>"
            parser = OptionParser(usage=usage)

            parser.add_option("-q", "--quiet",
                dest="verbose",
                action="store_false",
                default=True,
                help="Don't display automatic actions")
            parser.add_option("-s", "--no-strings",
                dest="import_strings",
                action="store_false",
                default=True,
                help="Don't import string data")
            parser.add_option("-n", "--no-string-names",
                dest="import_strings_names",
                action="store_false",
                default=True,
                help="Don't import string names")
            parser.add_option("-o", "--output-name",
                dest="output_name",
                action="store",
                default=None,
                help="Specify output name of bndb. Defaults to <file_name>.bndb")
            parser.add_option("-f", "--no-functions",
                dest="import_functions",
                action="store_false",
                default=True,
                help="Don't import function starts")
            parser.add_option("-c", "--no-comments",
                dest="import_comments",
                action="store_false",
                default=True,
                help="Don't import comments")

            (options, args) = parser.parse_args()
            self.import_strings = options.import_strings
            self.import_strings_names = options.import_strings_names
            self.import_functions = options.import_functions
            self.import_comments = options.import_comments
            self.verbose = options.verbose
            self.json_file = args[0]
            self.input_file = args[0]
            self.output_name = options.output_name
            if self.output_name is None:
                self.output_name = self.input_file + ".bndb"
            self.usage = parser.get_usage()


def main():
    options = GetOptions()
    if options.json_file is None or options.output_name is None:
        print options.usage
        return

    log("Loading the binary: {}".format(options.input_file), options)

    bv = BinaryViewType.get_view_of_file(options.input_file)
    if bv is None:
        print "Could not open {}".format(options.input_file)
        return False

    (success, error_message) = import_ida(options.json_file, bv, options.output_name, options)
    if not success:
        print "Error:", error_message
        print options.usage
        return

    log("Writing out {}".format(options.output_name), options.verbose)
    bv.create_database(options.output_name)
    return


class ImportIDAInBackground(BackgroundTaskThread):
    def __init__(self, bv, options):
        global task
        BackgroundTaskThread.__init__(self, "Importing data from IDA", False)
        self.json_file = options.json_file
        self.options = options
        self.bv = bv
        task = self

    def run(self):
        (success, error_message) = import_ida(self.options.json_file, self.bv, self.options)
        if not success:
            log_error(error_message)


def import_ida_in_background(bv):
    options = GetOptions(True)
    background_task = ImportIDAInBackground(bv, options)
    background_task.start()


if __name__ == "__main__":
    main()
else:
    PluginCommand.register("Import data from IDA", "Import data from IDA", import_ida_in_background)
