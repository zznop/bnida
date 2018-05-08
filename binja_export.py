#!/usr/bin/env python
#  Copyright (c) 2018 zznop
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
import sys

def get_functions(bv):
    """Populate dictionary with function names and offsets
    """
    functions = {}
    for func in bv.functions:
        functions[func.start] = func.name
    return functions

def get_symbols(bv):
    """Populate dictionary of symbol names
    """
    symbols = bv.get_symbols()
    for symbol in symbols:
        print symbol.name


def populate_json_array(bv):
    """Construct json array of everything we want to export
    """
    json_array              = {}
    json_array["functions"] = get_functions(bv)
    json_array["names"]     = {}
    json_array["segments"]  = {}
    json_array["strings"]   = get_symbols(bv)
    return json_array

def main():
    bv = BinaryViewType.get_view_of_file(sys.argv[1])
    bv.update_analysis_and_wait()
    json_array = populate_json_array(bv)
    print json_array

if __name__ == '__main__':
    main()

