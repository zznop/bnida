"""
Exports analysis data from a Binary Ninja database to a bnida JSON file
"""

import json
from binaryninja import (SaveFileNameField, get_form_input,
                         BackgroundTaskThread, types, log_debug, log_info)
from collections import OrderedDict


class GetOptions(object):
    """
    This class handles user input to specify the path to the JSON file
    """

    def __init__(self):
        json_file = SaveFileNameField('Export JSON file')
        get_form_input([json_file], 'Options')
        if json_file.result == '':
            self.json_file = None
        else:
            self.json_file = json_file.result


class ExportInBackground(BackgroundTaskThread):
    """
    This class exports data to the bnida JSON file
    """

    def __init__(self, bv, options):
        global task
        BackgroundTaskThread.__init__(self, 'Exporting data from BN', False)
        self.json_file = options.json_file
        self.options = options
        self.bv = bv
        task = self

    def get_sections(self):
        sections = {}
        for section_name in self.bv.sections:
            section = self.bv.get_section_by_name(section_name)
            sections[section.name] = {
                'start': section.start,
                'end': section.end
            }

        return sections

    def get_names(self):
        symbols = {}
        for symbol in self.bv.get_symbols():
            symbols[symbol.address] = symbol.name
        return symbols

    def get_functions(self):
        functions = []
        for func in self.bv.functions:
            functions.append(func.start)
        return functions

    def get_function_comments(self):
        comments = {}
        for func in self.bv:
            if func.comment:
                comments[func.start] = func.comment

        return comments

    def get_line_comments(self):
        comments = {}
        for addr in self.bv.address_comments:
            comments[addr] = self.bv.get_comment_at(addr)

        for func in self.bv:
            for addr in func.comments:
                comments[addr] = func.get_comment_at(addr)

        return comments

    def get_structures(self):
        structures = OrderedDict()
        for type_name, vtype in self.bv.types:
            if isinstance(vtype, types.StructureType):
                struct_name = str(type_name)
                members = {}
                for member in vtype.members:
                    members[member.name] = {}
                    members[member.name]['offset'] = member.offset
                    members[member.name]['size'] = member.type.width
                    members[member.name]['type'] = ''
                    for token in member.type.tokens:
                        members[member.name]['type'] += str(token)
                structures[struct_name] = {}
                structures[struct_name]['size'] = vtype.width
                structures[struct_name]['members'] = members
        return structures

    def run(self):
        log_info('Exporting analysis data to {}'.format(
            self.options.json_file))
        json_array = {}

        log_debug("Exporting sections")
        json_array['sections'] = self.get_sections()

        log_debug("Exporting names")
        json_array['names'] = self.get_names()

        log_debug("Exporting functions")
        json_array['functions'] = self.get_functions()

        log_debug("Exporting function comments")
        json_array['func_comments'] = self.get_function_comments()

        log_debug("Exporting line comments")
        json_array['line_comments'] = self.get_line_comments()

        log_debug("Exporting structs")
        json_array['structs'] = self.get_structures()

        with open(self.options.json_file, 'w+') as f:
            json.dump(json_array, f, indent=4)

        log_info('Done exporting analysis data')


def export_data_in_background(bv):
    options = GetOptions()
    background_task = ExportInBackground(bv, options)
    background_task.start()
