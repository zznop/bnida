"""
Exports analysis data from a BN database to a bnida JSON file
"""

import json
from binaryninja import (SaveFileNameField, get_form_input,
                         BackgroundTaskThread, types)
from binaryninja.log import Logger
from collections import OrderedDict

logger = Logger(session_id=0, logger_name=__name__)


class GetOptions(object):

    def __init__(self):
        json_file = SaveFileNameField('Export json file')
        get_form_input([json_file], 'BN Export Options')
        if json_file.result == '':
            self.json_file = None
        else:
            self.json_file = json_file.result


class ExportInBackground(BackgroundTaskThread):

    def __init__(self, bv, options):
        global task
        BackgroundTaskThread.__init__(self, 'Exporting data from BN', False)
        self.json_file = options.json_file
        self.options = options
        self.bv = bv
        task = self

    def get_sections(self):
        """
        Export sections

        :return: Dict containing section info
        """

        sections = {}
        for section_name in self.bv.sections:
            section = self.bv.get_section_by_name(section_name)
            sections[section.name] = {
                'start': section.start,
                'end': section.end
            }

        return sections

    def get_names(self):
        """
        Export symbols

        :return: Dict containing symbol info
        """

        symbols = {}
        for symbol in self.bv.get_symbols():
            symbols[symbol.address] = symbol.name
        return symbols

    def get_functions(self):
        """
        Export functions

        :return: Dict containing function info
        """

        functions = []
        for func in self.bv.functions:
            functions.append(func.start)
        return functions

    def get_function_comments(self):
        """
        Export function comments

        :return: Dict containing function comments
        """

        comments = {}
        for func in self.bv:
            if func.comment:
                comments[func.start] = func.comment

        return comments

    def get_line_comments(self):
        """
        Export line comments

        :return: Dict containing line comments
        """
        comments = {}
        for addr in self.bv.address_comments:
            comments[addr] = self.bv.get_comment_at(addr)

        for func in self.bv:
            for addr in func.comments:
                comments[addr] = func.get_comment_at(addr)

        return comments

    def get_structures(self):
        """
        Export structures/types

        :return: Dict containing structure info
        """

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
        """
        Export analysis data to bnida JSON file
        """
        logger.log_info('[*] Exporting analysis data to {}'.format(
            self.options.json_file))
        json_array = {}

        logger.log_debug("Exporting sections")
        json_array['sections'] = self.get_sections()

        logger.log_debug("Exporting names")
        json_array['names'] = self.get_names()

        logger.log_debug("Exporting functions")
        json_array['functions'] = self.get_functions()

        logger.log_debug("Exporting function comments")
        json_array['func_comments'] = self.get_function_comments()

        logger.log_debug("Exporting line comments")
        json_array['line_comments'] = self.get_line_comments()

        logger.log_debug("Exporting structs")
        json_array['structs'] = self.get_structures()

        with open(self.options.json_file, 'w+') as f:
            json.dump(json_array, f, indent=4)

        logger.log_info('[+] Done exporting analysis data')


def export_data_in_background(bv):
    """
    Export data in background from BN UI
    """

    options = GetOptions()
    background_task = ExportInBackground(bv, options)
    background_task.start()
