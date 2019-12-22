import json
from binaryninja import *

"""
Imports analysis data from a bnida json file into a Binary Ninja database
"""

__author__      = 'zznop'
__copyright__   = 'Copyright 2018, zznop0x90@gmail.com'
__license__     = 'WTFPL'


class GetOptions(object):
    """
    This class handles user input to specify path to JSON file
    """

    def __init__(self):
        json_file = OpenFileNameField('Import json file')
        get_form_input([json_file], 'BN Import Options')
        if json_file.result == '':
            self.json_file = None
        else:
            self.json_file = json_file.result


class ImportInBackground(BackgroundTaskThread):
    """
    This class imports the data into the BN database
    """

    def __init__(self, bv, options):
        global task
        BackgroundTaskThread.__init__(self, 'Importing data from bnida JSON file', False)
        self.json_file = options.json_file
        self.bv = bv
        self.options = options

    def adjust_addr(self, sections, addr):
        """
        Adjust the address if there are differences in section base addresses

        :param sections: Dictionary of sections
        :param addr: Address
        :return: Base address of section
        """

        section_start = None
        section_name = None
        for name, section in sections.items():
            if addr >= int(section['start']) and addr <= int(section['end']):
                section_start = int(section['start'])
                section_name = name
                break

        # Make sure the section was found (this check should always pass)
        if section_name is None:
            print('Section not found in analysis data for addr: {:08x}'.format(addr))
            return None

        # Retrieve section start in BN
        bn_section = self.bv.get_section_by_name(section_name)
        if bn_section is None:
            print('Section not found in BN - name:{} addr:{:08x}'.format(section_name, addr))
            return None

        # Adjust if needed
        return addr - section_start + bn_section.start

    def open_json_file(self, json_file):
        """
        Open and load the json file

        :param json_file: Path to JSON file
        :return: Dictionary of JSON file content
        """

        f = open(json_file, 'rb')
        return json.load(f)

    def import_functions(self, functions, sections):
        """
        Create functions from bnida analysis data

        :param functions: Array of function addrs
        :param sections: Dictonary of sections
        """

        for addr in functions:
            addr = self.adjust_addr(sections, int(addr))
            if addr is None:
                continue

            if self.bv.get_function_at(addr) is None:
                self.bv.add_function(addr)

    def import_function_comments(self, comments, sections):
        """
        Import function comments into BN database

        :param comments: Dictionary of function comments
        :param sections: Dictionary of sections
        """

        for addr, comment in comments.items():
            addr = self.adjust_addr(sections, int(func_addr))
            if addr is None:
                continue

            func = self.bv.get_function_at(addr)
            if func is None:
                continue

            func.comment = comment

    def import_line_comments(self, comments, sections):
        """
        Import line comments into BN database

        :param comments: Dictionary of line comments
        :param sections: Dictionary of sections
        """

        for addr, comment in comments.items():
            addr = self.adjust_addr(sections, int(addr))
            if addr is None:
                continue

            self.bv.set_comment_at(addr, comment)

    def import_structures(self, structs):
        """
        Import structures into BN database

        :param structs: Dictionary of structures
        """

        for struct_name, struct_info in structs.items():
            struct = types.Structure()
            for member_name, member_info in struct_info['members'].items():
                typ, _ = self.bv.parse_type_string('{}'.format(member_info['type']))
                struct.insert(int(member_info['offset']), typ, member_name)

            self.bv.define_user_type(struct_name, Type.structure_type(struct))

    def import_names(self, names, sections):
        """
        Import names into BN database

        :param names: Dictionary of symbol information
        :param sections: Dictionary of sections
        """

        for addr, name in names.items():
            addr = self.adjust_addr(sections, int(addr))
            if addr is None:
                continue

            if self.bv.get_function_at(addr):
                self.bv.define_user_symbol(Symbol(SymbolType.FunctionSymbol, addr, name))
            else:
                self.bv.define_user_symbol(Symbol(SymbolType.DataSymbol, addr, name))

    def get_architectures(self):
        """
        Get dictionary of supported architectures

        :return: Dictionary of supported architectures
        """

        archs = {}
        for arch in list(Architecture):
            archs[arch.name] = arch

        return archs

    def set_raw_binary_params(self, sections):
        """
        Prompt the user for the processor and create sections

        :param sections: Dictionary of sections
        """

        archs = self.get_architectures()
        arch_choices = list(archs.keys())
        arch_field = ChoiceField('Default Platform', arch_choices)
        input_fields = [arch_field, ]
        section_fields = {}
        for name, section in sections.items():
            section_fields[name] = IntegerField(name + ' offset')
            input_fields.append(section_fields[name])

        get_form_input(input_fields, 'Processor and Sections')

        # set the default platform
        self.bv.platform = archs[arch_choices[arch_field.result]].standalone_platform

        # create the sections
        for name, section_field in section_fields.items():
            self.bv.add_user_section(name, section_field.result, sections[name]['end'] - sections[name]['start'])

    def run(self):
        """
        Open JSON file and apply analysis data to BN database
        """

        json_array = self.open_json_file(self.options.json_file)
        if self.bv.platform is None:
            self.set_raw_binary_params(json_array['sections'])

        self.import_functions(json_array['functions'], json_array['sections'])
        self.import_function_comments(json_array['func_comments'], json_array['sections'])
        self.import_line_comments(json_array['line_comments'], json_array['sections'])
        self.import_names(json_array['names'], json_array['sections'])
        self.import_structures(json_array['structs'])
        self.bv.update_analysis_and_wait()

def import_data_in_background(bv):
    """
    Registered plugin command handler

    :param bv: Binary view
    """

    options = GetOptions()
    background_task = ImportInBackground(bv, options)
    background_task.start()

PluginCommand.register(
    "bnida: Import data",
    "bnida: Import data",
    import_data_in_background
)
