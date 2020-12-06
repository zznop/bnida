"""
Exports analysis data from a Ghidra program database to a bnida JSON file
"""

import json


def get_names(program):
    """
    Export symbols

    :param program: Program object
    :return: Dict containing symbol info
    """

    symbols = program.getSymbolTable().getAllSymbols(True)
    ret_symbols = {}
    for symbol in symbols:
        ret_symbols[symbol.getAddress().getOffset()] = symbol.getName()
    return ret_symbols


def get_sections(program):
    """
    Export sections

    :param program: Program object
    :return: Dict containing section info
    """

    sections = {}
    blocks = program.getMemory().getBlocks()
    for block in blocks:
        start = block.getStart().offset
        sections[block.getName()] = {
            'start': start,
            'end': start+block.getSize(),
        }
    return sections


def get_functions(program):
    """
    Export functions

    :param program: Program object
    :return: Dict containing function info
    """

    function_mgr = program.getFunctionManager()
    funcs = function_mgr.getFunctions(True)
    ret_funcs = []
    for func in funcs:
        ret_funcs.append(func.getEntryPoint().offset)
    return ret_funcs


def get_function_comments(program):
    """
    Export function comments

    :param program: Program object
    :return: Dict containing line comments
    """

    function_mgr = program.getFunctionManager()
    funcs = function_mgr.getFunctions(True)
    comments = {}
    for func in funcs:
        comment = func.getComment()
        if not comment:
            continue
        comments[func.getEntryPoint().offset] = comment

    return comments


def _get_comment(code_unit, _type):
    """
    Query comment of a specified type

    :param code_unit: Ghidra code unit
    :param _type: Comment type
    """

    comment = code_unit.getComment(_type)
    if comment:
        return comment

    return ""


def get_line_comments(program):
    """
    Export line comments

    :param program: Program object
    :return: Dict containing line comments
    """

    listing = program.getListing()
    code_units = listing.getCodeUnits(True)
    comments = {}
    for code_unit in code_units:
        comment = ""
        comment += _get_comment(code_unit, code_unit.EOL_COMMENT)
        comment += _get_comment(code_unit, code_unit.PRE_COMMENT)
        comment += _get_comment(code_unit, code_unit.POST_COMMENT)
        comment += _get_comment(code_unit, code_unit.REPEATABLE_COMMENT)
        if comment != "":
            comments[code_unit.getAddress().getOffset()] = comment

    return comments


def get_structures():
    """
    Export structures
    """

    return {}  # TODO


def main():
    """
    Export analysis data to a bnida JSON file
    """

    json_file = '/tmp/out.json'  # TODO
    print('[*] Exporting analysis data to {}'.format(json_file))

    state = getState()
    program = state.getCurrentProgram()
    json_array = {}
    json_array['sections'] = get_sections(program)
    json_array['names'] = get_names(program)
    json_array['functions'] = get_functions(program)
    json_array['func_comments'] = get_function_comments(program)
    json_array['line_comments'] = get_line_comments(program)
    json_array['structs'] = get_structures()

    with open(json_file, 'w') as f:
        json.dump(json_array, f, indent=4)

    print('[*] Done exporting analysis data')


main()
