import ida_struct
import ida_kernwin
import ida_segment
import ida_bytes
import idautils
import json

"""
Exports analysis data from IDA to a bnida json file
"""

__author__    = 'zznop'
__copyright__ = 'Copyright 2018, zznop0x90@gmail.com'
__license__   = 'MIT'


def get_single_comment(regular, repeatable):
    """
    IDA has repeatable and regular comments. BN only has regular comments.
    This function constructs a single comment from both repeatable and regular
    comments
    """

    if repeatable is None and regular is None:
        return None
    elif repeatable is not None and regular is not None:
        return regular + '\n' + repeatable
    elif repeatable is not None and regular is None:
        return repeatable
    elif regular is not None and repeatable is None:
        return regular

def get_single_function_comment(ea):
    """
    Get function comment

    :param ea: Function offset
    :return: comment string or None
    """

    func = ida_funcs.get_func(ea)
    regular = ida_funcs.get_func_cmt(func, False)
    repeatable = ida_funcs.get_func_cmt(func, True)
    return get_single_comment(regular, repeatable)

def get_single_line_comment(ea):
    """
    Get line comment

    :param ea: Function offset
    :return: Comment string or None
    """

    regular = ida_bytes.get_cmt(ea, False)
    repeatable = ida_bytes.get_cmt(ea, True)
    cmt = get_single_comment(regular, repeatable)
    return cmt

def get_function_comments():
    """
    Get function comments from IDA database

    :return: Dict containing function comments
    """

    comments = {}
    for ea in idautils.Functions():
        comment = get_single_function_comment(ea)
        if comment:
            comments[ea] = comment

    return comments

def get_functions():
    """
    Get function start addresses

    :return: Array containing function addresses
    """

    func_addrs = []
    for ea in idautils.Functions():
        func_addrs.append(ea)

    return func_addrs

def get_line_comments():
    """
    Iterate through every address in a segment and check for comments

    :return: Dict containing line comments
    """

    last_comment = ''
    comments = {}
    for ea in idautils.Segments():
        segm = ida_segment.getseg(ea)
        name = ida_segment.get_segm_name(segm)
        if name == 'LOAD':
            continue

        for i in range(segm.start_ea, segm.end_ea):
            comment = get_single_line_comment(i)
            if comment and comment != last_comment:
                comments[i] = comment
                last_comment = comment

    return comments


def get_names():
    """
    Get symbols from IDA database

    :return: Dict containing symbol information
    """

    symbols = {}
    for addr, name in idautils.Names():
        symbols[addr] = name

    return symbols

def get_sections():
    """
    Get section names and start/end addrs from IDA database

    :return: Dict containing section info
    """

    sections = {}
    for ea in idautils.Segments():
        segm = ida_segment.getseg(ea)
        name = ida_segment.get_segm_name(segm)
        if name == 'LOAD':
            continue

        curr = {}
        curr['start']  = segm.start_ea
        curr['end']    = segm.end_ea
        sections[name] = curr

    return sections

def get_member_type(struct, idx):
    """
    Retrieve the type information for the struct member

    :return: Type string
    """

    member = ida_struct.get_member(struct, idx)
    tif = idaapi.tinfo_t()
    ida_struct.get_member_tinfo(tif, member)
    elements = str(tif).split(' ')
    typ = None
    if len(elements) == 2 and elements[0] == 'unsigned':
        if elements[1] == '__int8':
            typ = 'uint8_t'
        elif elements[1] == '__int16':
            typ = 'uint16_t'
        elif elements[1] == '__int32':
            typ = 'uint32_t'
        elif elements[1] == '__int64':
            typ = 'uint64_t'
        elif elements[1] != '':
            typ = elements[1]
    elif len(elements) == 1:
        if elements[0] == '__int8':
            typ = 'int8_t'
        elif elements[0] == '__int16':
            typ = 'int16_t'
        elif elements[0] == '__int32':
            typ = 'int32_t'
        elif elements[0] == '__int64':
            typ = 'int64_t'
        elif elements[0] != '':
            typ = str(tif)

    return typ

def get_struct_members(struct, sid):
    """
    Get members belonging to a structure by structure ID

    :param struct: Structure object
    :param sid: Structure ID
    :return: Dict containing structure member information
    """

    members = {}
    for offset, name, size in idautils.StructMembers(sid):
        members[name] = {}
        typ = get_member_type(struct, offset)
        if typ:
            members[name]['type'] = typ
        else:
            # Type isn't set so make it a byte array
            members[name]['type'] = 'uint8_t [{}]'.format(size)
        members[name]['offset'] = offset
        members[name]['size']   = size

    return members

def get_structs():
    """
    Get structures from IDA database

    :return: Dict containing structure info
    """

    structs = {}
    for idx, sid, name in idautils.Structs():
        struct = ida_struct.get_struc(sid)
        structs[name] = {}
        structs[name]['size']    = ida_struct.get_struc_size(struct)
        structs[name]['members'] = get_struct_members(struct, sid)

    return structs

def main(json_file):
    """
    Construct a json file containing analysis data from an IDA database

    :param json_file: Output JSON file name
    """

    json_array = {}
    print('[*] Exporting analysis data to {}'.format(json_file))
    json_array['sections']      = get_sections()
    json_array['functions']     = get_functions()
    json_array['func_comments'] = get_function_comments()
    json_array['line_comments'] = get_line_comments()
    json_array['names']         = get_names()
    json_array['structs']       = get_structs()
    print('[+] Done exporting analysis data')

    with open(json_file, 'w') as f:
        f.write(json.dumps(json_array, indent=4))

if __name__ == '__main__':
    main(ida_kernwin.ask_file(1, '*.json', 'Export file name'))
