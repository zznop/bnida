"""ida_export.py: exports IDA analysis data to a json file"""

__author__      = "zznop"
__copyright__   = "Copyright 2018, zznop0x90@gmail.com"
__license__     = "WTFPL"

import idc
import idautils
import json

def get_single_comment(ea, is_func=False):
    """IDA has repeatable and regular comments. BN only has regular comments.
    This function constructs a single comment from both repeatable and regular
    comments
    """
    regular_comment    = ""
    repeatable_comment = ""

    if is_func:
        regular_comment = idc.GetFunctionCmt(ea, 0)
        repeatable_comment = idc.GetFunctionCmt(ea, 1)
    else:
        regular_comment = idc.Comment(ea)
        repeatable_comment = idc.RptCmt(ea)

    if regular_comment is None:
        return repeatable_comment
    elif repeatable_comment is None:
        return regular_comment
    elif repeatable_comment is None and regular_comment is None:
        return None
    else:
        if len(regular_comment) == 0:
            return repeatable_comment

        if len(repeatable_comment) == 0:
            return repeatable_comment

        return regular_comment + "\n" + repeatable_comment

    return None

def get_symbols():
    """Get symbols from IDA database
    """
    symbols = {}
    for addr, name in idautils.Names():
        symbols[addr] = name

    return symbols

def get_sections():
    """Get section names and start/end addrs from IDA database
    """
    sections = {}
    for ea in idautils.Segments():
        curr = {}
        curr["start"] = idc.SegStart(ea)
        curr["end"]   = idc.SegEnd(ea)
        sections[idc.SegName(ea)] = curr

    return sections

def get_comments():
    """Get function and instruction comments from IDA database
    """
    comments = {}
    for ea in idautils.Functions():
        current_function = {}
        end = idc.GetFunctionAttr(ea, idc.FUNCATTR_END)
        current_function["comment"] = get_single_comment(ea, True)
        current_function["comments"] = {}
        for line_ea in idautils.Heads(ea, end):
            instr_comment = get_single_comment(line_ea)
            if instr_comment is not None:
                current_function["comments"][line_ea] = instr_comment
        comments[ea] = current_function

    return comments

def get_member_type(struct, idx):
    """Retrieve the type information for the struct member
    """
    member = ida_struct.get_member(struct, idx)
    tif =  idaapi.tinfo_t()
    ida_struct.get_member_tinfo(member, tif)
    elements = str(tif).split(" ")
    typ = "unknown"
    if len(elements) == 2 and elements[0] == "unsigned":
        if elements[1] == "__int8":
            typ = "uint8_t"
        elif elements[1] == "__int16":
            typ = "uint16_t"
        elif elements[1] == "__int32":
            typ = "uint32_t"
        elif elements[1] == "__int64":
            typ = "uint64_t"
    elif len(elements) == 1:
        if elements[0] == "__int8":
            typ = "int8_t"
        elif elements[0] == "__int16":
            typ = "int16_t"
        elif elements[0] == "__int32":
            typ = "int32_t"
        elif elements[0] == "__int64":
            typ = "int64_t"
        else:
            typ = str(tif)

    return typ

def get_struct_members(struct, sid):
    """Get members belonging to a structure by structure ID
    """
    members = {}
    for offset, name, size in idautils.StructMembers(sid):
        members[name] = {}
        members[name]["type"]   = get_member_type(struct, offset)
        members[name]["offset"] = offset
        members[name]["size"]   = size

    return members

def get_structs():
    """Get structures from IDA database
    """
    structs = {}
    for idx, sid, name in idautils.Structs():
        struct = ida_struct.get_struc(sid)
        structs[name] = {}
        structs[name]["size"]    = idc.GetStrucSize(sid)
        structs[name]["members"] = get_struct_members(struct, sid)

    return structs

def main(json_file):
    """Construct a json file containing analysis data from an IDA database
    """
    json_array = {}
    json_array["sections"] = get_sections()
    json_array["comments"] = get_comments()
    json_array["symbols"]  = get_symbols()
    json_array["structs"]  = get_structs()

    with open(json_file, "wb") as f:
        f.write(json.dumps(json_array, indent=4))

if __name__ == '__main__':
    main(idc.AskFile(1, "*.json", "Export file name"))
