"""ida_import.py: imports BN analysis data into a IDA database from a json file"""

__author__      = "zznop"
__copyright__   = "Copyright 2018, zznop0x90@gmail.com"
__license__     = "WTFPL"

import idc
import idautils
import idaapi
import json

def sanitize_name(name):
    """Remove characters from BN names that IDA doesn't like
    """
    name = name.replace("!", "_")
    name = name.replace("@", "_")
    return name

def base_addr_off_section(sections, addr):
    """Adjust the address if there are differences in section base addresses
    """
    bn_section_start = None
    section_name = None
    for name, section in sections.iteritems():
        if addr >= int(section["start"]) and addr <= int(section["end"]):
            bn_section_start = int(section["start"])
            section_name = name
            break

    # make sure the section was found (this check should always pass)
    if section_name is None:
        print "Section not found in BN analysis data for addr: {:08x}".format(addr)
        return None

    # retrieve section start in IDA and adjust the addr
    ida_sections = idautils.Segments()
    for ea in ida_sections:
        if idc.SegName(ea) == section_name:
            return addr - bn_section_start + idc.SegStart(ea)

    print "Section not found in IDA - name:{} addr:{:08x}".format(section_name, addr)
    return None

def import_comments(comments, sections):
    """Import BN comments
    """
    for addr, current_function in comments.iteritems():
        addr = base_addr_off_section(sections, int(addr))
        if addr is None:
            continue 

        if current_function["comment"]:
            idc.MakeRptCmt(int(addr), current_function["comment"].encode("utf-8"))

        for instr_addr, comment in current_function["comments"].iteritems():
            instr_addr = base_addr_off_section(sections, int(instr_addr))
            if instr_addr is None:
                continue

            idc.MakeComm(instr_addr, comment.encode("utf-8"))

def import_symbols(names, sections):
    """Import BN symbol names
    """
    for addr, name in names.iteritems():
        addr = base_addr_off_section(sections, int(addr))
        if addr is None:
            continue

        name = sanitize_name(name).encode("utf-8")
        idc.MakeName(addr, name)

def get_json(json_file):
    """Read JSON data file
    """
    json_array = None
    if json_file is None:
        return None

    try:
        f = open(json_file, "rb")
        json_array = json.load(f)
    except Exception as e:
        print("Failed to parse json file {} {}".format(json_file, e))
    return json_array

def main(json_file):
    """Import data from BN
    """
    json_array = get_json(json_file)
    if not json_array:
        print("JSON file not specified")
        return

    import_symbols(json_array["names"], json_array["sections"])
    import_comments(json_array["comments"], json_array["sections"])

if __name__ == "__main__":
    main(idc.AskFile(1, "*.json", "Import file name"))
