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

def import_comments(comments):
    """Import BN comments
    """
    for addr, current_function in comments.iteritems():
        if current_function["comment"]:
            idc.MakeRptCmt(int(addr), current_function["comment"].encode("utf-8"))

        for addr, comment in current_function["comments"].iteritems():
            idc.MakeComm(int(addr), comment.encode("utf-8"))

def import_symbols(names):
    """Import BN symbol names
    """
    for addr, name in names.items():
        name = sanitize_name(name).encode("utf-8")
        idc.MakeName(int(addr), name)

def get_json(json_file):
    """Read JSON data file
    """
    json_array = None
    if json_file is None:
        print("JSON file not specified")
        return json_array

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
        return

    import_symbols(json_array["names"])
    import_comments(json_array["comments"])

if __name__ == "__main__":
    main(idc.AskFile(1, "*.json", "Import file name"))
