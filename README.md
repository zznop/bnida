# Binary Ninja Importer
Utility for importing analysis information into Binary Ninja.  The only currently supported mechanism is from IDA. This utility has two parts:
1. An exporter script which runs on the tool you wish to pull analysis information from. This tool writes a .json file to disk that can be consumed by the importer.
2. A Binary Ninja plugin which imports the exported information.


## Usage

Install the `binja_import.py` script into your Binary Ninja user directory. https://docs.binary.ninja/getting-started/index.html#user-folder

Open IDA (this script was only tested in IDA 6.9) Click `File->Script File` and select the `ida_export.py` script. The script will prompt you for a filename to write the export information to.

## Supported Analysis data

1. Function
    start address
    line comment, function comment
    no-return status
2. Strings
    string objects (start, length, type)
    string cross-references

## Unsupported Analysis data

1. Segments
2. Global non-string data
3. Local variable names and types
4. Standard types and enumerations
5. Non-function comments (currently unsupported by Binary Ninja)

## Notes

Currently this tool does *NOT* do any deconfliction. Thus if you have data you don't wish to import you must edit the intermediate json file directly. Future revisions of the tool we hope will have interactive deconfliction and allow for regular expression based inclusion/exclusion.

