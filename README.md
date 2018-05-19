# Binary Ninja Importer

Utility for transfering analysis information between Binary Ninja and IDA pro. This utility has four parts:
1. An IDA plugin that exports analysis data to a json file
2. A Binary Ninja plugin/script that imports the analysis data that has been exported from IDA
3. A Binary Ninja plugin/script that exports analysis data to a json file
4. An IDA plugin that imports analysis data that has been exported from Binary Ninja

## Usage

Install the `binja_import.py` and `binja_export.py` scripts into your Binary Ninja user directory. https://docs.binary.ninja/getting-started/index.html#user-folder

### IDA->Binary Ninja

1. Open your IDA database
2. Click `File->Script File` and select the `ida_export.py`
3. Input the filename of the file you want to write the exported data to
4. Click Ok. Analysis data will be written to the json file.
5. Open your BN database for the same binary
6. Click `tools->Import data to BN`
7. Enter the file path to the json file
8. Click ok. Your database will then be updated with the analysis data from IDA.

#### Supported Analysis data

1. Function
    start address
    line comment, function comment
    no-return status
2. Strings
    string objects (start, length, type)
    string cross-references

#### Unsupported Analysis data

1. Segments
2. Global non-string data
3. Local variable names and types
4. Standard types and enumerations
5. Non-function comments (currently unsupported by Binary Ninja)

### Binary Ninja->IDA

1. Open your Binary Ninja database
2. Click `tools->Export data from BN`
3. Enter the filename of the file you want to write the exported data to
4. Click Ok. Analysis data will be written to the json file
5. Open your IDA database for the same binary
6. Click `File->Script File` and select the `ida_import.py`
7. Select the json file
8. Click ok. Your database will then be updated with the analysis data from BN.

Analysis data for IDA to Binary Ninja is currently limited to comments and symbol names.

## Notes

Currently this tool does *NOT* do any deconfliction. Thus if you have data you don't wish to import you must edit the intermediate json file directly. Future revisions of the tool we hope will have interactive deconfliction and allow for regular expression based inclusion/exclusion.

