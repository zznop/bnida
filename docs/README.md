# Overview

bnida consists of (2) IDA Pro scripts and (2) Binary Ninja (BN) plugins that use IDAPython and BN Python API's to do
"one-shot" transfers of analysis data across IDA and BN databases. These scripts/plugins include:

* `binja_export.py` - Exports analysis data from a BN database to a bnida JSON file.
* `binja_import.py` - Imports analysis data from a bnida JSON file into a BN database.
* `ida_export.py` - Exports analysis data from an IDA database to a bnida JSON file.
* `ida_import.py` - Imports analysis data from a bnida JSON file into a IDA database.

All four scripts are designed to support a single, common JSON file format. This not only allows for transfers between
BN and IDA platorms, but also BN<->BN and IDA<->IDA too. This is especially useful if there is a desire to share
analysis data with someone using an older version of IDA who can't open your newer IDA database. The JSON file itself
is also easy to digest with custom tooling, since almost every programming language contains a JSON library.

# Installation

This section describes how to install bnida scripts on a Windows operating system. The process is similar on Linux.

1. Clone the [repository](https://github.com/zznop/bnida).

2. Copy the IDA scripts to `C:\Program Files\IDA {version}\plugins` and configure a hotkey. (or keep them where they are
if you prefer to run them as scripts with `Alt+F7`).

3. Copy the BN plugins to the Binary Ninja plugins folder at `%AppData%\Binary Ninja\plugins`

Optionally, you can keep the files where they are in the cloned repository and simply create symbolic links.

```
C:\Users\zznop\AppData\Roaming\Binary Ninja\plugins>mklink binja_export.py C:\Users\zznop\projects\bnida\binja\binja_export.py
symbolic link created for binja_export.py <<===>> C:\Users\zznop\projects\bnida\binja\binja_export.py
```

### Before

![BN Before](public/before.PNG "Before Loading Analysis Data")

### After

![BN After](public/after.PNG "After Loading Analysis Data")

## Getting Started

### Setup and Configuration

To use bnida, clone the [repository](https://github.com/zznop/bnida) into your Binary Ninja plugins folder. Then,
I recommend moving the IDA plugins (`ida_export.py` and `ida_import.py`), to `C:\Program Files\IDA 7.1\plugins` (Windows)
and configure a hotkey to execute each IDAPython script. To do so, follow
[this](http://www.mopsled.com/2016/add-shortcut-for-idapython-script-ida-pro/) blog post.
If you don't want to bother with that, no problem. You can run `ida_export.py` or `ida_import.py` by simply typing
`Alt+F7` to execute a script file.

### IDA to Binary Ninja

1. Open your IDA database (or load a binary and allow analysis to complete)

2. Type `Alt+F7` and select the `ida_export.py`

    ##### Run IDA Export Script
    
    ![Run IDA Export](public/ida-run-script.PNG "Run ida_export.py script")

3. Input the file path for the JSON file that will be created

4. Click Ok. Analysis data will be written to the JSON file

    ##### IDA Analysis Data JSON
    
    ![IDA Analysis Data JSON](public/ida-exported-json.PNG "IDA Analysis Data JSON")

5. Open your BN database for the same binary (or load a binary and allow analysis to complete)
6. Click `tools->Import data to BN`

    ##### Run Binja Import Plugin
    
    ![Run Binja Import](public/bn-tools-import-data.PNG "Run binja_import.py Plugin")

7. Enter the file path to the JSON file

    ##### Supply File Path to IDA JSON
    
    ![Enter JSON File](public/bn-import-file-input.PNG "File path to IDA JSON")

8. Click ok. Your database will then be updated with the analysis data from IDA.

### Binary Ninja to IDA

BN to IDA transfers require a similar process. The steps are as follows:

1. Open your Binary Ninja database (or load a binary and allow analysis to complete)
2. Click `tools->Export data from BN`
3. Input the file path for the JSON file that will be created
4. Click Ok. Analysis data will be written to the JSON file
5. Open your IDA database for the same binary (or load the binary and allow analysis to complete)
6. Type `Alt+F7` or click `File->Script File` and select the `ida_import.py`
7. Select the JSON file
8. Click ok. Your database will then be updated with the analysis data from BN.

## Additional Information

### Handling Flat Files

bnida calculates offsets between IDA and BN relative to the base address of the symbol's section. This is done to 
account for potential base address differences between the platforms. This design works excellent with PE and ELF 
executable file formats where the section names are defined in headers (which ensures section names are uniform).
However, with flat files (such as kernel images) where defining sections are left to the user, it is important to ensure
that section names are identical between the BNDB and IDB. Currently, `binja_import.py` contains a feature that allows
you to define the offsets for sections contained in the exported IDA JSON data. After selecting the JSON file, it checks
if the default processor has been set. If it has not been set, a input box will appear. The input box prompts the user
to define the default processor and set the base address for each section found in the JSON file.

##### Binja Import Prompt for Defining Sections

![Defining Sections](public/flat-file-section-definition.PNG "Defining Sections")

Sections can be defined manually using the Binary Ninja API and the script console, if needed. To create a section, use
`BinaryView.add_user_section(name, start, length)`. To validate that the section was created, navigate to linear view
and scroll to the top of the binary.

##### Add a Section Manually

![Create Section Manually](public/bn-add-section.PNG "BN Add User Section")

##### BN Sections View

![BN Sections](public/bn-sections.PNG "BN Sections")
