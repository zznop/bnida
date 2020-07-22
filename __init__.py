from binaryninja import *
from .binja import *

PluginCommand.register(
    'bnida: Import analysis data',
    'Import analysis data from JSON file',
    import_data_in_background
)

PluginCommand.register(
    'bnida: Export analysis data',
    'Export analysis data to a JSON file',
    export_data_in_background
)
