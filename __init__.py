from binaryninja import *
from .binja_export import *
from .binja_import import *

PluginCommand.register(
    "Export data from BN",
    "Export data from BN",
    export_bn_in_background
)

PluginCommand.register(
    "Import data from IDA",
    "Import data from IDA",
    import_ida_in_background
)
