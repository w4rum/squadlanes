########################################################################
# REQUIRED SETTINGS - Our defaults will probably not work on your system
########################################################################

# Location of the steam-distributed Squad installation
# e.g. "/mnt/windows-drive/Program Files (x86)/Steam/steamapps/common/Squad"
SQUAD_GAME_DIR = "/mnt/win/Program Files (x86)/Steam/steamapps/common/Squad"

# Location of any layer mod packs that should be loaded.
#
# Syntax: {
#    "Mod Name": "Path to .pak files",
# }
#
# Supply the full path to the directory that the .pak files for the "WindowsNoEditor"
# version are in.
#
# This should work without problem for layers that use the same logic as vanilla.
# It will *not* work for mod packs that come with their own layer choosing logic like
# Hawk's Layer Pack (HLP)
# HLP, however, is an exception because we've explicitly added support for that.
MODS = {
    #"Hawks Layer Pack": "/mnt/win/Program Files (x86)/Steam/steamapps/workshop/content/393380/2442357787/HawksLayerPack/Content/Paks/WindowsNoEditor/",
}

################################################################################
# OPTIONAL SETTINGS - Our defaults should work if you just cloned the repository
################################################################################

# Limit how many unpack processes are run in parallel
# - increase to make unpacking faster (up to the speed of your storage device) but require more RAM
# - decrease to use less RAM but unpack slower
# (16 uses about 3-4 GiB of RAM)
MAXIMUM_PARALLEL_TASKS = 16

# Path to the UnrealPak Windows executable
UNREAL_PAK_PATH = "./UnrealPakTool/UnrealPak.exe"

# Path to the crypto.json as required by UnrealPak
# (needs the Squad decryption key)
CRYPTO_JSON_PATH = "./crypto.json"

# Path to the ELF executable from Squadlanes' umodel fork
UMODEL_PATH = "./umodel-squadlanes"

# Directory into which the Unreal Engine 4 assets are unpacked
UNPACKED_ASSETS_DIR = "./intermediate-files/unpacked-assets"

# Directory into which our umodel forks dumps map layer information
LAYER_DUMP_DIR = "./intermediate-files/layer-dumps"

# Directory into which the full-size maps are extracted
FULLSIZE_MAP_DIR = "./intermediate-files/map-fullsize"

# Directory into which the small map tiles are generated
TILE_MAP_DIR = "../dist/map-tiles"

# Verbosity of the logging
#  Recommended values: info, debug
LOG_LEVEL = "info"
# LOG_LEVEL = "debug"

# set to False to extract in series (slower but makes debugging easier)
EXTRACT_PARALLEL = True
