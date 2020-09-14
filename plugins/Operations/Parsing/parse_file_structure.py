#
# Parsing file structure of selected region (the whole file if not selected)
# with Kaitai Struct
#
# Copyright (c) 2020, Nobutaka Mantani
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import binascii
import collections
import datetime
import enum
import importlib
import inspect
import json
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
import re
import struct
import sys
import time

# Set to True to enable debug output
DEBUG = False

class_dict = {"bmp": "Bmp",
              "elf": "Elf",
              "gif": "Gif",
              "gzip": "Gzip",
              "jpeg": "Jpeg",
              "mbr_partition_table": "MbrPartitionTable",
              "microsoft_pe": "MicrosoftPe",
              "png": "Png",
              "rar": "Rar",
              "windows_lnk_file": "WindowsLnkFile",
              "zip": "Zip"}
parsed_dict = collections.defaultdict(dict)

def explore(file_type, obj, path="", offset=0, parent_offset=0, adjusted=False):
    """
    Explore object tree to add data and its location to parsed_dict
    """

    # base: start position of child objects
    if obj._io == obj._root._io and not adjusted:
        parent = False
        base = 0 # absolute address
    elif obj._parent != None and obj._io == obj._parent._io and not adjusted:
        parent = True
        base = parent_offset
    else:
        parent = False
        base = offset

    if DEBUG:
        print("==== Debug output ====", file=sys.stderr)
        print("Path: %s" % path, file=sys.stderr)
        print("offset: %s" % hex(offset), file=sys.stderr)
        print("parent_offset: %s" % hex(parent_offset), file=sys.stderr)
        print("adjusted: %s" % adjusted, file=sys.stderr)
        print("base: %s" % hex(base), file=sys.stderr)

        if obj._io == obj._root._io:
            print("_root._io: True", file=sys.stderr)
        else:
            print("_root._io: True", file=sys.stderr)
        if obj._parent != None and obj._io == obj._parent._io:
            print("_parent._io: True", file=sys.stderr)
        else:
            print("_parent._io: False", file=sys.stderr)

        for m in inspect.getmembers(obj):
            print(m, file=sys.stderr)

    # m[0]: object name
    # m[1]: object data
    for m in inspect.getmembers(obj):
        if path == "":
            path_new = m[0]
        else:
            path_new = path + "." + m[0]

        if (isinstance(m[1], KaitaiStruct) and not m[0].startswith("_")) or str(m[1]).startswith("<enum"):
            # Recursively explore child objects
            if hasattr(obj, "_debug") and (m[0] in obj._debug.keys() or ("_m_" + m[0]) in obj._debug.keys()):
                if "_m_" + m[0] in obj._debug.keys():
                    (offset_new, adjusted) = adjust_offset(file_type, path, "_m_" + m[0], offset, parent_offset, base, obj._debug["_m_" + m[0]]["start"])
                else:
                    (offset_new, adjusted) = adjust_offset(file_type, path, m[0], offset, parent_offset, base, obj._debug[m[0]]["start"])

                if parent:
                    explore(file_type, m[1], path_new, offset_new, parent_offset, adjusted)
                else:
                    explore(file_type, m[1], path_new, offset_new, offset, adjusted)
        elif not m[0] in ("SEQ_FIELDS", "__module__", "__doc__") and not m[0].startswith("_") \
             and (type(m[1]) in (bool, int, list, str, bytes, tuple, collections.defaultdict) or isinstance(m[1], enum.Enum)):
            # Add data that has _debug attribute (start and end offsets) to parsed_dict
            if hasattr(obj, "_debug") and (m[0] in obj._debug.keys() or ("_m_" + m[0]) in obj._debug.keys()):
                if type(m[1]) == list:
                    for i in range(0, len(m[1])):
                        if not isinstance(m[1][i], KaitaiStruct):
                            # "arr" contains list of start / end position like this:
                            # 'sections': {'start': 496, 'arr': [{'start': 496, 'end': 536}, {'start': 536, 'end': 576}, {'start': 576, 'end': 616}], 'end': 616}
                            if "arr" in obj._debug[m[0]].keys() and i < len(obj._debug[m[0]]["arr"]) \
                               and "end" in obj._debug[m[0]]["arr"][i].keys():
                                parsed_dict[path_new + "." + str(i)]["start"] = base + obj._debug[m[0]]["arr"][i]["start"]
                                parsed_dict[path_new + "." + str(i)]["end"] = base + obj._debug[m[0]]["arr"][i]["end"] - 1
                            elif "arr" in obj._debug["_m_" + m[0]].keys() and i < len(obj._debug["_m_" + m[0]]["arr"]) \
                                and "end" in obj._debug["_m_" + m[0]]["arr"][i].keys():
                                parsed_dict[path_new + "." + str(i)]["start"] = base + obj._debug["_m_" + m[0]]["arr"][i]["start"]
                                parsed_dict[path_new + "." + str(i)]["end"] = base + obj._debug["_m_" + m[0]]["arr"][i]["end"] - 1
                            elif "_m_" + m[0] in obj._debug.keys() and "end" in obj._debug["_m_" + m[0]].keys():
                                parsed_dict[path_new]["start"] = base + obj._debug["_m_" + m[0]]["start"]
                                parsed_dict[path_new]["end"] = base + obj._debug["_m_" + m[0]]["end"] - 1
                            elif "end" in obj._debug[m[0]].keys():
                                parsed_dict[path_new]["start"] = base + obj._debug[m[0]]["start"]
                                parsed_dict[path_new]["end"] = base + obj._debug[m[0]]["end"] - 1
                elif "_m_" + m[0] in obj._debug.keys() and "end" in obj._debug["_m_" + m[0]].keys():
                    parsed_dict[path_new]["start"] = base + obj._debug["_m_" + m[0]]["start"]
                    parsed_dict[path_new]["end"] = base + obj._debug["_m_" + m[0]]["end"] - 1
                elif "end" in obj._debug[m[0]].keys():
                    parsed_dict[path_new]["start"] = base + obj._debug[m[0]]["start"]
                    parsed_dict[path_new]["end"] = base + obj._debug[m[0]]["end"] - 1

                if type(m[1]) == list:
                    for i in range(0, len(m[1])):
                        if not isinstance(m[1][i], KaitaiStruct) and (path_new + "." + str(i)) in parsed_dict.keys() \
                            and "start" in parsed_dict[path_new + "." + str(i)].keys() \
                            and "end" in parsed_dict[path_new + "." + str(i)].keys():
                            parsed_dict[path_new + "." + str(i)]["data"] = str(m[1][i])
                elif "start" in parsed_dict[path_new].keys() and "end" in parsed_dict[path_new].keys():
                    if isinstance(m[1], enum.Enum):
                        parsed_dict[path_new]["data"] = "%s: %d (%s)" % (str(m[1]), m[1].value, hex(m[1].value))
                    elif type(m[1]) == int:
                        if is_date_time(file_type, path_new):
                            parsed_dict[path_new]["data"] = convert_date_time(file_type, path_new, m[1])
                        else:
                            parsed_dict[path_new]["data"] = "%s (%s)" % (m[1], hex(m[1]))
                    elif type(m[1]) == bytes:
                        if len(m[1]) > 16:
                            parsed_dict[path_new]["data"] = binascii.b2a_hex(m[1])[0:32].decode() + "... (hex)"
                        else:
                            parsed_dict[path_new]["data"] = binascii.b2a_hex(m[1]).decode() + " (hex)"
                    else:
                        parsed_dict[path_new]["data"] = m[1]

            # Handling of list of KaitaiStruct objects
            if type(m[1]) == list:
                for i in range(0, len(m[1])):
                    if isinstance(m[1][i], KaitaiStruct):
                        if "arr" in obj._debug[m[0]].keys():
                            (offset_new, adjusted) = adjust_offset(file_type, path + "." + str(i), m[0], offset, parent_offset, base, obj._debug[m[0]]["arr"][i]["start"])
                        elif "arr" in obj._debug["_m_" + m[0]].keys():
                            (offset_new, adjusted) = adjust_offset(file_type, path + "." + str(i), "_m_" + m[0], offset, parent_offset, base, obj._debug["_m_" + m[0]]["arr"][i]["start"])
                        else:
                            offset_new = base

                        if parent:
                            explore(file_type, m[1][i], path_new + "." + str(i), offset_new, parent_offset, adjusted)
                        else:
                            explore(file_type, m[1][i], path_new + "." + str(i), offset_new, offset, adjusted)

def is_date_time(file_type, path):
    """
    Return True if path is an object that needs to be converted to date/time string.
    """
    date_time_objects = {}
    date_time_objects["gzip"] = ("mod_time",)
    date_time_objects["microsoft_pe"] = ("pe.coff_hdr.time_date_stamp",)
    date_time_objects["rar"] = ("file_time.time", "file_time.date")
    date_time_objects["windows_lnk_file"] = ("header.time_creation", "header.time_access", "header.time_write", "last_mod_time")
    date_time_objects["zip"] = ("body.mod_time", "header.file_mod_date", "header.file_mod_time", "body.last_mod_time", "body.last_access_time", "body.creation_time", "body.last_mod_file_time", "body.last_mod_file_date")

    if file_type in date_time_objects.keys():
        for p in date_time_objects[file_type]:
            if p in path:
                return True
        return False
    else:
        return False

def convert_date_time(file_type, path, data):
    """
    Convert from bytes to date/time string.
    """
    if file_type == "gzip":
        return date_from_unix_time(data, "localtime")
    elif file_type == "microsoft_pe":
        return date_from_unix_time(data, "UTC")
    elif file_type == "windows_lnk_file":
        if "last_mod_time" in path:
            return datetime_from_msdos_time(data, "UTC")
        else:
            return date_from_windows_filetime(data)
    elif file_type == "rar":
        # MSDOS FAT timestamp format
        if "file_time.date" in path:
            return date_from_msdos_time(data, "localtime")
        elif "file_time.time" in path:
            return time_from_msdos_time(data, "localtime")
        else:
            return data
    elif file_type == "zip":
        if "header.extra.entries" in path and "body.mod_time" in path:
            return date_from_unix_time(data, "localtime")
        elif "body.mod_time" in path or "body.last_mod_time" in path or "body.last_access_time" in path or "body.creation_time" in path:
            return date_from_windows_filetime(data)
        elif "header.file_mod_date" in path or "body.last_mod_file_date" in path:
            return date_from_msdos_time(data, "localtime")
        elif "header.file_mod_time" in path or "body.last_mod_file_time" in path:
            return time_from_msdos_time(data, "localtime")
    else:
        return data

def date_from_windows_filetime(data):
    """
    Convert from Windows FILETIME to date/time string
    """
    us = data / 10.
    return str(datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=us)) + " (Windows FILETIME, UTC)"

def date_from_unix_time(data, timezone):
    """
    Convert from UNIX time to date/time string
    """
    return "%s (UNIX time, %s)" % (str(datetime.datetime.fromtimestamp(data)), timezone)

def date_from_msdos_time(data, timezone):
    """
    Convert from MSDOS timestamp to date string
    """
    year = 1980 + ((data & 0xfe00) >> 9)
    month = ((data & 0x1e0) >> 5)
    day = data & 0x1f
    return "%04d-%02d-%02d (MSDOS date/time, %s)" % (year, month, day, timezone)

def time_from_msdos_time(data, timezone):
    """
    Convert from MSDOS timestamp to time string
    """
    hour = (data & 0xf800) >> 11
    minute = (data & 0x7e0) >> 5
    second = 2 * (data & 0x1f)
    return "%02d:%02d:%02d (MSDOS date/time, %s)" % (hour, minute, second, timezone)

def datetime_from_msdos_time(data, timezone):
    """
    Convert from MSDOS timestamp to date/time string
    """
    data_high = (data & 0xffff0000) >> 16
    data_low = data & 0xffff

    year = 1980 + ((data_low & 0xfe00) >> 9)
    month = ((data_low & 0x1e0) >> 5)
    day = data_low & 0x1f
    hour = (data_high & 0xf800) >> 11
    minute = (data_high & 0x7e0) >> 5
    second = 2 * (data_high & 0x1f)

    return "%04d-%02d-%02d %02d:%02d:%02d (MSDOS date/time, %s)" % (year, month, day, hour, minute, second, timezone)

def adjust_offset(file_type, path, name, offset, parent_offset, base, start):
    """
    Adjust offset (absolute or relative) for some special cases.
    """
    adjusted = False
    if file_type == "elf" and (name == "_m_dynamic" or name == "_m_body"):
        adjusted = True
        return (start, adjusted) # absolute address

    # For JPEG files that contains Exif data
    if file_type == "jpeg":
        if re.match(r"^segments\.\d+\.data\.body$", path):
            adjusted = True
            return (parent_offset + start, adjusted) # relative address
        elif re.match(r"^segments\.\d+\.data\.body\.data$", path) or re.match(r"^segments\.\d+\.data\.body\.data\.body$", path) or re.match(r"^segments\.\d+\.data\.body\.data\.body\.ifd0$", path) or name == "fields":
            adjusted = True
            return (offset, adjusted) # relative address

    if file_type == "windows_lnk_file":
        if name == "id_list":
            adjusted = True
            return (start, adjusted) # absolute address
        elif name == "data":
            adjusted = True
            return (offset + start, adjusted) # relative address
        elif name == "items":
            adjusted = True
            return (parent_offset + 2, adjusted) # relative address

    # default cases
    return (base + start, adjusted)

# Receive data as hex string
data = binascii.a2b_hex(sys.stdin.read())

if len(sys.argv) > 1 and sys.argv[1] in class_dict.keys():
    # Dynamically load parser module specified with sys.argv[1]
    file_type = sys.argv[1]
    sys.path.insert(0, "./Parsing/Kaitai Struct")
    module = importlib.import_module(file_type)
    parser = getattr(module, class_dict[file_type])
    obj = parser.from_bytes(data)
    obj._read()
    explore(file_type, obj)
else:
    print("Error: parser not found.", file=sys.stderr)
    exit(1)

# Send parsed data as JSON
print(json.dumps(parsed_dict, indent=2))
