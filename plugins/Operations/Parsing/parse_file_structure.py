#
# Parse file structure - Parsing file structure of selected region
# (the whole file if not selected) with Kaitai Struct
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
import re
import sys

sys.path.append("./Parsing")
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO

# Set to True to enable debug output
DEBUG = False

module_dict = {"BMP": "bmp",
               "ELF": "elf",
               "GIF": "gif",
               "Gzip": "gzip",
               "JPEG": "jpeg",
               "Mach-O": "mach_o",
               "MBR partition table": "mbr_partition_table",
               "PE": "microsoft_pe",
               "PNG": "png",
               "RAR": "rar",
               "Windows shortcut": "windows_lnk_file",
               "ZIP": "zip"}

class_dict = {"BMP": "Bmp",
              "ELF": "Elf",
              "GIF": "Gif",
              "Gzip": "Gzip",
              "JPEG": "Jpeg",
              "Mach-O": "MachO",
              "MBR partition table": "MbrPartitionTable",
              "PE": "MicrosoftPe",
              "PNG": "Png",
              "RAR": "Rar",
              "Windows shortcut": "WindowsLnkFile",
              "ZIP": "Zip"}
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
            print("_root._io: False", file=sys.stderr)
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
                            if type(m[1][i]) == str:
                                parsed_dict[path_new + "." + str(i)]["data"] =  repr(m[1][i])[1:-1] # Escape \r, \n, \t and remove single quote
                            elif type(m[1][i]) == bytes:
                                if len(m[1][i]) > 16:
                                    parsed_dict[path_new + "." + str(i)]["data"] = binascii.b2a_hex(m[1][i])[0:32].decode() + "... (hex)"
                                else:
                                    parsed_dict[path_new + "." + str(i)]["data"] = binascii.b2a_hex(m[1][i]).decode() + " (hex)"
                            else:
                                parsed_dict[path_new + "." + str(i)]["data"] = m[1][i]
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
                        parsed_dict[path_new]["data"] = repr(m[1])[1:-1] # Escape \r, \n, \t and remove single quote

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
    date_time_objects["Gzip"] = ("mod_time",)
    date_time_objects["PE"] = ("pe.coff_hdr.time_date_stamp",)
    date_time_objects["Windows shortcut"] = ("header.time_creation", "header.time_access", "header.time_write", "last_mod_time")
    date_time_objects["ZIP"] = ("body.last_mod_time", "body.last_access_time", "body.creation_time")

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
    if file_type == "Gzip":
        return date_from_unix_time(data, "UTC")
    elif file_type == "PE":
        return date_from_unix_time(data, "UTC")
    elif file_type == "Windows shortcut":
        if "last_mod_time" in path:
            return datetime_from_msdos_time(data, "UTC")
        else:
            return date_from_windows_filetime(data)
    elif file_type == "ZIP":
        if "body.last_mod_time" in path or "body.last_access_time" in path or "body.creation_time" in path:
            return date_from_windows_filetime(data)
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
    if timezone == "UTC":
        return "%s (UNIX time, %s)" % (str(datetime.datetime.fromtimestamp(data, datetime.timezone.utc)), timezone)
    else:
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
    Adjust offset (absolute or relative) of object that has child objects for some special cases.
    """
    adjusted = False
    if file_type == "ELF":
        if name == "_m_dynamic" or name == "_m_body":
            adjusted = True
            return (start, adjusted) # absolute address

    # For JPEG files that contains Exif data
    elif file_type == "JPEG":
        if re.match(r"^segments\.\d+\.data\.body$", path):
            adjusted = True
            return (parent_offset + start, adjusted) # relative address
        elif re.match(r"^segments\.\d+\.data\.body\.data$", path) \
             or re.match(r"^segments\.\d+\.data\.body\.data\.body$", path) \
             or re.match(r"^segments\.\d+\.data\.body\.data\.body\.ifd0$", path) or name == "fields":
            adjusted = True
            return (offset, adjusted) # relative address

    elif file_type == "Mach-O":
        if re.match(r"^load_commands\.\d+\.body\.sections\.\d$", path):
            adjusted = True
            return (start, adjusted) # absolute address

    elif file_type == "RAR":
        if re.match(r"^blocks\.\d+\.body\.file_time$", path):
            adjusted = True
            return (offset, adjusted)

    elif file_type == "Windows shortcut":
        if name == "id_list":
            adjusted = True
            return (start, adjusted) # absolute address
        elif name == "data":
            adjusted = True
            return (offset + start, adjusted) # relative address
        elif name == "items":
            adjusted = True
            return (parent_offset + 2, adjusted) # relative address
    elif file_type == "ZIP":
        if re.match(r"^sections\.\d+\.body\.header\.file_mod_time$", path) \
           or re.match(r"^sections\.\d+\.body\.file_mod_time$", path) \
           or re.match(r"^sections\.\d+\.body\.local_header\.body\.header\.file_mod_time$", path):
            adjusted = True
            return (offset, adjusted)

    # default cases
    return (base + start, adjusted)

def adjust_start_end(file_type, parsed_dict, data):
    """
    Directly adjust offset of start and end for some special cases.
    """
    if file_type == "BMP":
        # Add region of bitmap
        parsed_dict["bitmap"]["start"] = int(parsed_dict["file_hdr.ofs_bitmap"]["data"].split()[0]) # data is like "16 (0x10)"
        parsed_dict["bitmap"]["end"] = int(parsed_dict["file_hdr.len_file"]["data"].split()[0]) - 1
        parsed_dict["bitmap"]["data"] = ""

        bitmap = data[parsed_dict["bitmap"]["start"]:parsed_dict["bitmap"]["end"]]

        if len(bitmap) > 16:
            parsed_dict["bitmap"]["data"] = binascii.b2a_hex(bitmap)[0:32].decode() + "... (hex)"
        else:
            parsed_dict["bitmap"]["data"] = binascii.b2a_hex(bitmap).decode() + " (hex)"

    elif file_type == "ELF":
        new_dict = collections.defaultdict(dict)
        header_section_names_start = parsed_dict["header.section_names.entries.0"]["start"]

        for k in parsed_dict.keys():
            if re.match(r"^header\.section_headers\.\d+\.ofs_name$", k):
                # Adjust offset of header.section_headers.??.name
                offset_name = parsed_dict[k[:-8] + "name"]["start"] - parsed_dict[k]["start"] # k[:-8] + "name" = header.section_headers.??.name
                len_name = len(parsed_dict[k[:-8] + "name"]["data"])
                parsed_dict[k[:-8] + "name"]["start"] = header_section_names_start + offset_name
                parsed_dict[k[:-8] + "name"]["end"] = parsed_dict[k[:-8] + "name"]["start"] + len_name

                # Add region of body
                len_body = int(parsed_dict[k[:-8] + "len_body"]["data"].split()[0]) # data is like "16 (0x10)"
                if len_body > 0:
                    new_dict[k[:-8] + "body"]["start"] = int(parsed_dict[k[:-8] + "ofs_body"]["data"].split()[0]) # absolute address
                    new_dict[k[:-8] + "body"]["end"] = new_dict[k[:-8] + "body"]["start"] + len_body - 1

                    body = data[new_dict[k[:-8] + "body"]["start"]:new_dict[k[:-8] + "body"]["end"]]

                    if len_body > 16:
                        new_dict[k[:-8] + "body"]["data"] = binascii.b2a_hex(body)[0:32].decode() + "... (hex)"
                    else:
                        new_dict[k[:-8] + "body"]["data"] = binascii.b2a_hex(body).decode() + " (hex)"
            elif re.match(r"^header\.section_headers\.\d+\.body\.entries\.\d+\.name$", k):
                # Adjust offset of header.section_headers.??.body.??.entries.??.name
                # k[:-4] + "ofs_name" = header.section_headers.??.body.??.entries.??.ofs_name
                if k[:-4] + "ofs_name" in parsed_dict:
                    parsed_dict[k]["start"] = parsed_dict[k[:-4] + "ofs_name"]["start"]
                    parsed_dict[k]["end"] = parsed_dict[k[:-4] + "ofs_name"]["end"]

        for k in new_dict.keys():
            parsed_dict[k]["start"] = new_dict[k]["start"]
            parsed_dict[k]["end"] = new_dict[k]["end"]
            parsed_dict[k]["data"] = new_dict[k]["data"]

    elif file_type == "Mach-O":
        new_dict = collections.defaultdict(dict)

        for k in parsed_dict.keys():
            if re.match(r"^load_commands\.\d+\.body\.sections\.\d+\.data$", k):
                offset_key = k[:-4] + "offset" # load_commands.??.body.sections.??.offset
                size_key = k[:-4] + "size" # load_commands.??.body.sections.??.size
                new_dict[k]["start"] = int(parsed_dict[offset_key]["data"].split()[0]) # data is like "16 (0x10)"
                new_dict[k]["end"] = new_dict[k]["start"] + int(parsed_dict[size_key]["data"].split()[0]) - 1
                new_dict[k]["data"] = parsed_dict[k]["data"]

            if re.match(r"^load_commands\.\d+\.body\.indirect_symbols\.\d+$", k):
                i_local_sym_key = ".".join(k.split(".")[:3]) + ".i_local_sym" # load_commands.??.body.i_local_sym
                i_local_sym_offset = parsed_dict[i_local_sym_key]["start"]
                new_dict[k]["start"] = parsed_dict[k]["start"] - i_local_sym_offset
                new_dict[k]["end"] = parsed_dict[k]["end"] - i_local_sym_offset
                new_dict[k]["data"] = parsed_dict[k]["data"]

            if re.match(r"^load_commands\.\d+\.body\.rebase\.", k) \
               or re.match(r"^load_commands\.\d+\.body\.bind\.", k) \
               or re.match(r"^load_commands\.\d+\.body\.weak_bind\.", k) \
               or re.match(r"^load_commands\.\d+\.body\.lazy_bind\.", k) \
               or re.match(r"^load_commands\.\d+\.body\.exports\.", k):
                rebase_off_key = ".".join(k.split(".")[:3]) + ".rebase_off" # load_commands.??.body.rebase_off
                rebase_off_start = parsed_dict[rebase_off_key]["start"]

                new_dict[k]["start"] = parsed_dict[k]["start"] - rebase_off_start
                new_dict[k]["end"] = parsed_dict[k]["end"] - rebase_off_start
                new_dict[k]["data"] = parsed_dict[k]["data"]

            if re.match(r"^load_commands\.\d+\.body\.export_off$", k):
                export_off_key = ".".join(k.split(".")[:3]) + ".export_off" # load_commands.??.body.export_off
                exports_start = int(parsed_dict[export_off_key]["data"].split()[0]) # data is like "16 (0x10)"
                export_size_key = ".".join(k.split(".")[:3]) + ".export_size" # load_commands.??.body.export_size
                export_size = int(parsed_dict[export_size_key]["data"].split()[0]) # data is like "16 (0x10)"

                exports_key = ".".join(k.split(".")[:3]) + ".exports" # load_commands.??.body.exports
                new_dict[exports_key]["start"] = exports_start
                new_dict[exports_key]["end"] = exports_start + export_size - 1

                exports = data[new_dict[exports_key]["start"]:new_dict[exports_key]["end"]]

                if len(exports) > 16:
                    new_dict[exports_key]["data"] = binascii.b2a_hex(exports)[0:32].decode() + "... (hex)"
                else:
                    new_dict[exports_key]["data"] = binascii.b2a_hex(exports).decode() + " (hex)"

            if re.match(r"^load_commands\.\d+\.body\.strs\.", k):
                sym_off_key = ".".join(k.split(".")[:3]) + ".sym_off" # load_commands.??.body.sym_off
                sym_off_start = parsed_dict[sym_off_key]["start"]

                new_dict[k]["start"] = parsed_dict[k]["start"] - sym_off_start
                new_dict[k]["end"] = parsed_dict[k]["end"] - sym_off_start
                new_dict[k]["data"] = parsed_dict[k]["data"]

        for k in new_dict.keys():
            parsed_dict[k]["start"] = new_dict[k]["start"]
            parsed_dict[k]["end"] = new_dict[k]["end"]
            parsed_dict[k]["data"] = new_dict[k]["data"]

    elif file_type == "RAR":
        # Add attributes of blocks.??.body.file_time.time and blocks.??.body.file_time.date
        new_dict = collections.defaultdict(dict)

        for k in parsed_dict.keys():
            if re.match(r"^blocks\.\d+\.body\.file_time\.time\.second_div_2$", k):
                    new_key = k[:-17] + "time" # blocks.??.body.file_time.time
                    new_dict[new_key]["start"] = parsed_dict[k]["start"]
                    new_dict[new_key]["end"] = new_dict[new_key]["start"] + 1
                    time = int.from_bytes(data[new_dict[new_key]["start"]:new_dict[new_key]["end"]+1], "little")
                    new_dict[new_key]["data"] = time_from_msdos_time(time, "localtime, unknown timezone")

                    new_key = k[:-17] + "date" # blocks.??.body.file_time.date
                    new_dict[new_key]["start"] = parsed_dict[k]["start"] + 2
                    new_dict[new_key]["end"] = new_dict[new_key]["start"] + 1
                    date = int.from_bytes(data[new_dict[new_key]["start"]:new_dict[new_key]["end"]+1], "little")
                    new_dict[new_key]["data"] = date_from_msdos_time(date, "localtime, unknown timezone")

        for k in new_dict.keys():
            parsed_dict[k]["start"] = new_dict[k]["start"]
            parsed_dict[k]["end"] = new_dict[k]["end"]
            parsed_dict[k]["data"] = new_dict[k]["data"]

    elif file_type == "ZIP":
        # Add attributes of sections.??.body.header.file_mod_time.time.second_div_2 and so on
        new_dict = collections.defaultdict(dict)

        for k in parsed_dict.keys():
            if re.match(r"^sections\.\d+\..+\.second_div_2$", k):
                    new_key = k[:-17] + "time" # sections.??.body.header.file_mod_time.time
                    new_dict[new_key]["start"] = parsed_dict[k]["start"]
                    new_dict[new_key]["end"] = new_dict[new_key]["start"] + 1
                    time = int.from_bytes(data[new_dict[new_key]["start"]:new_dict[new_key]["end"]+1], "little")
                    new_dict[new_key]["data"] = time_from_msdos_time(time, "localtime, unknown timezone")

                    new_key = k[:-17] + "date" # sections.??.body.header.file_mod_time.date
                    new_dict[new_key]["start"] = parsed_dict[k]["start"] + 2
                    new_dict[new_key]["end"] = new_dict[new_key]["start"] + 1
                    date = int.from_bytes(data[new_dict[new_key]["start"]:new_dict[new_key]["end"]+1], "little")
                    new_dict[new_key]["data"] = date_from_msdos_time(date, "localtime, unknown timezone")

        for k in new_dict.keys():
            parsed_dict[k]["start"] = new_dict[k]["start"]
            parsed_dict[k]["end"] = new_dict[k]["end"]
            parsed_dict[k]["data"] = new_dict[k]["data"]

# Receive data as hex string
data = sys.stdin.buffer.read()

if len(sys.argv) > 1 and sys.argv[1] in module_dict.keys():
    # Dynamically load parser module specified with sys.argv[1]
    file_type = sys.argv[1]
    sys.path.insert(0, "./Parsing/Kaitai Struct")
    module = importlib.import_module(module_dict[file_type])
    parser = getattr(module, class_dict[file_type])
    obj = parser.from_bytes(data)
    obj._read()
    explore(file_type, obj)
else:
    print("Error: parser of %s not found." % file_type, file=sys.stderr)
    exit(1)

adjust_start_end(file_type, parsed_dict, data)

# Send parsed data as JSON
print(json.dumps(parsed_dict, indent=2))
