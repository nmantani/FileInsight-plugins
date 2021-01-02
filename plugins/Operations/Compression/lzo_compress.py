#
# LZO compress - Compress selected region with LZO algorithm
#
# Copyright (c) 2020, Nobutaka Mantani
# All rights reserved.
#
# This file is distributed under GPLv2 because it uses python-lzo
# Python module that is distributed under GPLv2.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import binascii
import sys

try:
    import lzo
except ImportError:
    exit(-1) # python-lz4 is not installed

data = binascii.a2b_hex(sys.stdin.read())
data = lzo.compress(data)
sys.stdout.write(str(binascii.b2a_hex(data).decode()))
