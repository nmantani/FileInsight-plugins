#
# lzip compress - Compress selected region with lzip format
#
# Copyright (c) 2023, Nobutaka Mantani
# All rights reserved.
#
# This file is distributed under GPLv3 because it uses lzip
# Python module that is distributed under GPLv3.
#
# This program is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation, either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import sys

try:
    import lzip
except ImportError:
    exit(-1) # lzip is not installed

try:
    data = sys.stdin.buffer.read()
    data = lzip.compress_to_buffer(data)
    sys.stdout.buffer.write(data)
except Exception as e:
    print(e, file=sys.stderr)
    exit(1)
