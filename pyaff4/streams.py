# Copyright 2016-2018 Schatz Forensic Pty Ltd. All rights reserved.
# Copyright © 2026 Apple Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.
import io

def ReadAll(stream):
    res = b""
    read = 0
    length = 0
    if isinstance(stream, io.BytesIO):
        length = stream.getbuffer().nbytes
    else:
        length = stream.Size()

    while True:
        toRead = length - read
        data = stream.read(toRead)
        if data is None or len(data) == 0:
            # EOF
            return res
        else:
            res += data

def WriteAll(fromstream, tostream):
    while True:
        toRead = 32 * 1024
        data = fromstream.read(toRead)
        if data is None or len(data) == 0:
            # EOF
            return
        else:
            tostream.write(data)