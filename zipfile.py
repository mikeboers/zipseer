"""
Read and write ZIP files.
"""
import struct, os, time, sys
import binascii, stat
import io
import re
import string

try:
    import zlib # We may need its compression method
    crc32 = zlib.crc32
except ImportError:
    zlib = None
    crc32 = binascii.crc32

__all__ = ["COMPRESSION_NONE", "COMPRESSION_DEFLATE",
           "ZipInfo", "ZipFile"]

MAX_32BIT = (1 << 32) - 1
MAX_16BIT = (1 << 16) - 1

# The compression methods we understand.
COMPRESSION_NONE = 0
COMPRESSION_DEFLATE = 8

# Below are some formats and associated data for reading/writing headers using
# the struct module.  The names and structures of headers/records are those used
# in the PKWARE description of the ZIP file format:
#     http://www.pkware.com/documents/casestudies/APPNOTE.TXT
# (URL valid as of January 2008)

# The "end of central directory" structure, magic number, size, and indices
# (section V.I in the format document)
structEndArchive = '<4s4H2LH'
stringEndArchive = 'PK\005\006'

# The "central directory" structure, magic number, size, and indices
# of entries in the structure (section V.F in the format document)
structCentralDir = '<4s4B4HL2L5H2L'
stringCentralDir = 'PK\001\002'

# The "dumps_local_file_header" structure, magic number, size, and indices
# (section V.A in the format document)
structFileHeader = '<4s2B4HL2L2H'
stringFileHeader = 'PK\003\004'

structDataDescriptor = '<4sLLL'
structDataDescriptor64 = '<4sLQQ'
stringDataDescriptor = 'PK\x07\x08'

# The "Zip64 end of central directory locator" structure, magic number, and size
structEndArchive64Locator = '<4sLQL'
stringEndArchive64Locator = 'PK\x06\x07'

# The "Zip64 end of central directory" record, magic number, size, and indices
# (section V.G in the format document)
structEndArchive64 = '<4sQ2H2L4Q'
stringEndArchive64 = 'PK\x06\x06'


def iter_deflate(source):
    """If you need to compress something."""
    compressor = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
    for x in source:
        yield compressor.compress(x)
    yield compressor.flush()


class ZipInfo (object):
    """Class with attributes describing each file in the ZIP archive."""

    __slots__ = (
            'filename',
            'date_time',
            'compress_type',
            'comment',
            'extra',
            'create_system',
            'create_version',
            'extract_version',
            'reserved',
            'flag_bits',
            'volume',
            'internal_attr',
            'external_attr',
            'header_offset',
            'CRC',
            'compress_size',
            'file_size',
            'use_zip64',
            'source_path',
            'source_func',
        )

    def __init__(self, filename, date_time=(1980, 1, 1, 0, 0, 0), compress_type=None):

        # Terminate the file name at the first null byte.  Null bytes in file
        # names are used as tricks by viruses in archives.
        null_byte = filename.find(chr(0))
        if null_byte >= 0:
            filename = filename[0:null_byte]

        # Ensure paths in generated ZIP files always use forward slashes as
        # required by the ZIP format specification.
        if os.sep != '/' and os.sep in filename:
            filename = filename.replace(os.sep, '/')

        self.filename = filename        # Normalized file name
        self.date_time = date_time      # year, month, day, hour, min, sec

        if date_time[0] < 1980:
            raise ValueError("ZIP does not support timestamps before 1980.", date_time)

        if compress_type is None:
            compress_type = COMPRESSION_NONE

        # Standard values:
        self.compress_type = compress_type # Type of compression for the file
        self.comment = ""               # Comment for each file
        self.extra = ""                 # ZIP extra data
        if sys.platform == 'win32':
            self.create_system = 0      # System which created ZIP archive
        else:
            # Assume everything else is unix-y
            self.create_system = 3      # System which created ZIP archive
        self.create_version = 20        # Version which created ZIP archive
        self.extract_version = 20       # Version needed to extract archive
        self.reserved = 0               # Must be zero
        self.flag_bits = 0              # ZIP flag bits
        self.volume = 0                 # Volume number of file header
        self.internal_attr = 0          # Internal attributes
        self.external_attr = 0          # External file attributes

        # For deferred creation.
        self.source_path = None
        self.source_func = None

        # Mutable state, mostly set by ZipFile
        self.use_zip64 = False    # Are we using zip64 for sure?
        self.header_offset = None # Byte offset to the file header
        self.CRC = None           # CRC-32 of the uncompressed file
        self.compress_size = None # Size of the compressed file
        self.file_size = None     # Size of the uncompressed file

    @classmethod
    def from_path(cls, filename, arcname=None, compress_type=None, compress_size=None):

        st = os.stat(filename)
        isdir = stat.S_ISDIR(st.st_mode)
        mtime = time.localtime(st.st_mtime)
        date_time = mtime[0:6]

        if arcname is None:
            arcname = filename
        arcname = os.path.normpath(os.path.splitdrive(arcname)[1])
        while arcname[0] in (os.sep, os.altsep):
            arcname = arcname[1:]
        if isdir:
            arcname += '/'
            compress_type = COMPRESSION_NONE

        if compress_type and compress_type != COMPRESSION_NONE and compress_size is None:
            raise ValueError("Need compress_size with compress_type.")

        self = ZipInfo(arcname, date_time, compress_type=compress_type)

        self.external_attr = (st[0] & 0xFFFF) << 16 # Unix attributes
        self.file_size = st.st_size
        self.compress_size = compress_size
        self.flag_bits = 0x00

        if isdir:
            self.file_size = 0
            self.compress_size = 0
            self.CRC = 0
            self.external_attr |= 0x10  # MS-DOS directory flag

        self.source_path = filename

        return self

    @classmethod
    def from_func(cls, callback, size, arcname, compress_type=None, compress_size=None):
        self = cls(
            filename=arcname,
            date_time=time.localtime(time.time())[:6],
            compress_type=compress_type,
        )
        self.source_func = callback
        self.file_size = size
        self.compress_size = compress_size
        if self.filename[-1] == '/': # Directory!
            self.external_attr = 0o40775 << 16   # drwxrwxr-x
            self.external_attr |= 0x10           # MS-DOS directory flag
        else:
            self.external_attr = 0o600 << 16     # ?rw-------
        return self

    @property
    def needs_zip64(self):
        return self.file_size > MAX_32BIT or self.compress_size > MAX_32BIT

    @property
    def use_data_descriptor(self):
        return bool(self.flag_bits & 0x08)
    @use_data_descriptor.setter
    def use_data_descriptor(self, v):
        if v:
            self.flag_bits |= 0x08
        else:
            self.flag_bits &= ~0x08

    def assert_early_sanity(self):
        if self.file_size and not (self.source_func or self.source_path):
            raise ValueError("Contents has size, but no source.")
        if self.source_func and self.source_path:
            raise ValueError("Contents is doubly sourced.")

    def assert_late_sanity(self):
        if self.file_size is None:
            raise ValueError("Missing file_size.", self)
        if self.compress_size is None:
            raise ValueError("Missing compress_size.", self)
        if self.needs_zip64 and not self.use_zip64:
            raise ValueError("Needs Zip64 but not setup to use it; call finalize()", self)
        if self.file_size and not (self.source_func or self.source_path):
            raise ValueError("Non-zero size has no source.", self)
        if self.compress_type != COMPRESSION_NONE and self.CRC is None:
            raise ValueError("Need CRC when given pre-compressed data.", self)
        if self.header_offset is None:
            raise RuntimeError("Missing header offset.", self)

    def finalize(self):
        if self.compress_size is None:
            if self.compress_type != COMPRESSION_NONE:
                raise ValueError("Compress size required if content is compressed.")
            self.compress_size = self.file_size
        if self.needs_zip64:
            self.use_zip64 = True
        # self.CRC = 1 # Add bad CRC to not use a data descriptor.
        if self.CRC is None:
            self.use_data_descriptor = True

    def dumps_local_file_header(self):

        """Return the per-file header as a string."""
        dt = self.date_time
        dosdate = (dt[0] - 1980) << 9 | dt[1] << 5 | dt[2]
        dostime = dt[3] << 11 | dt[4] << 5 | (dt[5] // 2)

        if self.use_data_descriptor:
            # We write these again after the file.
            CRC = compress_size = file_size = 0
        else:
            CRC = self.CRC or 0 # Only allowed during size calc.
            compress_size = self.compress_size
            file_size = self.file_size

        extra = self.extra

        if self.use_zip64:
            # Stuff the real sizes into an "extra" header. Even if we're using
            # a data descriptor, we need to do this and put zeroes in there
            # because (a) the zeroes are required, and (b) both sizes are required
            # if the ZIP64 "extra" exists, and (c) if we don't do either then
            # how will the decompressor know that data descriptor will have
            # 8 byte values?
            fmt = '<HHQQ'
            extra = extra + struct.pack(fmt, 1, struct.calcsize(fmt) - 4, file_size, compress_size)
            file_size = 0xffffffff
            compress_size = 0xffffffff
            self.extract_version = max(45, self.extract_version)
            self.create_version = max(45, self.extract_version)

        filename, flag_bits = self._encode_filename_flags()
        header = struct.pack(structFileHeader, stringFileHeader,
                 self.extract_version, self.reserved, flag_bits,
                 self.compress_type, dostime, dosdate, CRC,
                 compress_size, file_size,
                 len(filename), len(extra))

        return header + filename + extra

    def dumps_data_descriptor(self):
        if self.use_data_descriptor:
            fmt = structDataDescriptor64 if self.use_zip64 else structDataDescriptor
            CRC = self.CRC or 0 # Only allowed during size calc.
            return struct.pack(fmt,
                stringDataDescriptor, CRC, self.compress_size, self.file_size
            )
        return ''

    def _encode_filename_flags(self):
        if isinstance(self.filename, unicode):
            try:
                return self.filename.encode('ascii'), self.flag_bits
            except UnicodeEncodeError:
                return self.filename.encode('utf-8'), self.flag_bits | 0x800
        else:
            return self.filename, self.flag_bits

    def iter_main(self):
        yield self.dumps_local_file_header()
        for chunk in self._iter_source():
            yield chunk
        yield self.dumps_data_descriptor()

    def _iter_source(self):

        if self.source_path:
            iter_ = self._iter_source_path()
        else:
            iter_ = self._iter_source_func()

        if self.CRC is not None:
            for chunk in iter_:
                yield chunk
            return

        CRC = 0
        size = 0
        for chunk in iter_:
            size += len(chunk)
            CRC = crc32(chunk, CRC) & 0xffffffff
            yield chunk

        # TODO: Warn if the size differs.

        self.CRC = CRC
        #self.CRC = 1 # Add a bad CRC.

    def _iter_source_path(self):
        with open(self.source_path, 'rb') as fh:
            while True:
                chunk = fh.read(8192)
                if not chunk:
                    return
                yield chunk

    def _iter_source_func(self):
        x = self.source_func()
        if isinstance(x, basestring):
            yield x
            return
        for chunk in x:
            yield chunk

    def dumps_central_directory_header(self):

        dt = self.date_time
        dosdate = (dt[0] - 1980) << 9 | dt[1] << 5 | dt[2]
        dostime = dt[3] << 11 | dt[4] << 5 | (dt[5] // 2)
        extra = []

        # TODO: Should this be use_zip64??
        if self.needs_zip64:
            extra.append(self.file_size)
            extra.append(self.compress_size)
            file_size = 0xffffffff
            compress_size = 0xffffffff
        else:
            file_size = self.file_size
            compress_size = self.compress_size

        header_offset = self.header_offset
        if header_offset > MAX_32BIT:
            extra.append(header_offset)
            header_offset = 0xffffffff

        extra_data = self.extra
        if extra:
            # Append a ZIP64 field to the extra's
            extra_data = struct.pack(
                    '<HH' + 'Q'*len(extra),
                    1, 8*len(extra), *extra) + extra_data

            extract_version = max(45, self.extract_version)
            create_version = max(45, self.create_version)
        else:
            extract_version = self.extract_version
            create_version = self.create_version

        filename, flag_bits = self._encode_filename_flags()

        CRC = self.CRC or 0 # We're only allowed to do this during size calc.

        centdir = struct.pack(structCentralDir,
            stringCentralDir, create_version,
            self.create_system, extract_version, self.reserved,
            flag_bits, self.compress_type, dostime, dosdate,
            CRC, compress_size, file_size,
            len(filename), len(extra_data), len(self.comment),
            0, self.internal_attr, self.external_attr,
            header_offset
        )
        
        return centdir + filename + extra_data + self.comment


class ZipFile(object):

    def __init__(self):
        self.comment = ''
        self.infos = []      # List of ZipInfo instances for archive
        self.info_by_name = {}    # Find file info given name

        self._finalized = False
        self._pos = 0

    @property
    def comment(self):
        return self._comment
    @comment.setter
    def comment(self, comment):
        if len(comment) > MAX_16BIT:
            raise ValueError("Comment must be less than {} long.".format(MAX_16BIT))
        self._comment = comment

    def add_from_path(self, *args, **kwargs):
        info = ZipInfo.from_path(*args, **kwargs)
        self.add(info)
        return info

    def add_from_func(self, *args, **kwargs):
        info = ZipInfo.from_func(*args, **kwargs)
        self.add(info)
        return info

    def add(self, info):

        if not isinstance(info, ZipInfo):
            raise TypeError("Archive contents must be ZipInfo.")

        if info.filename in self.info_by_name:
            raise ValueError("Duplicate name.", info.filename)

        info.assert_early_sanity()

        self.infos.append(info)
        self.info_by_name[info.filename] = info

    def calculate_size(self, unify_zip64=False, only_members=False):

        all_use_64 = True
        self._pos = 0

        for info in self.infos:
            info.header_offset = self._pos
            info.finalize()
            info.assert_late_sanity()
            self._pos += len(info.dumps_local_file_header())
            self._pos += info.compress_size
            self._pos += len(info.dumps_data_descriptor())
            all_use_64 = all_use_64 and info.use_zip64

        if unify_zip64 and not all_use_64 and (self._pos > MAX_32BIT or len(self.infos) > MAX_16BIT):
            # N.B.: We're not checking the central directory size here.
            # TODO: Do so.
            for info in self.infos:
                info.use_zip64 = True
            self.calculate_size(only_members=True) # Reset the _pos up to here.

        if only_members: # Effectively a recursion check for unify_zip64.
            return

        for x in self.iter_central_directory():
            self._pos += len(x)

        return self._pos

    def _iter(self):

        self._pos = 0

        for info in self.infos:
            info.finalize()
            info.assert_late_sanity()
            info.header_offset = self._pos
            for x in info.iter_main():
                yield x
        for x in self.iter_central_directory():
            yield x

    def iter(self):
        for chunk in self._iter():
            self._pos += len(chunk)
            yield chunk

    def iter_central_directory(self):

        cent_dir_count = len(self.infos)
        cent_dir_offset = self._pos

        for info in self.infos:
            yield info.dumps_central_directory_header()

        cent_dir_64_offset = self._pos
        cent_dir_size = cent_dir_64_offset - cent_dir_offset
        
        if (
            # The spec requires ZIP64 if any of these are >, but we're testing
            # against >= to avoid an edge case in which one of them is > and
            # one is ==. So instead of being wrong in that case, we're ZIP64
            # if everything is ==.
            cent_dir_count  >= MAX_16BIT or
            cent_dir_offset >= MAX_32BIT or
            cent_dir_size   >= MAX_32BIT
        ):
            # Write the ZIP64 end-of-archive records
            zip64endrec = struct.pack(
                    structEndArchive64, stringEndArchive64,
                    44, 45, 45, 0, 0, cent_dir_count, cent_dir_count,
                    cent_dir_size, cent_dir_offset)
            yield zip64endrec

            zip64locrec = struct.pack(
                    structEndArchive64Locator,
                    stringEndArchive64Locator, 0, cent_dir_64_offset, 1)
            yield zip64locrec

            cent_dir_count  = MAX_16BIT
            cent_dir_size   = MAX_32BIT
            cent_dir_offset = MAX_32BIT

        endrec = struct.pack(structEndArchive, stringEndArchive,
                            0, 0, cent_dir_count, cent_dir_count,
                            cent_dir_size, cent_dir_offset, len(self._comment))

        yield endrec
        if self._comment:
            yield self._comment


if __name__ == '__main__':

    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output')
    parser.add_argument('--only-to-zip64', action='store_true')
    parser.add_argument('--add-large-file', action='store_true')
    parser.add_argument('paths', nargs='*')
    args = parser.parse_args()

    content_size = 0

    zipseer = ZipFile()
    for path in args.paths:
        zipseer.add_from_path(path)

        if args.only_to_zip64:
            content_size += os.path.getsize(path)
            if content_size > MAX_32BIT:
                break

    if args.add_large_file:
        def iter_large_file():
            for i in xrange(4 * 1024 * 1024):
                yield '%1023d\n' % i
        mem = zipseer.add_from_func(iter_large_file, 4 * 1024 * 1024 * 1024, 'counter.txt')
        print mem.compress_size

    print zipseer.calculate_size()

    fh = open(args.output, 'wb') if args.output else None

    size = 0
    for chunk in zipseer.iter():
        size += len(chunk)
        if fh:
            fh.write(chunk)
    print size

    if fh:
        fh.close()

