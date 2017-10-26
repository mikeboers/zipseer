"""
Read and write ZIP files.
"""
import struct, os, time, sys, shutil
import binascii, cStringIO, stat
import io
import re
import string

try:
    import zlib # We may need its compression method
    crc32 = zlib.crc32
except ImportError:
    zlib = None
    crc32 = binascii.crc32

__all__ = ["ZIP_STORED", "ZIP_DEFLATED",
           "ZipInfo", "ZipFile"]

ZIP64_LIMIT = (1 << 31) - 1
ZIP_FILECOUNT_LIMIT = (1 << 16) - 1
ZIP_MAX_COMMENT = (1 << 16) - 1

# constants for Zip file compression methods
ZIP_STORED = 0
ZIP_DEFLATED = 8
# Other ZIP compression methods not supported

# Below are some formats and associated data for reading/writing headers using
# the struct module.  The names and structures of headers/records are those used
# in the PKWARE description of the ZIP file format:
#     http://www.pkware.com/documents/casestudies/APPNOTE.TXT
# (URL valid as of January 2008)

# The "end of central directory" structure, magic number, size, and indices
# (section V.I in the format document)
structEndArchive = "<4s4H2LH"
stringEndArchive = "PK\005\006"
sizeEndCentDir = struct.calcsize(structEndArchive)

_ECD_SIGNATURE = 0
_ECD_DISK_NUMBER = 1
_ECD_DISK_START = 2
_ECD_ENTRIES_THIS_DISK = 3
_ECD_ENTRIES_TOTAL = 4
_ECD_SIZE = 5
_ECD_OFFSET = 6
_ECD_COMMENT_SIZE = 7
# These last two indices are not part of the structure as defined in the
# spec, but they are used internally by this module as a convenience
_ECD_COMMENT = 8
_ECD_LOCATION = 9

# The "central directory" structure, magic number, size, and indices
# of entries in the structure (section V.F in the format document)
structCentralDir = "<4s4B4HL2L5H2L"
stringCentralDir = "PK\001\002"
sizeCentralDir = struct.calcsize(structCentralDir)

# indexes of entries in the central directory structure
_CD_SIGNATURE = 0
_CD_CREATE_VERSION = 1
_CD_CREATE_SYSTEM = 2
_CD_EXTRACT_VERSION = 3
_CD_EXTRACT_SYSTEM = 4
_CD_FLAG_BITS = 5
_CD_COMPRESS_TYPE = 6
_CD_TIME = 7
_CD_DATE = 8
_CD_CRC = 9
_CD_COMPRESSED_SIZE = 10
_CD_UNCOMPRESSED_SIZE = 11
_CD_FILENAME_LENGTH = 12
_CD_EXTRA_FIELD_LENGTH = 13
_CD_COMMENT_LENGTH = 14
_CD_DISK_NUMBER_START = 15
_CD_INTERNAL_FILE_ATTRIBUTES = 16
_CD_EXTERNAL_FILE_ATTRIBUTES = 17
_CD_LOCAL_HEADER_OFFSET = 18

# The "local file header" structure, magic number, size, and indices
# (section V.A in the format document)
structFileHeader = "<4s2B4HL2L2H"
stringFileHeader = "PK\003\004"
sizeFileHeader = struct.calcsize(structFileHeader)

_FH_SIGNATURE = 0
_FH_EXTRACT_VERSION = 1
_FH_EXTRACT_SYSTEM = 2
_FH_GENERAL_PURPOSE_FLAG_BITS = 3
_FH_COMPRESSION_METHOD = 4
_FH_LAST_MOD_TIME = 5
_FH_LAST_MOD_DATE = 6
_FH_CRC = 7
_FH_COMPRESSED_SIZE = 8
_FH_UNCOMPRESSED_SIZE = 9
_FH_FILENAME_LENGTH = 10
_FH_EXTRA_FIELD_LENGTH = 11

# The "Zip64 end of central directory locator" structure, magic number, and size
structEndArchive64Locator = "<4sLQL"
stringEndArchive64Locator = "PK\x06\x07"
sizeEndCentDir64Locator = struct.calcsize(structEndArchive64Locator)

# The "Zip64 end of central directory" record, magic number, size, and indices
# (section V.G in the format document)
structEndArchive64 = "<4sQ2H2L4Q"
stringEndArchive64 = "PK\x06\x06"
sizeEndCentDir64 = struct.calcsize(structEndArchive64)

_CD64_SIGNATURE = 0
_CD64_DIRECTORY_RECSIZE = 1
_CD64_CREATE_VERSION = 2
_CD64_EXTRACT_VERSION = 3
_CD64_DISK_NUMBER = 4
_CD64_DISK_NUMBER_START = 5
_CD64_NUMBER_ENTRIES_THIS_DISK = 6
_CD64_NUMBER_ENTRIES_TOTAL = 7
_CD64_DIRECTORY_SIZE = 8
_CD64_OFFSET_START_CENTDIR = 9


class ZipInfo (object):
    """Class with attributes describing each file in the ZIP archive."""

    __slots__ = (
            'orig_filename',
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
            '_raw_time',
        )

    def __init__(self, filename="NoName", date_time=(1980,1,1,0,0,0)):

        self.orig_filename = filename   # Original file name in archive

        # Terminate the file name at the first null byte.  Null bytes in file
        # names are used as tricks by viruses in archives.
        null_byte = filename.find(chr(0))
        if null_byte >= 0:
            filename = filename[0:null_byte]

        # Ensure paths in generated ZIP files always use forward slashes as
        # required by the ZIP format specification.
        if os.sep != "/" and os.sep in filename:
            filename = filename.replace(os.sep, "/")

        self.filename = filename        # Normalized file name
        self.date_time = date_time      # year, month, day, hour, min, sec

        if date_time[0] < 1980:
            raise ValueError('ZIP does not support timestamps before 1980')

        # Standard values:
        self.compress_type = ZIP_STORED # Type of compression for the file
        self.comment = ""               # Comment for each file
        self.extra = ""                 # ZIP extra data
        if sys.platform == 'win32':
            self.create_system = 0          # System which created ZIP archive
        else:
            # Assume everything else is unix-y
            self.create_system = 3          # System which created ZIP archive
        self.create_version = 20        # Version which created ZIP archive
        self.extract_version = 20       # Version needed to extract archive
        self.reserved = 0               # Must be zero
        self.flag_bits = 0              # ZIP flag bits
        self.volume = 0                 # Volume number of file header
        self.internal_attr = 0          # Internal attributes
        self.external_attr = 0          # External file attributes
        # Other attributes are set by class ZipFile:
        # header_offset         Byte offset to the file header
        # CRC                   CRC-32 of the uncompressed file
        # compress_size         Size of the compressed file
        # file_size             Size of the uncompressed file

    def FileHeader(self, _garbage=None):
        """Return the per-file header as a string."""
        dt = self.date_time
        dosdate = (dt[0] - 1980) << 9 | dt[1] << 5 | dt[2]
        dostime = dt[3] << 11 | dt[4] << 5 | (dt[5] // 2)
        if self.flag_bits & 0x08:
            # Set these to zero because we write them after the file data
            CRC = compress_size = file_size = 0
        else:
            CRC = self.CRC
            compress_size = self.compress_size
            file_size = self.file_size

        extra = self.extra

        if file_size > ZIP64_LIMIT or compress_size > ZIP64_LIMIT:
            # File is larger than what fits into a 4 byte integer,
            # fall back to the ZIP64 extension
            fmt = '<HHQQ'
            extra = extra + struct.pack(fmt,
                    1, struct.calcsize(fmt)-4, file_size, compress_size)
            file_size = 0xffffffff
            compress_size = 0xffffffff
            self.extract_version = max(45, self.extract_version)
            self.create_version = max(45, self.extract_version)

        filename, flag_bits = self._encodeFilenameFlags()
        header = struct.pack(structFileHeader, stringFileHeader,
                 self.extract_version, self.reserved, flag_bits,
                 self.compress_type, dostime, dosdate, CRC,
                 compress_size, file_size,
                 len(filename), len(extra))
        return header + filename + extra

    def _encodeFilenameFlags(self):
        if isinstance(self.filename, unicode):
            try:
                return self.filename.encode('ascii'), self.flag_bits
            except UnicodeEncodeError:
                return self.filename.encode('utf-8'), self.flag_bits | 0x800
        else:
            return self.filename, self.flag_bits


class ZipFile(object):

    def __init__(self):
        self._allowZip64 = True
        self._comment = ''
        self._filePassed = 0
        self._start_disk = 0
        self.compression = ZIP_STORED  # Method of compression
        self.debug = 0  # Level of printing: 0 through 3
        self.filelist = []      # List of ZipInfo instances for archive
        self.filename = None
        self.fp = None
        self.mode = 'w' # GARBAGE
        self.NameToInfo = {}    # Find file info given name

    @property
    def comment(self):
        return self._comment

    @comment.setter
    def comment(self, comment):
        if len(comment) > ZIP_MAX_COMMENT:
            raise ValueError("Comment must be less than {} long.".format(ZIP_MAX_COMMENT))
        self._comment = comment


    def _writecheck(self, zinfo):
        """Check for errors before writing a file to the archive."""
        if zinfo.filename in self.NameToInfo:
            import warnings
            warnings.warn('Duplicate name: %r' % zinfo.filename, stacklevel=3)
        if self.mode not in ("w", "a"):
            raise RuntimeError, 'write() requires mode "w" or "a"'
        if not self.fp:
            raise RuntimeError, \
                  "Attempt to write ZIP archive that was already closed"
        if zinfo.compress_type == ZIP_DEFLATED and not zlib:
            raise RuntimeError, \
                  "Compression requires the (missing) zlib module"
        if zinfo.compress_type not in (ZIP_STORED, ZIP_DEFLATED):
            raise RuntimeError, \
                  "That compression method is not supported"

    def write(self, filename, arcname=None, compress_type=None):
        """Put the bytes from filename into the archive under the name
        arcname."""
        if not self.fp:
            raise RuntimeError(
                  "Attempt to write to ZIP archive that was already closed")

        st = os.stat(filename)
        isdir = stat.S_ISDIR(st.st_mode)
        mtime = time.localtime(st.st_mtime)
        date_time = mtime[0:6]
        # Create ZipInfo instance to store file information
        if arcname is None:
            arcname = filename
        arcname = os.path.normpath(os.path.splitdrive(arcname)[1])
        while arcname[0] in (os.sep, os.altsep):
            arcname = arcname[1:]
        if isdir:
            arcname += '/'
        zinfo = ZipInfo(arcname, date_time)
        zinfo.external_attr = (st[0] & 0xFFFF) << 16L      # Unix attributes
        if isdir:
            zinfo.compress_type = ZIP_STORED
        elif compress_type is None:
            zinfo.compress_type = self.compression
        else:
            zinfo.compress_type = compress_type

        zinfo.file_size = st.st_size
        zinfo.flag_bits = 0x00
        zinfo.header_offset = self.fp.tell()    # Start of header bytes

        self._writecheck(zinfo)

        if isdir:
            zinfo.file_size = 0
            zinfo.compress_size = 0
            zinfo.CRC = 0
            zinfo.external_attr |= 0x10  # MS-DOS directory flag
            self.filelist.append(zinfo)
            self.NameToInfo[zinfo.filename] = zinfo
            self.fp.write(zinfo.FileHeader(False))
            return

        with open(filename, "rb") as fp:
            # Must overwrite CRC and sizes with correct data later
            zinfo.CRC = CRC = 0
            zinfo.compress_size = compress_size = 0
            # Compressed size can be larger than uncompressed size
            zip64 = self._allowZip64 and \
                    zinfo.file_size * 1.05 > ZIP64_LIMIT
            self.fp.write(zinfo.FileHeader(zip64))
            if zinfo.compress_type == ZIP_DEFLATED:
                cmpr = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION,
                     zlib.DEFLATED, -15)
            else:
                cmpr = None
            file_size = 0
            while 1:
                buf = fp.read(1024 * 8)
                if not buf:
                    break
                file_size = file_size + len(buf)
                CRC = crc32(buf, CRC) & 0xffffffff
                if cmpr:
                    buf = cmpr.compress(buf)
                    compress_size = compress_size + len(buf)
                self.fp.write(buf)
        if cmpr:
            buf = cmpr.flush()
            compress_size = compress_size + len(buf)
            self.fp.write(buf)
            zinfo.compress_size = compress_size
        else:
            zinfo.compress_size = file_size
        zinfo.CRC = CRC
        zinfo.file_size = file_size
        if not zip64 and self._allowZip64:
            if file_size > ZIP64_LIMIT:
                raise RuntimeError('File size has increased during compressing')
            if compress_size > ZIP64_LIMIT:
                raise RuntimeError('Compressed size larger than uncompressed size')
        # Seek backwards and write file header (which will now include
        # correct CRC and file sizes)
        position = self.fp.tell() # Preserve current position in file
        self.fp.seek(zinfo.header_offset, 0)
        self.fp.write(zinfo.FileHeader(zip64))
        self.fp.seek(position, 0)
        self.filelist.append(zinfo)
        self.NameToInfo[zinfo.filename] = zinfo

    def writestr(self, zinfo_or_arcname, bytes, compress_type=None):
        """Write a file into the archive.  The contents is the string
        'bytes'.  'zinfo_or_arcname' is either a ZipInfo instance or
        the name of the file in the archive."""
        if not isinstance(zinfo_or_arcname, ZipInfo):
            zinfo = ZipInfo(filename=zinfo_or_arcname,
                            date_time=time.localtime(time.time())[:6])

            zinfo.compress_type = self.compression
            if zinfo.filename[-1] == '/':
                zinfo.external_attr = 0o40775 << 16   # drwxrwxr-x
                zinfo.external_attr |= 0x10           # MS-DOS directory flag
            else:
                zinfo.external_attr = 0o600 << 16     # ?rw-------
        else:
            zinfo = zinfo_or_arcname

        if not self.fp:
            raise RuntimeError(
                  "Attempt to write to ZIP archive that was already closed")

        if compress_type is not None:
            zinfo.compress_type = compress_type

        zinfo.file_size = len(bytes)            # Uncompressed size
        zinfo.header_offset = self.fp.tell()    # Start of header bytes
        self._writecheck(zinfo)
        zinfo.CRC = crc32(bytes) & 0xffffffff       # CRC-32 checksum
        if zinfo.compress_type == ZIP_DEFLATED:
            co = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION,
                 zlib.DEFLATED, -15)
            bytes = co.compress(bytes) + co.flush()
            zinfo.compress_size = len(bytes)    # Compressed size
        else:
            zinfo.compress_size = zinfo.file_size
        zip64 = zinfo.file_size > ZIP64_LIMIT or \
                zinfo.compress_size > ZIP64_LIMIT
        self.fp.write(zinfo.FileHeader(zip64))
        self.fp.write(bytes)
        if zinfo.flag_bits & 0x08:
            # Write CRC and file sizes after the file data
            fmt = '<LQQ' if zip64 else '<LLL'
            self.fp.write(struct.pack(fmt, zinfo.CRC, zinfo.compress_size,
                  zinfo.file_size))
        self.fp.flush()
        self.filelist.append(zinfo)
        self.NameToInfo[zinfo.filename] = zinfo

    def close(self):
        """Close the file, and for mode "w" and "a" write the ending
        records."""
        if self.fp is None:
            return

        try:
            if self.mode in ("w", "a"): # write ending records
                pos1 = self.fp.tell()
                for zinfo in self.filelist:         # write central directory
                    dt = zinfo.date_time
                    dosdate = (dt[0] - 1980) << 9 | dt[1] << 5 | dt[2]
                    dostime = dt[3] << 11 | dt[4] << 5 | (dt[5] // 2)
                    extra = []
                    if zinfo.file_size > ZIP64_LIMIT \
                            or zinfo.compress_size > ZIP64_LIMIT:
                        extra.append(zinfo.file_size)
                        extra.append(zinfo.compress_size)
                        file_size = 0xffffffff
                        compress_size = 0xffffffff
                    else:
                        file_size = zinfo.file_size
                        compress_size = zinfo.compress_size

                    header_offset = zinfo.header_offset - self._start_disk
                    if header_offset > ZIP64_LIMIT:
                        extra.append(header_offset)
                        header_offset = 0xffffffffL

                    extra_data = zinfo.extra
                    if extra:
                        # Append a ZIP64 field to the extra's
                        extra_data = struct.pack(
                                '<HH' + 'Q'*len(extra),
                                1, 8*len(extra), *extra) + extra_data

                        extract_version = max(45, zinfo.extract_version)
                        create_version = max(45, zinfo.create_version)
                    else:
                        extract_version = zinfo.extract_version
                        create_version = zinfo.create_version

                    try:
                        filename, flag_bits = zinfo._encodeFilenameFlags()
                        centdir = struct.pack(structCentralDir,
                        stringCentralDir, create_version,
                        zinfo.create_system, extract_version, zinfo.reserved,
                        flag_bits, zinfo.compress_type, dostime, dosdate,
                        zinfo.CRC, compress_size, file_size,
                        len(filename), len(extra_data), len(zinfo.comment),
                        0, zinfo.internal_attr, zinfo.external_attr,
                        header_offset)
                    except DeprecationWarning:
                        print >>sys.stderr, (structCentralDir,
                        stringCentralDir, create_version,
                        zinfo.create_system, extract_version, zinfo.reserved,
                        zinfo.flag_bits, zinfo.compress_type, dostime, dosdate,
                        zinfo.CRC, compress_size, file_size,
                        len(zinfo.filename), len(extra_data), len(zinfo.comment),
                        0, zinfo.internal_attr, zinfo.external_attr,
                        header_offset)
                        raise
                    self.fp.write(centdir)
                    self.fp.write(filename)
                    self.fp.write(extra_data)
                    self.fp.write(zinfo.comment)

                pos2 = self.fp.tell()
                # Write end-of-zip-archive record
                centDirCount = len(self.filelist)
                centDirSize = pos2 - pos1
                centDirOffset = pos1 - self._start_disk
                requires_zip64 = None
                if centDirCount > ZIP_FILECOUNT_LIMIT:
                    requires_zip64 = "Files count"
                elif centDirOffset > ZIP64_LIMIT:
                    requires_zip64 = "Central directory offset"
                elif centDirSize > ZIP64_LIMIT:
                    requires_zip64 = "Central directory size"
                if requires_zip64:
                    # Need to write the ZIP64 end-of-archive records
                    zip64endrec = struct.pack(
                            structEndArchive64, stringEndArchive64,
                            44, 45, 45, 0, 0, centDirCount, centDirCount,
                            centDirSize, centDirOffset)
                    self.fp.write(zip64endrec)

                    zip64locrec = struct.pack(
                            structEndArchive64Locator,
                            stringEndArchive64Locator, 0, pos2, 1)
                    self.fp.write(zip64locrec)
                    centDirCount = min(centDirCount, 0xFFFF)
                    centDirSize = min(centDirSize, 0xFFFFFFFF)
                    centDirOffset = min(centDirOffset, 0xFFFFFFFF)

                endrec = struct.pack(structEndArchive, stringEndArchive,
                                    0, 0, centDirCount, centDirCount,
                                    centDirSize, centDirOffset, len(self._comment))
                self.fp.write(endrec)
                self.fp.write(self._comment)
                self.fp.flush()
        finally:
            fp = self.fp
            self.fp = None
            if not self._filePassed:
                fp.close()

