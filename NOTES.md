
Testing ZIP64
=============

- ZIP64 due to archive too big;
- OR, ZIP64 due to archive too big, AND all members forced zip64;
- OR, ZIP64 due to one member compress_size too big:
    √ Unarchiver.
    x macOS GUI errors.
    √ macOS CLI `unzip`.

    MD5 of "counter.txt" is 6f740afdfdef50c6df0ed0a284ae54f1

- Bad MACs in file header;
- OR bad MACs in data descriptor:
    √ Unarchiver complains file by file, popping up a dialog.
    x macOS GUI doesn't say anything.
    √ macOS CLI `unzip` warns file by file.

- ZIP64 of one file of null (compresses small enough for archive to not be ZIP64):
    √ Unarchiver.
    √ macOS GUI is also good! I guess it ignores the file_size... but then how
      would it know the compress_size???
    √ macOS CLI `unzip`.

    MD5 of "null.txt" (4GB of nulls) is c9a5a6878d97b48cc965c1e41859f034
