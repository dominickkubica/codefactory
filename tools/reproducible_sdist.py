"""Rewrite an sdist so the same source always gives the same bytes: every file's time set to SOURCE_DATE_EPOCH,
owners cleared, entries sorted, and the gzip header's own timestamp fixed. (Wheels are already reproducible.)

    SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) python tools/reproducible_sdist.py dist/*.tar.gz
"""

import gzip
import io
import os
import sys
import tarfile


def normalize(path: str, epoch: int) -> None:
    with tarfile.open(path, "r:gz") as src:
        members = sorted(src.getmembers(), key=lambda m: m.name)
        data = {m.name: src.extractfile(m).read() for m in members if m.isfile()}
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as out:
        for m in members:
            m.mtime, m.uid, m.gid, m.uname, m.gname = epoch, 0, 0, "", ""
            m.pax_headers = {}
            out.addfile(m, io.BytesIO(data[m.name]) if m.isfile() else None)
    with open(path, "wb") as f, gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=epoch, compresslevel=9) as gz:
        gz.write(raw.getvalue())


if __name__ == "__main__":
    epoch = int(os.environ["SOURCE_DATE_EPOCH"])
    for p in sys.argv[1:]:
        normalize(p, epoch)
