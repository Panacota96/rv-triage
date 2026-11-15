//! Readers under the NTFS parser: a sector-aligned block cache (a Windows volume handle only accepts reads whose
//! offset and length are multiples of the sector size) and a window onto one partition of a disk image.

use std::io::{self, Read, Seek, SeekFrom};

/// Serves any byte range of `inner` while only ever reading whole, aligned blocks from it: every read of the
/// inner reader starts at a multiple of `sector` and asks for a multiple of `sector` bytes. The last block is
/// shortened (to a sector multiple) so that reads do not run past `limit`.
pub struct AlignedReader<R> {
    inner: R,
    sector: u64,
    block: usize,
    buf: Vec<u8>,
    buf_start: u64,
    buf_len: usize,
    pos: u64,
    limit: Option<u64>,
}

impl<R: Read + Seek> AlignedReader<R> {
    /// `sector` must be a power of two; the block size is rounded up to a multiple of it.
    pub fn new(inner: R, sector: u64, block: usize) -> AlignedReader<R> {
        let sector = sector.max(1);
        let block = (block as u64).div_ceil(sector).max(1) * sector;
        AlignedReader {
            inner,
            sector,
            block: block as usize,
            buf: vec![0; block as usize],
            buf_start: 0,
            buf_len: 0,
            pos: 0,
            limit: None,
        }
    }

    /// Changes the alignment and the end of the readable range (bytes past `limit` read as end of file).
    pub fn set_geometry(&mut self, sector: u64, limit: Option<u64>) {
        let sector = sector.max(1);
        if !(self.block as u64).is_multiple_of(sector) {
            self.block = (self.block as u64).div_ceil(sector) as usize * sector as usize;
            self.buf = vec![0; self.block];
        }
        self.sector = sector;
        self.limit = limit;
        self.buf_len = 0;
    }

    fn fill(&mut self) -> io::Result<()> {
        let start = self.pos - self.pos % self.block as u64;
        let mut len = self.block as u64;
        if let Some(limit) = self.limit {
            len = len.min((limit.saturating_sub(start)).div_ceil(self.sector) * self.sector);
        }
        self.buf_start = start;
        self.buf_len = 0;
        if len == 0 {
            return Ok(());
        }
        self.inner.seek(SeekFrom::Start(start))?;
        let mut filled = 0usize;
        while (filled as u64) < len {
            match self.inner.read(&mut self.buf[filled..len as usize]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
            // A short read that is not a sector multiple only happens at the end of the device.
            if !(filled as u64).is_multiple_of(self.sector) {
                break;
            }
        }
        self.buf_len = filled;
        Ok(())
    }
}

impl<R: Read + Seek> Read for AlignedReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let end = self.limit.unwrap_or(u64::MAX);
        if self.pos >= end {
            return Ok(0);
        }
        let cached = self.pos >= self.buf_start && self.pos < self.buf_start + self.buf_len as u64;
        if !cached {
            self.fill()?;
            if self.pos >= self.buf_start + self.buf_len as u64 {
                return Ok(0);
            }
        }
        let off = (self.pos - self.buf_start) as usize;
        let n = out
            .len()
            .min(self.buf_len - off)
            .min((end - self.pos).min(usize::MAX as u64) as usize);
        out[..n].copy_from_slice(&self.buf[off..off + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for AlignedReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
            SeekFrom::End(d) => {
                let end = match self.limit {
                    Some(l) => l,
                    None => self.inner.seek(SeekFrom::End(0))?,
                };
                end.checked_add_signed(d)
            }
        };
        self.pos = new.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start of the volume",
            )
        })?;
        Ok(self.pos)
    }
}

/// One partition of a disk image: offsets are relative to the partition start.
pub struct OffsetReader<R> {
    inner: R,
    offset: u64,
    len: Option<u64>,
}

impl<R: Read + Seek> OffsetReader<R> {
    pub fn new(inner: R, offset: u64, len: Option<u64>) -> OffsetReader<R> {
        OffsetReader { inner, offset, len }
    }
}

impl<R: Read + Seek> Read for OffsetReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<R: Read + Seek> Seek for OffsetReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let abs = match pos {
            SeekFrom::Start(n) => self.offset.checked_add(n),
            SeekFrom::Current(d) => self.inner.stream_position()?.checked_add_signed(d),
            SeekFrom::End(d) => match self.len {
                Some(l) => (self.offset + l).checked_add_signed(d),
                None => self.inner.seek(SeekFrom::End(0))?.checked_add_signed(d),
            },
        };
        let abs = abs.filter(|a| *a >= self.offset).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "seek outside the partition")
        })?;
        Ok(self.inner.seek(SeekFrom::Start(abs))? - self.offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A device that rejects reads whose offset or length is not a multiple of 512, like a volume handle.
    struct Sectors {
        data: Cursor<Vec<u8>>,
        reads: usize,
    }

    impl Read for Sectors {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.data.position().is_multiple_of(512) || !buf.len().is_multiple_of(512) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unaligned read",
                ));
            }
            self.reads += 1;
            self.data.read(buf)
        }
    }

    impl Seek for Sectors {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.data.seek(pos)
        }
    }

    fn device(len: usize) -> (Vec<u8>, Sectors) {
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let dev = Sectors {
            data: Cursor::new(data.clone()),
            reads: 0,
        };
        (data, dev)
    }

    #[test]
    fn serves_unaligned_ranges_with_aligned_reads_only() {
        let (data, dev) = device(512 * 40);
        let mut r = AlignedReader::new(dev, 512, 4096);
        for (off, len) in [
            (0usize, 1usize),
            (3, 700),
            (511, 2),
            (4095, 3),
            (5000, 9000),
            (20000, 480),
        ] {
            r.seek(SeekFrom::Start(off as u64)).unwrap();
            let mut got = vec![0u8; len];
            r.read_exact(&mut got).unwrap();
            assert_eq!(got, data[off..off + len], "{} {}", off, len);
        }
        // Cached: a second read inside the same block does not touch the device.
        let before = r.inner.reads;
        r.seek(SeekFrom::Start(20001)).unwrap();
        let mut b = [0u8; 10];
        r.read_exact(&mut b).unwrap();
        assert_eq!(r.inner.reads, before);
        // Reading to the end stops at the device end.
        r.seek(SeekFrom::End(-5)).unwrap();
        let mut rest = vec![];
        r.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, data[data.len() - 5..]);
    }

    #[test]
    fn limit_shortens_the_last_block_to_whole_sectors() {
        let (data, dev) = device(512 * 10);
        let mut r = AlignedReader::new(dev, 512, 4096);
        // The volume ends 100 bytes into sector 9: reads never ask past sector 9's end and stop at the limit.
        r.set_geometry(512, Some(512 * 9 + 100));
        r.seek(SeekFrom::Start(4000)).unwrap();
        let mut got = vec![];
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, data[4000..512 * 9 + 100]);
        assert_eq!(r.seek(SeekFrom::End(0)).unwrap(), 512 * 9 + 100);
    }

    #[test]
    fn unaligned_reads_are_really_rejected_by_the_fake() {
        let (_, mut dev) = device(1024);
        dev.seek(SeekFrom::Start(3)).unwrap();
        assert!(dev.read(&mut [0u8; 512]).is_err());
    }

    #[test]
    fn offset_reader_windows_a_partition() {
        let data: Vec<u8> = (0..2048u32).map(|i| i as u8).collect();
        let mut r = OffsetReader::new(Cursor::new(data.clone()), 1024, Some(512));
        r.seek(SeekFrom::Start(10)).unwrap();
        let mut b = [0u8; 4];
        r.read_exact(&mut b).unwrap();
        assert_eq!(b, data[1034..1038]);
        assert_eq!(r.seek(SeekFrom::End(0)).unwrap(), 512);
        assert!(r.seek(SeekFrom::Current(-1000)).is_err());
    }
}
