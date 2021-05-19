use digest::{generic_array::GenericArray, Digest};
use md5::Md5;
use positioned_io::{Cursor, ReadAt};
use reqwest::blocking::Body;
use std::{
    fs::File,
    io::{copy, Read, Result as IOResult},
    sync::Arc,
};

#[derive(Debug, Clone)]
pub(super) struct PartReader {
    source: UploadSource,
    start_from: u64,
    len: u64,
}

impl PartReader {
    #[inline]
    pub(super) fn new(source: UploadSource, start_from: u64, len: u64) -> Self {
        Self {
            source,
            start_from,
            len,
        }
    }

    #[inline]
    pub(super) fn body(&self, size: u64) -> Body {
        Body::sized(self.reader(), size)
    }

    #[inline]
    pub(super) fn md5(&self) -> IOResult<(u64, GenericArray<u8, <Md5 as Digest>::OutputSize>)> {
        let mut hasher = Md5::new();
        let size = copy(&mut self.reader(), &mut hasher)?;
        Ok((size, hasher.finalize()))
    }

    #[inline]
    fn reader(&self) -> impl Read + Send + 'static {
        Cursor::new_pos(self.source.to_owned(), self.start_from).take(self.len)
    }
}

#[derive(Debug, Clone)]
pub(super) enum UploadSource {
    File(Arc<File>),
    Data(Arc<Vec<u8>>),
}

impl UploadSource {
    #[inline]
    pub(super) fn part(self, part_size: u64) -> UploadSourcePartitioner {
        UploadSourcePartitioner {
            source: self,
            offset_size: 0,
            part_size,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct UploadSourcePartitioner {
    source: UploadSource,
    part_size: u64,
    offset_size: u64,
}

impl UploadSourcePartitioner {
    pub(super) fn next_part_reader(&mut self) -> IOResult<Option<PartReader>> {
        let mut one_byte_buf = [0u8; 1];
        let start_from = self.offset_size;
        let got_byte = self.source.read_at(start_from, &mut one_byte_buf)?;

        if got_byte == 0 {
            Ok(None)
        } else {
            self.offset_size += self.part_size;
            Ok(Some(PartReader {
                source: self.source.to_owned(),
                len: self.part_size,
                start_from,
            }))
        }
    }
}

impl ReadAt for UploadSource {
    #[inline]
    fn read_at(&self, pos: u64, buf: &mut [u8]) -> IOResult<usize> {
        match self {
            Self::File(file) => file.read_at(pos, buf),
            Self::Data(data) => data.read_at(pos, buf),
        }
    }
}
