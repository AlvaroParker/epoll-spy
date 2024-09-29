use bytes::BytesMut;
use std::fmt;

use super::{EpollData, EpollEvent, Events};

pub struct EpollCtl {
    pid: u32,
    epfd: u64,
    op: u64,
    fd: u64,
    epoll_event: EpollEvent,
    return_value: i64,
}

impl EpollCtl {
    pub fn new(bytes: BytesMut) -> Option<Self> {
        if let Some(raw) = RawEpollCtl::new(bytes) {
            let raw_event = raw.epoll_event;
            let events =
                u32::from_le_bytes([raw_event[0], raw_event[1], raw_event[2], raw_event[3]]);
            let data = u64::from_le_bytes([
                raw_event[4],
                raw_event[5],
                raw_event[6],
                raw_event[7],
                raw_event[8],
                raw_event[9],
                raw_event[10],
                raw_event[11],
            ]);
            let epoll_event = EpollEvent {
                events: Events::from_bits(events).unwrap_or_default(),
                data: EpollData { uint64: data },
            };
            return Some(Self {
                pid: raw.pid,
                epfd: raw.epfd,
                op: raw.op,
                fd: raw.fd,
                epoll_event,
                return_value: raw.return_value,
            });
        }
        None
    }
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct RawEpollCtl {
    pid: u32,
    epfd: u64,
    op: u64,
    fd: u64,
    epoll_event: [u8; 12],
    return_value: i64,
}

impl RawEpollCtl {
    pub fn new(mut bytes: BytesMut) -> Option<Self> {
        if bytes.len() < std::mem::size_of::<Self>() {
            return None;
        }
        Some(unsafe {
            let raw_ptr = bytes.as_mut_ptr() as *const Self;
            // Move the data out of the raw pointer and consume the BytesMut
            std::ptr::read(raw_ptr)
        })
    }
}

impl fmt::Display for EpollCtl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let op_str = match self.op {
            1 => "EPOLL_CTL_ADD",
            2 => "EPOLL_CTL_DEL",
            3 => "EPOLL_CTL_MOD",
            _ => "INVALID_OPCODE",
        };
        write!(
            f,
            "(pid: {}) epoll_ctl({}, {}, {}, {}) = {}",
            self.pid, self.epfd, op_str, self.fd, self.epoll_event, self.return_value
        )
    }
}
