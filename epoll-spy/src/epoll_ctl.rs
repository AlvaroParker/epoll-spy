use bitflags::bitflags;
use bytes::BytesMut;
use std::fmt;

pub union EpollData {
    uint32: u32,
    uint64: u64,
}

impl fmt::Display for EpollData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let uint32 = unsafe { self.uint32 };
        let uint64 = unsafe { self.uint64 };
        write!(f, "{{ u32: {}, u64: {} }}", uint32, uint64)
    }
}

pub struct EpollEvent {
    events: Events,
    data: EpollData,
}

impl fmt::Display for EpollEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ events={{ {} }}, data={} }}", self.events, self.data)
    }
}

pub struct EpollCtl {
    epfd: u64,
    op: u64,
    fd: u64,
    epoll_event: EpollEvent,
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
            "epoll_ctl({}, {}, {}, {})",
            self.epfd, op_str, self.fd, self.epoll_event
        )
    }
}

bitflags! {
    #[derive(Clone, Debug , Default)]
    pub struct Events: u32 {
        const EPOLLIN       = 0x001;
        const EPOLLPRI      = 0x002;
        const EPOLLOUT      = 0x004;
        const EPOLLRDNORM   = 0x040;
        const EPOLLRDBAND   = 0x080;
        const EPOLLWRNORM   = 0x100;
        const EPOLLWRBAND   = 0x200;
        const EPOLLMSG      = 0x400;
        const EPOLLERR      = 0x008;
        const EPOLLHUP      = 0x010;
        const EPOLLRDHUP    = 0x2000;
        const EPOLLEXCLUSIVE = 1u32 << 28;
        const EPOLLWAKEUP   = 1u32 << 29;
        const EPOLLONESHOT  = 1u32 << 30;
        const EPOLLET       = 1u32 << 31;
    }
}

impl fmt::Display for Events {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::new();

        if self.contains(Events::EPOLLIN) {
            flags.push("EPOLLIN");
        }
        if self.contains(Events::EPOLLPRI) {
            flags.push("EPOLLPRI");
        }
        if self.contains(Events::EPOLLOUT) {
            flags.push("EPOLLOUT");
        }
        if self.contains(Events::EPOLLRDNORM) {
            flags.push("EPOLLRDNORM");
        }
        if self.contains(Events::EPOLLRDBAND) {
            flags.push("EPOLLRDBAND");
        }
        if self.contains(Events::EPOLLWRNORM) {
            flags.push("EPOLLWRNORM");
        }
        if self.contains(Events::EPOLLWRBAND) {
            flags.push("EPOLLWRBAND");
        }
        if self.contains(Events::EPOLLMSG) {
            flags.push("EPOLLMSG");
        }
        if self.contains(Events::EPOLLERR) {
            flags.push("EPOLLERR");
        }
        if self.contains(Events::EPOLLHUP) {
            flags.push("EPOLLHUP");
        }
        if self.contains(Events::EPOLLRDHUP) {
            flags.push("EPOLLRDHUP");
        }
        if self.contains(Events::EPOLLEXCLUSIVE) {
            flags.push("EPOLLEXCLUSIVE");
        }
        if self.contains(Events::EPOLLWAKEUP) {
            flags.push("EPOLLWAKEUP");
        }
        if self.contains(Events::EPOLLONESHOT) {
            flags.push("EPOLLONESHOT");
        }
        if self.contains(Events::EPOLLET) {
            flags.push("EPOLLET");
        }

        write!(f, "{}", flags.join(" | "))
    }
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
                epfd: raw.epfd,
                op: raw.op,
                fd: raw.fd,
                epoll_event,
            });
        }
        None
    }
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct RawEpollCtl {
    epfd: u64,
    op: u64,
    fd: u64,
    epoll_event: [u8; 12],
}

impl RawEpollCtl {
    pub fn new(mut bytes: BytesMut) -> Option<Self> {
        if bytes.len() != std::mem::size_of::<Self>() {
            return None;
        }
        Some(unsafe {
            let raw_ptr = bytes.as_mut_ptr() as *const Self;
            // Move the data out of the raw pointer and consume the BytesMut
            std::ptr::read(raw_ptr)
        })
    }
}
