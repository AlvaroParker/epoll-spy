use bitflags::bitflags;
use std::fmt;

mod epoll_ctl;

pub use epoll_ctl::EpollCtl;

pub struct EpollEvent {
    events: Events,
    data: EpollData,
}

pub union EpollData {
    uint32: u32,
    uint64: u64,
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

impl fmt::Display for EpollData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let uint32 = unsafe { self.uint32 };
        let uint64 = unsafe { self.uint64 };
        write!(f, "{{ u32: {}, u64: {} }}", uint32, uint64)
    }
}

impl fmt::Display for EpollEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{{ events={{ {} }}, data={} }}", self.events, self.data)
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
