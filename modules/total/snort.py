from ctypes import *

ALERTMSG_LENGTH = 256
SNAPLEN = 1514

time_t = suseconds_t = c_long

class timeval(Structure):
    _fields_ = [('tv_sec', time_t),
		('tv_usec', suseconds_t)]

class Event(Structure):
    _fields_ = [('sig_generator', c_uint32),
		('sig_id', c_uint32),
		('sig_rev', c_uint32),
		('classification', c_uint32),
		('priority', c_uint32),
		('event_id', c_uint32),
		('event_reference', c_uint32),
		('ref_time', timeval)
    ]

class pcap_pkthdr(Structure):
    _fields_ = [('ts', timeval),
		('caplen', c_uint32),
		('len', c_uint32)]

class Alertpkt(Structure):
    _fields_ = [('alertmsg', (c_uint8 * ALERTMSG_LENGTH)),
		('pkth', pcap_pkthdr),
		('dlthdr', c_uint32),
		('nethdr', c_uint32),
		('transhdr', c_uint32),
		('data', c_uint32),
		('val', c_uint32),
		('pkt', (c_uint8 * SNAPLEN)),
		('event', Event)
    ]
    str_format = "[%s]" % ', '.join(['{0.%s}' % f[0] for f in _fields_])
