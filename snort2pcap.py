#!/usr/bin/env python3

import time, struct, base64, os

class pcap_hdr():
    def __init__(self, snaplen=65535, network=1):
        self.header = struct.pack('@IHHiIII', int('0xa1b2c3d4',16), 2, 4, time.timezone, 0, snaplen, network )

class pkt_hdr():
    def __init__(self, ts_sec, ts_usec, incl_len, orig_len):
        self.header = struct.pack('@IIII', ts_sec, ts_usec, incl_len, orig_len)

class pkt_data():
    def __init__(self, data):
        if isinstance(data, str) or isinstance(data, unicode):
            self.data = base64.b64decode(data)
        else:
            raise ValueError("Packet data in unreadable format.")

def write_pcap(packets, fpath, **kwargs):
    if not os.path.exists(fpath):
        with open(fpath, 'wb') as f:
            hdr = pcap_hdr(**kwargs)
            f.write(hdr.header)
            for (pheader, pdata) in packets:
                pdbin = pkt_data(pdata)
                # need to prep data with dummy MAC and protocol type; snort events do not include this
                pcapbin = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x00' + pdbin.data
                phbin = pkt_hdr(pheader['packet_second'],pheader['packet_microsecond'],len(pcapbin),len(pcapbin))
                f.write(phbin.header)

                f.write(pcapbin)
                
    else:
        raise IOError("Operation not permitted: file already exists.")
    
