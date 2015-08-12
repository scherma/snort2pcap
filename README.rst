==========
snort2pcap
==========

*Feed in snort events, get pcaps out*

**Usage**

Call write_pcap with the following arguments:

*required*
- packets; see data structure below
- fpath; file path, must not already exist
*optional*
- snaplen=123; max length of captured packets, in octets (see libpcap file format)
- linktype=1; since dummy MACs have been hard coded, probably best to leave this alone


| ``list = [packet_1, packet_2, ... packet_n]``
|  
| ``packet_n = (snort_packet_descriptor, packet_data)``

| ``snort_packet_descriptor = {``
| ``"sensor_id": 123,               # number``
| ``"event_id": 234,                # number``
| ``"packet_second": 345,           # number``
| ``"packet_microsecond": 456,      # number``
| ``"linktype": 7,                  # number``
| ``"packet_length": 890,           # number``
| ``"packet_data": "AAAAb=="        # base64 string``
| ``}``
|
| ``packet_data = "AAAAb=="             # base64 string``
