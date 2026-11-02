import struct
import unittest

from research.live_tcp import ControlTCP, decode_segment, encode_segment, tcp_checksum
from research.live_relay import RelayProtocolError


class ControlTCPTests(unittest.TestCase):
    def connected(self, initial=100, peer=200):
        tcp = ControlTCP(initial)
        replies, frames = tcp.receive(encode_segment(peer, 0, 2, syn=True))
        response = decode_segment(replies[0])
        self.assertEqual((response.sequence, response.acknowledgement, response.flags),
                         (initial, (peer+1)&0xffffffff, 0x12))
        tcp.receive(encode_segment((peer+1)&0xffffffff, (initial+1)&0xffffffff, 0x10))
        self.assertTrue(tcp.established)
        return tcp

    def test_checksum_uses_zero_address_ipv6_pseudoheader(self):
        raw = encode_segment(100, 200, 0x10)
        self.assertEqual(tcp_checksum(raw[1:]), 0)
        for bad in (raw[:-1], raw[:4]+bytes([raw[4]^1])+raw[5:], b"\0"+raw[1:]):
            with self.assertRaises(RelayProtocolError):
                decode_segment(bad)

    def test_partial_frames_duplicates_out_of_order_and_sequence_wrap(self):
        tcp = self.connected(peer=0xfffffffc)
        data = b"\0\x06abcdef\0\x02gh"
        seq = tcp.receive_next
        _, frames = tcp.receive(encode_segment((seq+3)&0xffffffff, 101, 0x18, data[3:]))
        self.assertEqual(frames, [])
        self.assertEqual(tcp.receive_next, seq)
        _, frames = tcp.receive(encode_segment(seq, 101, 0x18, data[:5]))
        self.assertEqual(frames, [])
        _, frames = tcp.receive(encode_segment(seq, 101, 0x18, data))
        self.assertEqual(frames, [b"abcdef", b"gh"])
        _, frames = tcp.receive(encode_segment(seq, 101, 0x18, data))
        self.assertEqual(frames, [])

    def test_sending_frames_and_acknowledgements(self):
        tcp = self.connected()
        packets = tcp.send_frame(b"x"*1300)
        self.assertEqual(len(packets), 2)
        data = b"".join(decode_segment(p).payload for p in packets)
        self.assertEqual(data, struct.pack("!H", 1300)+b"x"*1300)
        with self.assertRaises(RelayProtocolError):
            tcp.receive(encode_segment(201, tcp.send_next+1, 0x10))
        tcp.receive(encode_segment(201, tcp.send_next, 0x10))
        self.assertEqual(tcp.unacknowledged, [])

    def test_handshake_and_window_are_required(self):
        with self.assertRaises(RelayProtocolError):
            ControlTCP().receive(encode_segment(201, 101, 0x10))
        tcp = self.connected()
        with self.assertRaises(RelayProtocolError):
            tcp.receive(encode_segment(999, 0, 2, syn=True))
        with self.assertRaises(RelayProtocolError):
            tcp.send_frame(b"x"*65535)
        tcp.receive(encode_segment(201, 101, 0x11))
        self.assertTrue(tcp.closed)

    def test_lost_ack_retransmits_boundedly_and_progress_resets_timer(self):
        tcp = self.connected()
        packets = tcp.send_frame(b"fixture")
        self.assertEqual(tcp.retransmit(0), [])
        self.assertEqual(tcp.retransmit(1), packets)
        self.assertEqual(tcp.retransmit(2), [])
        self.assertEqual(tcp.retransmit(3), packets)
        tcp.receive(encode_segment(201, tcp.send_next, 0x10))
        self.assertEqual(tcp.retransmit(100), [])
        tcp.send_frame(b"second")
        tcp.retransmit(101)
        for now in (102, 104, 108, 116, 124, 132):
            self.assertTrue(tcp.retransmit(now))
        with self.assertRaises(TimeoutError):
            tcp.retransmit(140)


if __name__ == "__main__":
    unittest.main()
