#!/usr/bin/env python3
#Roll no : 23P-0569....
import argparse
import heapq
import random
import struct
import sys

DATA, ACK = 0, 1


# Packet format + Internet checksum.......
# this formate will follow packet = [type (1 byte)][seq (2 bytes)][payload][checksum (2 bytes)]
def internet_checksum(data: bytes) -> int:
    """16-bit one's complement sum of the data, then inverted."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)  #this will  wraparounds carry and take complement...
    return (~total) & 0xFFFF


def make_pkt(ptype: int, seq: int, payload: bytes = b"") -> bytes:
    body = struct.pack(">BH", ptype, seq) + payload
    return body + struct.pack(">H", internet_checksum(body))


def parse_pkt(raw: bytes):
    #this will return (ok, type, seq, payload). if ok=False means corrupted packet.....
    if len(raw) < 5:
        return False, None, None, None
    body, chk = raw[:-2], struct.unpack(">H", raw[-2:])[0]
    if internet_checksum(body) != chk:
        return False, None, None, None
    ptype, seq = struct.unpack(">BH", body[:3])
    return True, ptype, seq, body[3:]


def flip_random_bit(raw: bytes, rng: random.Random) -> bytes:
    b = bytearray(raw)
    pos = rng.randrange(len(b) * 8)
    b[pos // 8] ^= 1 << (pos % 8)
    return bytes(b)


def make_payload(idx: int) -> bytes:
    return b"MSG%06d" % idx  # stands in for a 1000-byte message


#this is simulator like event queue, timers and also channell......
class Sim:
    def __init__(self, a):
        self.a = a
        self.rng = random.Random(a.seed)
        self.M = 2 ** a.k                      # seq number....
        self.now = 0.0                         
        self.q, self.cnt = [], 0               # this is event queue
        self.tx_time = a.packet_bytes * 8 / (a.bandwidth_mbps * 1e6) * 1000 
        self.link_free = 0.0                   # sender link is busy until this time...
        self.forced = set(a.force_loss)        # packets whose 1st transmission is dropped.....
        self.timers, self.tok = {}, 0
        self.delivered_count = 0
        self.st = dict.fromkeys(
            ["data_sent", "retransmissions", "acks_sent", "pkts_lost", "acks_lost",
             "pkts_corrupted", "acks_corrupted", "delayed", "timeouts",
             "corrupt_detected", "delivered_correct", "delivered_wrong", "end_time"], 0)
        if a.protocol == "gbn":
            self.sender, self.receiver = GBNSender(self), GBNReceiver(self)
        else:
            self.sender, self.receiver = SRSender(self), SRReceiver(self)

    # ---- helpers ----
    def log(self, who, msg, t=None):
        if not self.a.quiet:
            print(f"[{(self.now if t is None else t):9.1f} ms] {who:<8} {msg}")

    def schedule(self, t, kind, data):
        heapq.heappush(self.q, (t, self.cnt, kind, data))
        self.cnt += 1

    def start_timer(self, key, expire):
        self.tok += 1
        self.timers[key] = self.tok            # a newer token invalidates the old timer....
        self.schedule(expire, "timer", (key, self.tok))

    def stop_timer(self, key):
        self.timers.pop(key, None)

    #here is sending packets on the link......
    def send_data(self, idx, retx, info=""):
        """Put data packet #idx on the link. Returns the time it leaves the sender."""
        t = max(self.now, self.link_free)
        self.link_free = t + self.tx_time      # one packet at a time: L/R each.....
        self.st["data_sent"] += 1
        if retx:
            self.st["retransmissions"] += 1
        raw = make_pkt(DATA, idx % self.M, make_payload(idx))
        self.log("SENDER", ("RETRANSMIT" if retx else "SEND") + f" pkt seq={idx % self.M} (#{idx})" + info, t)
        self.channel(raw, "data", t, f"pkt seq={idx % self.M} (#{idx})", idx)
        return t

    def send_ack(self, seq):
        self.st["acks_sent"] += 1
        self.channel(make_pkt(ACK, seq), "ack", self.now, f"ACK seq={seq}")

    def channel(self, raw, kind, t, label, idx=None):
        """Unreliable channel: loss, then corruption, then extra delay."""
        a = self.a
        r_loss, r_cor, r_del = self.rng.random(), self.rng.random(), self.rng.random()
        forced = kind == "data" and idx in self.forced
        if forced:
            self.forced.discard(idx)           # only the FIRST transmission is dropped
        if forced or r_loss < a.loss:
            self.st["pkts_lost" if kind == "data" else "acks_lost"] += 1
            self.log("CHANNEL", f"X  {label} LOST", t)
            return
        if r_cor < a.corrupt:
            raw = flip_random_bit(raw, self.rng)
            self.st["pkts_corrupted" if kind == "data" else "acks_corrupted"] += 1
            self.log("CHANNEL", f"~  {label} CORRUPTED (bit flipped)", t)
        extra = 0.0
        if r_del < a.delay:
            extra = self.rng.uniform(0, a.delay_max)
            self.st["delayed"] += 1
            self.log("CHANNEL", f"...{label} DELAYED +{extra:.0f} ms", t)
        self.schedule(t + a.prop_delay + extra, "rcv_data" if kind == "data" else "rcv_ack", raw)

    #application delivery this will checks correctness and order....
    def deliver(self, payload):
        try:
            got = int(payload[3:])
        except ValueError:
            got = -1
        if got == self.delivered_count:
            self.st["delivered_correct"] += 1
        else:
            self.st["delivered_wrong"] += 1
        self.delivered_count += 1
        self.log("RECEIVER", f"  -> delivered to application: {payload.decode(errors='replace')}")

    # ---- main loop ----
    def run(self):
        self.sender.fill()
        while self.q and not self.sender.done:
            t, _, kind, data = heapq.heappop(self.q)
            self.now = t
            if t > self.a.max_time:
                self.log("SIM", "max simulated time reached, stopping")
                break
            if kind == "rcv_data":
                self.receiver.on_packet(data)
            elif kind == "rcv_ack":
                self.sender.on_ack(data)
            elif kind == "timer":
                key, tok = data
                if self.timers.get(key) == tok:  # ignore stopped / replaced timers
                    del self.timers[key]
                    self.sender.on_timeout(key)
        self.st["end_time"] = self.now
        return self.st



# GBN  
class GBNSender:
    """One timer for the oldest unACKed packet. Cumulative ACKs. Go-back resend."""

    def __init__(self, sim):
        self.s, self.a = sim, sim.a
        self.base = 0          # oldest unACKed packet
        self.nextseqnum = 0    # next packet to send

    @property
    def done(self):
        return self.base >= self.a.packets

    def win(self):
        return f"base={self.base} nextseqnum={self.nextseqnum} window=[{self.base}-{self.base + self.a.window - 1}]"

    def fill(self):
        while self.nextseqnum < self.base + self.a.window and self.nextseqnum < self.a.packets:
            idx = self.nextseqnum
            self.nextseqnum += 1
            t = self.s.send_data(idx, retx=False, info=f"  | {self.win()}")
            if self.base == idx:               # first packet in flight -> start the one timer
                self.s.start_timer("gbn", t + self.a.timeout)

    def on_ack(self, raw):
        ok, ptype, seq, _ = parse_pkt(raw)
        if not ok or ptype != ACK:
            self.s.st["corrupt_detected"] += 1
            self.s.log("SENDER", "got corrupted ACK -> checksum error, ignored")
            return
        offset = (seq - self.base) % self.s.M
        if offset < self.nextseqnum - self.base:        # ACK(n) with n in [base, nextseqnum-1]
            n = self.base + offset
            self.base = n + 1                            # cumulative ACK: everything up to n
            self.s.log("SENDER", f"got cumulative ACK seq={seq} (ACKs up to #{n})  | {self.win()}")
            if self.base == self.nextseqnum:
                self.s.stop_timer("gbn")
            else:
                self.s.start_timer("gbn", self.s.now + self.a.timeout)  # restart for new oldest
            self.fill()
        else:
            self.s.log("SENDER", f"got duplicate ACK seq={seq}, ignored  | {self.win()}")

    def on_timeout(self, key):
        self.s.st["timeouts"] += 1
        self.s.log("SENDER", f"TIMEOUT for oldest unACKed pkt #{self.base} -> go back, resend #{self.base}..#{self.nextseqnum - 1}")
        first = None
        for idx in range(self.base, self.nextseqnum):
            t = self.s.send_data(idx, retx=True)
            first = t if first is None else first
        self.s.start_timer("gbn", first + self.a.timeout)


class GBNReceiver:
    """Only expectedseqnum. Out-of-order packets are discarded; ACK last in-order."""

    def __init__(self, sim):
        self.s = sim
        self.expectedseqnum = 0

    def reack(self):
        if self.expectedseqnum > 0:
            self.s.send_ack((self.expectedseqnum - 1) % self.s.M)
        else:
            self.s.log("RECEIVER", "  nothing delivered yet -> no ACK")

    def on_packet(self, raw):
        ok, ptype, seq, payload = parse_pkt(raw)
        if not ok or ptype != DATA:
            self.s.st["corrupt_detected"] += 1
            self.s.log("RECEIVER", f"got corrupted packet -> checksum error, discarded | expectedseqnum={self.expectedseqnum}")
            self.reack()
            return
        if seq == self.expectedseqnum % self.s.M:
            self.s.log("RECEIVER", f"got pkt seq={seq} IN ORDER (#{self.expectedseqnum}) -> deliver, send ACK{seq}")
            self.s.deliver(payload)
            self.expectedseqnum += 1
            self.s.send_ack(seq)
        else:
            self.s.log("RECEIVER", f"got pkt seq={seq} OUT OF ORDER (expectedseqnum={self.expectedseqnum % self.s.M}) -> DISCARD")
            self.reack()


# SR SELECTIVE REPEAT .... 
class SRSender:
    """A timer per packet. Individual ACKs. Resend only the packet that timed out."""

    def __init__(self, sim):
        self.s, self.a = sim, sim.a
        self.base = 0          # oldest unACKed packet (sendbase)
        self.nextseqnum = 0
        self.acked = set()     # packets inside the window already ACKed

    @property
    def done(self):
        return self.base >= self.a.packets

    def win(self):
        return f"base={self.base} nextseqnum={self.nextseqnum} sender window=[{self.base}-{self.base + self.a.window - 1}]"

    def fill(self):
        while self.nextseqnum < self.base + self.a.window and self.nextseqnum < self.a.packets:
            idx = self.nextseqnum
            self.nextseqnum += 1
            t = self.s.send_data(idx, retx=False, info=f"  | {self.win()}")
            self.s.start_timer(("sr", idx), t + self.a.timeout)  #timer per packet.....

    def on_ack(self, raw):
        ok, ptype, seq, _ = parse_pkt(raw)
        if not ok or ptype != ACK:
            self.s.st["corrupt_detected"] += 1
            self.s.log("SENDER", "got corrupted ACK -> checksum error, ignored")
            return
        offset = (seq - self.base) % self.s.M
        idx = self.base + offset
        if offset < self.a.window and idx < self.nextseqnum and idx not in self.acked:
            self.acked.add(idx)                          #individual ACK this wil mark ONLY this packet...
            self.s.stop_timer(("sr", idx))
            self.s.log("SENDER", f"got individual ACK seq={seq} -> mark #{idx} as received")
            moved = False
            while self.base in self.acked:               # slide window past consecutive ACKed pkts
                self.acked.discard(self.base)
                self.base += 1
                moved = True
            self.s.log("SENDER", ("window moved  | " if moved else "base stays (smallest unACKed not ACKed yet)  | ") + self.win())
            self.fill()
        else:
            self.s.log("SENDER", f"got ACK seq={seq} for already-ACKed / old packet, ignored")

    def on_timeout(self, key):
        idx = key[1]
        if idx < self.base or idx in self.acked:
            return
        self.s.st["timeouts"] += 1
        self.s.log("SENDER", f"TIMEOUT for pkt #{idx} -> resend ONLY #{idx}")
        t = self.s.send_data(idx, retx=True)
        self.s.start_timer(("sr", idx), t + self.a.timeout)


class SRReceiver:
    """Receiver window [rcv_base, rcv_base+N-1]. Buffers out-of-order, ACKs each packet."""

    def __init__(self, sim):
        self.s, self.a = sim, sim.a
        self.rcv_base = 0
        self.buffer = {}       # absolute number....payload

    def win(self):
        return f"rcv_base={self.rcv_base} receiver window=[{self.rcv_base}-{self.rcv_base + self.a.window - 1}]"

    def on_packet(self, raw):
        ok, ptype, seq, payload = parse_pkt(raw)
        if not ok or ptype != DATA:
            self.s.st["corrupt_detected"] += 1
            self.s.log("RECEIVER", "got corrupted packet -> checksum error, discarded (no ACK)")
            return
        N, M = self.a.window, self.s.M
        offset = (seq - self.rcv_base) % M
        if offset < N:                                   # seq in [rcv_base, rcv_base+N-1]
            idx = self.rcv_base + offset
            self.s.send_ack(seq)                         # individual ACK
            if idx in self.buffer:
                self.s.log("RECEIVER", f"got duplicate pkt seq={seq} (#{idx}) already buffered -> re-ACK")
                return
            self.buffer[idx] = payload
            if idx == self.rcv_base:
                self.s.log("RECEIVER", f"got pkt seq={seq} (#{idx}) = rcv_base -> ACK{seq}, deliver in order")
                while self.rcv_base in self.buffer:      # deliver this + any buffered inn order pkts
                    self.s.deliver(self.buffer.pop(self.rcv_base))
                    self.rcv_base += 1
                self.s.log("RECEIVER", f"  window moved | {self.win()}")
            else:
                self.s.log("RECEIVER", f"got pkt seq={seq} (#{idx}) OUT OF ORDER -> BUFFER, ACK{seq} | {self.win()}")
        elif offset >= M - N:                            # seq in [rcv_base-N, rcv_base-1]: old packet
            self.s.log("RECEIVER", f"got old pkt seq={seq} (already delivered) -> re-ACK{seq}")
            self.s.send_ack(seq)
        else:
            self.s.log("RECEIVER", f"got pkt seq={seq} outside receiver window -> ignored")


# command line......
def build_parser():
    p = argparse.ArgumentParser(description="GBN / SR over a simulated unreliable channel")
    p.add_argument("--protocol", choices=["gbn", "sr"], required=True)
    p.add_argument("--packets", type=int, default=20, help="number of data packets to send")
    p.add_argument("--window", type=int, default=4, help="window size N")
    p.add_argument("--k", type=int, default=3, help="sequence-number bits (numbers wrap modulo 2^k)")
    p.add_argument("--loss", type=float, default=0.0, help="loss probability (packets and ACKs)")
    p.add_argument("--corrupt", type=float, default=0.0, help="corruption probability (packets and ACKs)")
    p.add_argument("--delay", type=float, default=0.0, help="probability of extra delay (packets and ACKs)")
    p.add_argument("--timeout", type=float, default=600.0, help="timeout in ms (must be > RTT)")
    p.add_argument("--seed", type=int, default=569, help="random seed (last 4 digits of roll no: 0569)")
    p.add_argument("--prop-delay", type=float, default=250.0, help="one-way propagation delay in ms (RTT/2)")
    p.add_argument("--bandwidth-mbps", type=float, default=2.0, help="link rate R in Mbps")
    p.add_argument("--packet-bytes", type=int, default=1000, help="packet size L in bytes")
    p.add_argument("--delay-max", type=float, default=500.0, help="max extra delay in ms when a packet is delayed")
    p.add_argument("--force-loss", type=int, nargs="*", default=[],
                   help="packet numbers whose FIRST transmission is dropped (e.g. --force-loss 2)")
    p.add_argument("--max-time", type=float, default=1e9, help="stop simulation after this many ms")
    p.add_argument("--quiet", action="store_true", help="do not print the event log")
    return p


def simulate(**overrides):
    """Run one simulation from Python (used by run_experiments.py). Returns the stats dict."""
    defaults = vars(build_parser().parse_args(["--protocol", overrides.get("protocol", "gbn")]))
    defaults.update(overrides)
    a = argparse.Namespace(**defaults)
    check_args(a)
    return Sim(a).run()


def check_args(a):
    M = 2 ** a.k
    if a.window < 1:
        sys.exit("window must be >= 1")
    if a.protocol == "gbn" and a.window > M - 1:
        sys.exit(f"GBN needs window <= 2^k - 1 = {M - 1}")
    if a.protocol == "sr" and a.window > M // 2 and not a.quiet:
        print(f"WARNING: SR needs window <= 2^k / 2 = {M // 2}. With N={a.window} the receiver can "
              f"mistake an old packet for a new one (see Task 5). Wrong deliveries will be reported.\n")


def main():
    a = build_parser().parse_args()
    check_args(a)
    sim = Sim(a)
    print(f"=== {a.protocol.upper()} | packets={a.packets} N={a.window} k={a.k} (seq space 0..{sim.M - 1}) "
          f"loss={a.loss} corrupt={a.corrupt} delay={a.delay} timeout={a.timeout} ms seed={a.seed} ===")
    st = sim.run()
    ok = st["delivered_correct"] == a.packets and st["delivered_wrong"] == 0
    secs = st["end_time"] / 1000
    thr = st["delivered_correct"] * a.packet_bytes * 8 / secs / 1000 if secs > 0 else 0
    print("\n--- SUMMARY ---")
    print(f"packets transmitted (incl. retransmissions) : {st['data_sent']}")
    print(f"retransmissions                              : {st['retransmissions']}")
    print(f"timeouts                                     : {st['timeouts']}")
    print(f"ACKs sent                                    : {st['acks_sent']}")
    print(f"data packets lost / corrupted                : {st['pkts_lost']} / {st['pkts_corrupted']}")
    print(f"ACKs lost / corrupted                        : {st['acks_lost']} / {st['acks_corrupted']}")
    print(f"packets/ACKs delayed                         : {st['delayed']}")
    print(f"corruption detected by checksum              : {st['corrupt_detected']}")
    print(f"packets delivered correctly and in order     : {st['delivered_correct']} / {a.packets}")
    print(f"wrong deliveries (ambiguity)                 : {st['delivered_wrong']}")
    print(f"total time                                   : {st['end_time']:.1f} ms")
    print(f"throughput                                   : {thr:.2f} kbps")
    print("RESULT:", "SUCCESS - all packets delivered correctly and in order" if ok else "FAILED")


if __name__ == "__main__":
    main()
