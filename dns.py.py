import socket
import struct
import random   #for random id


DNS_PORT = 53  # DNS always uses port 53

TIMEOUT_SECONDS = 4      # wait this many seconds for a reply, then treat it as timeout,,,,

# this rcode tells us if the lookup worked or failed (like NXDOMAIN)....
RCODE_MEANINGS = {
    0: "NOERROR (Success)",
    1: "FORMERR (Format Error)",
    2: "SERVFAIL (Server Failure)",
    3: "NXDOMAIN (Domain does not exist)",
    4: "NOTIMP (Not Implemented)",
    5: "REFUSED",
}


# make the 12 byte DNS header
def build_dns_header(transaction_id):
    flags = 0x0100   # RD = 1, so we ask the server to recurse for us
    qdcount = 1      # we send one question
    ancount = 0
    nscount = 0
    arcount = 0
    # pack 6 numbers as 16-bit big endian values
    header = struct.pack(">HHHHHH", transaction_id, flags, qdcount, ancount, nscount, arcount)
    return header


# change www.google.com into DNS labels like length + text + 0 at the end.....
def encode_domain_name(domain):
    encoded = b""
    parts = domain.strip(".").split(".")
    for label in parts:
        try:
            label_bytes = label.encode("ascii")
        except UnicodeEncodeError:
            return None
        if len(label_bytes) == 0 or len(label_bytes) > 63:
            return None
        encoded = encoded + struct.pack("B", len(label_bytes)) + label_bytes
    encoded = encoded + b"\x00"
    return encoded


# question section: encoded name + type A (1) + class IN (1)
def build_dns_question(domain, qtype=1, qclass=1):
    qname = encode_domain_name(domain)
    if qname is None:
        return None
    qtype_qclass = struct.pack(">HH", qtype, qclass)
    return qname + qtype_qclass


# it will put header and question together to make the full DNS query...
def build_dns_query(domain):
    transaction_id = random.randint(0, 65535)
    header = build_dns_header(transaction_id)
    question = build_dns_question(domain)
    if question is None:
        return None, transaction_id
    message = header + question
    return message, transaction_id


# read the 12 byte header from the response
def parse_dns_header(data):
    if len(data) < 12:
        return None

    unpacked = struct.unpack(">HHHHHH", data[:12])
    transaction_id = unpacked[0]
    flags = unpacked[1]
    qdcount = unpacked[2]
    ancount = unpacked[3]
    nscount = unpacked[4]
    arcount = unpacked[5]

    # it will split the flags into the bits we need to show...
    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 0x1
    tc = (flags >> 9) & 0x1
    rd = (flags >> 8) & 0x1
    ra = (flags >> 7) & 0x1
    rcode = flags & 0xF

    header = {}
    header["id"] = transaction_id
    header["flags"] = flags
    header["qr"] = qr
    header["opcode"] = opcode
    header["aa"] = aa
    header["tc"] = tc
    header["rd"] = rd
    header["ra"] = ra
    header["rcode"] = rcode
    header["qdcount"] = qdcount
    header["ancount"] = ancount
    header["nscount"] = nscount
    header["arcount"] = arcount
    return header


# read a domain name, also follow compression pointers like (0xC0)....
def read_dns_name(data, offset):
    labels = []
    original_offset = None
    jumps = 0

    while True:
        if offset >= len(data):
            return None, offset

        length_byte = data[offset]

        # if top two bits are 11, this is a pointer to an earlier name....
        if (length_byte & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                return None, offset
            pointer = struct.unpack(">H", data[offset:offset + 2])[0]
            pointer_offset = pointer & 0x3FFF
            if original_offset is None:
                original_offset = offset + 2
            offset = pointer_offset
            jumps = jumps + 1
            if jumps > 20:
                return None, offset
            continue

        # 0 means the name is finished
        if length_byte == 0:
            offset = offset + 1
            break

        offset = offset + 1
        if offset + length_byte > len(data):
            return None, offset
        label = data[offset:offset + length_byte].decode("ascii", errors="replace")
        labels.append(label)
        offset = offset + length_byte

    if original_offset is not None:
        final_offset = original_offset
    else:
        final_offset = offset

    name = ".".join(labels)
    return name, final_offset


# this will read the question section from the response (name, type, class)....
def parse_dns_question(data, offset, qdcount):
    qname = ""
    i = 0
    while i < qdcount:
        name, offset = read_dns_name(data, offset)
        if name is None:
            return None, None
        if offset + 4 > len(data):
            return None, None
        qtype_qclass = struct.unpack(">HH", data[offset:offset + 4])
        qname = name
        offset = offset + 4
        i = i + 1
    return qname, offset


# this will read answer records: NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA....
def parse_dns_answers(data, offset, ancount):
    answers = []
    i = 0
    while i < ancount:
        name, offset = read_dns_name(data, offset)
        if name is None:
            return None, offset
        if offset + 10 > len(data):
            return None, offset

        fields = struct.unpack(">HHIH", data[offset:offset + 10])
        rtype = fields[0]
        rclass = fields[1]
        ttl = fields[2]
        rdlength = fields[3]
        offset = offset + 10

        if offset + rdlength > len(data):
            return None, offset

        rdata_raw = data[offset:offset + rdlength]

        record = {}
        record["name"] = name
        record["type"] = rtype
        record["class"] = rclass
        record["ttl"] = ttl

        # type 1 is A record, the IPv4 address we want
        if rtype == 1 and rdlength == 4:
            record["address"] = socket.inet_ntoa(rdata_raw)
        # type 5 is CNAME, it points to another name
        elif rtype == 5:
            cname, unused = read_dns_name(data, offset)
            if cname is None:
                record["address"] = None
            else:
                record["cname"] = cname
        else:
            record["address"] = None

        offset = offset + rdlength
        answers.append(record)
        i = i + 1

    return answers, offset


# this will parse Header, then Question, then Answer....
def parse_dns_response(data):
    header = parse_dns_header(data)
    if header is None:
        return None, None, None

    offset = 12
    qname, offset = parse_dns_question(data, offset, header["qdcount"])
    if offset is None:
        return None, None, None

    answers, offset = parse_dns_answers(data, offset, header["ancount"])
    if answers is None:
        return None, None, None

    return header, qname, answers


# this will send the query with a UDP socket to port 53 and get the reply....
def send_dns_query(domain, dns_server_ip, timeout=TIMEOUT_SECONDS):
    query, transaction_id = build_dns_query(domain)
    if query is None:
        return None, transaction_id, "bad_query"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (dns_server_ip, DNS_PORT))
        response, unused_addr = sock.recvfrom(4096)
        sock.close()
        return response, transaction_id, "ok"
    except socket.timeout:
        sock.close()
        return None, transaction_id, "timeout"
    except OSError:
        sock.close()
        return None, transaction_id, "network"


# this will simple check so a wrong  domain does not crash the program...
def is_valid_domain(domain):
    if domain == "":
        return False
    if len(domain) > 253:
        return False

    labels = domain.strip(".").split(".")
    if len(labels) < 2:
        return False

    for label in labels:
        if label == "":
            return False
        if len(label) > 63:
            return False
        ok = True
        for c in label:
            if c.isalnum() or c == "-":
                continue
            else:
                ok = False
                break
        if ok == False:
            return False

    return True



def lookup_domain(domain, dns_server_ip):
    if is_valid_domain(domain) == False:
        print("Invalid domain name: " + domain)
        print()
        return

    response, sent_id, status = send_dns_query(domain, dns_server_ip)

    if status == "timeout":
        print("Timeout: no response from " + dns_server_ip)
        print()
        return
    if status == "network" or response is None:
        print("Could not send query to DNS server " + dns_server_ip)
        print()
        return

    try:
        header, qname, answers = parse_dns_response(response)
    except (struct.error, IndexError, UnicodeDecodeError):
        print("Malformed DNS response. Skipping this query.")
        print()
        return

    if header is None or answers is None:
        print("Malformed DNS response. Skipping this query.")
        print()
        return

    if qname == "":
        qname = domain

    print("----------------------------------------------------")
    print("Query Name         : " + qname)
    print("Query Type         : A (IPv4 address)")
    print("DNS Server Used    : " + dns_server_ip)
    print("DNS Port           : " + str(DNS_PORT))
    print("Transaction ID     : " + str(header["id"]))
    print("Flags (raw)        : " + hex(header["flags"]) + "  (QR=" + str(header["qr"]) + ", RD=" + str(header["rd"]) + ", RA=" + str(header["ra"]) + ")")

    if header["rcode"] in RCODE_MEANINGS:
        status_text = RCODE_MEANINGS[header["rcode"]]
    else:
        status_text = "Unknown (" + str(header["rcode"]) + ")"

    print("Response Status    : " + status_text)
    print("Answer Count       : " + str(header["ancount"]))

    # NXDOMAIN and other failed rcode values, print status and continue
    if header["rcode"] != 0:
        print("----------------------------------------------------")
        print()
        return

    if len(answers) == 0:
        print("No answer records returned.")
    else:
        print()
        print("Answer Record(s):")
        i = 0
        while i < len(answers):
            rec = answers[i]
            print("  [" + str(i + 1) + "] Name: " + rec["name"])
            if "address" in rec and rec["address"]:
                print("      Type: A | IPv4 Address: " + rec["address"] + " | TTL: " + str(rec["ttl"]) + " sec")
            elif "cname" in rec:
                print("      Type: CNAME | Points to: " + rec["cname"] + " | TTL: " + str(rec["ttl"]) + " sec")
            else:
                print("      Type: " + str(rec["type"]) + " (not A/CNAME) | TTL: " + str(rec["ttl"]) + " sec")
            i = i + 1

    print("----------------------------------------------------")
    print()


# sk DNS server IP once, then many domain names...
def main():
    print("=== Simple DNS Query Client ===")
    dns_server_ip = input("Enter DNS server IP (e.g. 8.8.8.8): ").strip()

    if dns_server_ip == "":
        print("No DNS server IP provided. Exiting.")
        return

    while True:
        domain = input("\nEnter domain name to resolve (or'q' to exit): ").strip()
        if domain.lower() == "q":
            print("Exiting.........")
            break
        if domain == "":
            continue
        lookup_domain(domain, dns_server_ip)


if __name__ == "__main__":
    main()
