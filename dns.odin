package dns_toy

import "core:bytes"
import "core:fmt"
import "core:encoding/hex"
import "core:net"
import "core:io"
import "core:math/rand"
import "core:os"
import "core:slice"
import "core:strings"
import "core:testing"

TYPE_A: u16be = 1
TYPE_NS: u16be = 2
CLASS_IN: u16be = 1
RECURSION_DESIRED: u16be = 1 << 8

main :: proc() {
    if len(os.args) == 1 {
        fmt.eprintln("Must supply a domain to resolve")
        os.exit(1)
    }
    domain := os.args[1]
    addr := cast(net.IP4_Address){198, 41, 0, 4}
    packet := query(addr, domain, record_type = TYPE_A, flags = 0)

    fmt.println(packet)

    for answer in packet.answers {
        #partial switch d in answer.data {
        case Address:
            fmt.printf("answer: %s\n", ip_to_string(d))
        case:
            fmt.eprintln("Logic error, final answer must be an address")
            os.exit(1)
        }
    }
}

query :: proc(
    ip_address: net.IP4_Address,
    domain_name: string,
    record_type: u16be,
    flags: u16be,
) -> DnsPacket {
    rng := rand.create(1)
    id := cast(u16be)rand.int_max(65_535, &rng)
    send_buf: bytes.Buffer
    write_query(domain_name, &send_buf, id = id, flags = flags, record_type = record_type)

    sock, _err := net.make_unbound_udp_socket(net.Address_Family.IP4)
    defer net.close(sock)

    addr := net.Endpoint {
        address = ip_address,
        port    = 53,
    }
    _, err := net.send_udp(sock, bytes.buffer_to_bytes(&send_buf), addr)

    recv_buf: [1024]u8
    bytes_read, _, _ := net.recv_udp(sock, recv_buf[:])

    resp_rdr: bytes.Reader
    bytes.reader_init(&resp_rdr, recv_buf[:bytes_read])
    return packet_from_reader(&resp_rdr)
}

write_query :: proc(
    domain_name: string,
    buf: ^bytes.Buffer,
    id: u16be,
    flags: u16be,
    record_type: u16be,
) {
    header := DnsHeader {
        id            = id,
        flags         = flags,
        num_questions = 1,
    }
    question := DnsQuestion {
        name  = domain_name,
        type  = record_type,
        class = CLASS_IN,
    }

    header_write_buf(header, buf)
    question_write_buf(question, buf)
}

@(test)
test_write_query :: proc(t: ^testing.T) {
    buf: bytes.Buffer
    write_query(
        id = 0x8298,
        domain_name = "www.example.com",
        record_type = TYPE_A,
        buf = &buf,
        flags = RECURSION_DESIRED,
    )
    expected, _ := hex.decode(
        transmute([]u8)string(
            "82980100000100000000000003777777076578616d706c6503636f6d0000010001",
        ),
    )
    testing.expect(t, slice.equal(bytes.buffer_to_bytes(&buf), expected))
}

DnsHeader :: struct #packed {
    id:              u16be,
    flags:           u16be,
    num_questions:   u16be,
    num_answers:     u16be,
    num_authorities: u16be,
    num_additionals: u16be,
}

header_write_buf :: proc(header: DnsHeader, buf: ^bytes.Buffer) {
    header_bytes := transmute([12]u8)header
    bytes.buffer_write(buf, header_bytes[:])
}

header_from_reader :: proc(rdr: ^bytes.Reader) -> DnsHeader {
    buf: [12]u8
    bytes.reader_read(rdr, buf[:])
    return transmute(DnsHeader)buf
}

DnsQuestion :: struct {
    name:  string,
    type:  u16be,
    class: u16be,
}

question_write_buf :: proc(question: DnsQuestion, buf: ^bytes.Buffer) {
    parts := strings.split(question.name, ".")

    for part in parts {
        bytes.buffer_write_byte(buf, cast(u8)len(part))
        bytes.buffer_write_string(buf, part)
    }

    bytes.buffer_write_byte(buf, 0)

    type_bytes := transmute([2]u8)question.type
    bytes.buffer_write(buf, type_bytes[:])

    class_bytes := transmute([2]u8)question.class
    bytes.buffer_write(buf, class_bytes[:])
}

question_from_reader :: proc(rdr: ^bytes.Reader) -> DnsQuestion {
    name := parse_domain_name(rdr)

    type_bytes: [2]u8
    bytes.reader_read(rdr, type_bytes[:])

    class_bytes: [2]u8
    bytes.reader_read(rdr, class_bytes[:])

    return(
        DnsQuestion{
            name = name,
            type = transmute(u16be)type_bytes,
            class = transmute(u16be)class_bytes,
        } \
    )

}

DnsRecord :: struct {
    name:  string,
    type:  u16be,
    class: u16be,
    ttl:   u32be,
    data:  RecordData,
}

RecordData :: union {
    Domain,
    Address,
    Raw,
}

Domain :: distinct string
Address :: distinct net.IP4_Address
Raw :: distinct []u8

record_from_reader :: proc(rdr: ^bytes.Reader) -> DnsRecord {
    name := parse_domain_name(rdr)

    type_bytes: [2]u8
    bytes.reader_read(rdr, type_bytes[:])
    type := transmute(u16be)type_bytes

    class_bytes: [2]u8
    bytes.reader_read(rdr, class_bytes[:])

    ttl_bytes: [4]u8
    bytes.reader_read(rdr, ttl_bytes[:])

    data_len_bytes: [2]u8
    bytes.reader_read(rdr, data_len_bytes[:])
    data_len := transmute(u16be)data_len_bytes

    data: RecordData
    {
        if type == TYPE_NS {
            data = cast(Domain)parse_domain_name(rdr)
        } else if type == TYPE_A {
            assert(data_len == 4)
            ip: [4]u8
            for i in 0 ..< data_len {
                b, _ := bytes.reader_read_byte(rdr)
                ip[i] = b
                data = cast(Address)ip
            }
        } else {
            data_buf: bytes.Buffer
            for _ in 0 ..< data_len {
                b, _ := bytes.reader_read_byte(rdr)
                bytes.buffer_write_byte(&data_buf, b)
            }
            data_bytes := bytes.buffer_to_bytes(&data_buf)

            data = cast(Raw)data_bytes
        }
    }

    return(
        DnsRecord{
            name = name,
            type = type,
            class = transmute(u16be)class_bytes,
            ttl = transmute(u32be)ttl_bytes,
            data = data,
        } \
    )
}

DnsPacket :: struct {
    header:      DnsHeader,
    questions:   []DnsQuestion,
    answers:     []DnsRecord,
    authorities: []DnsRecord,
    additionals: []DnsRecord,
}

packet_from_reader :: proc(rdr: ^bytes.Reader) -> DnsPacket {
    header := header_from_reader(rdr)

    questions: [dynamic]DnsQuestion
    for _ in 0 ..< header.num_questions {
        question := question_from_reader(rdr)
        append(&questions, question)
    }
    answers: [dynamic]DnsRecord
    for _ in 0 ..< header.num_answers {
        record := record_from_reader(rdr)
        append(&answers, record)
    }
    authorities: [dynamic]DnsRecord
    for _ in 0 ..< header.num_authorities {
        record := record_from_reader(rdr)
        append(&authorities, record)
    }
    additionals: [dynamic]DnsRecord
    for _ in 0 ..< header.num_additionals {
        record := record_from_reader(rdr)
        append(&additionals, record)
    }

    return(
        DnsPacket{
            header = header,
            questions = questions[:],
            answers = answers[:],
            authorities = authorities[:],
            additionals = additionals[:],
        } \
    )
}

@(test)
test_read_response :: proc(t: ^testing.T) {
    response := "`V\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00R\x9b\x00\x04]\xb8\xd8\x22"

    response_rdr: bytes.Reader
    bytes.reader_init(&response_rdr, transmute([]u8)response)

    packet := packet_from_reader(&response_rdr)

    testing.expect_value(
        t,
        packet.header,
        DnsHeader{
            id = 24662,
            flags = 33152,
            num_questions = 1,
            num_answers = 1,
            num_authorities = 0,
            num_additionals = 0,
        },
    )

    testing.expect_value(t, len(packet.questions), 1)
    question := packet.questions[0]
    testing.expect_value(t, question.name, "www.example.com")
    testing.expect_value(t, question.type, 1)
    testing.expect_value(t, question.class, 1)

    testing.expect_value(t, len(packet.answers), 1)
    record := packet.answers[0]
    testing.expect_value(t, record.name, "www.example.com")
    testing.expect_value(t, record.type, 1)
    testing.expect_value(t, record.class, 1)
    testing.expect_value(t, record.ttl, 21147)
    #partial switch d in record.data {
    case Address:
        //testing.expect(t, slice.equal(d, transmute(Address)string("]\xb8\xd8\x22")))
        testing.expect_value(t, ip_to_string(d), "93.184.216.34")
    case:
        panic("Must be address")
    }

    testing.expect_value(t, len(packet.authorities), 0)
    testing.expect_value(t, len(packet.additionals), 0)
}

parse_domain_name :: proc(rdr: ^bytes.Reader) -> string {
    buf: bytes.Buffer

    inner_parse_domain_name(rdr, &buf)

    buf_len := bytes.buffer_length(&buf)
    if buf_len > 0 {
        bytes.buffer_truncate(&buf, buf_len - 1) // hack: remove last period, assumes there's at least one part
    }
    return transmute(string)bytes.buffer_to_bytes(&buf)
}

inner_parse_domain_name :: proc(rdr: ^bytes.Reader, out: ^bytes.Buffer) {
    for {
        part_len, _ := bytes.reader_read_byte(rdr)
        if part_len == 0 do break

        if part_len & 0b1100_0000 != 0 {
            // get from pointer
            b, _ := bytes.reader_read_byte(rdr)
            pointer_bytes := [2]u8{part_len & 0b0011_1111, b}
            pointer := transmute(u16be)pointer_bytes
            current_pos := rdr.i
            bytes.reader_seek(rdr, cast(i64)pointer, io.Seek_From.Start)
            inner_parse_domain_name(rdr, out)
            bytes.reader_seek(rdr, cast(i64)current_pos, io.Seek_From.Start)
            break
        } else {
            // read directly
            for _ in 0 ..< part_len {
                b, _ := bytes.reader_read_byte(rdr)
                bytes.buffer_write_byte(out, b)
            }
            bytes.buffer_write_byte(out, '.')
        }
    }
}

@(test)
test_parse_domain_name :: proc(t: ^testing.T) {
    input := "\x03www\x07example\x03com\x00\x00\x01\x00\x01"
    input_rdr: bytes.Reader
    bytes.reader_init(&input_rdr, transmute([]u8)input)
    testing.expect_value(t, parse_domain_name(&input_rdr), "www.example.com")
}

ip_to_string :: proc(ip: Address) -> string {
    sb: strings.Builder
    return fmt.sbprintf(&sb, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}
