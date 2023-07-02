package dns_toy

import "core:bytes"
import "core:fmt"
import "core:encoding/hex"
import "core:net"
import "core:math/rand"
import "core:slice"
import "core:strings"
import "core:testing"

TYPE_A: u16be = 1
CLASS_IN: u16be = 1
RECURSION_DESIRED: u16be = 1 << 8

main :: proc() {
    send_buf: bytes.Buffer

    rng := rand.create(1)
    id := cast(u16be)rand.int_max(65_535, &rng)
    write_query(id, "www.example.com", TYPE_A, &send_buf)

    sock, _err := net.make_unbound_udp_socket(net.Address_Family.IP4)
    defer net.close(sock)

    addr := net.Endpoint {
        address = cast(net.IP4_Address){8, 8, 8, 8},
        port    = 53,
    }
    _, err := net.send_udp(sock, bytes.buffer_to_bytes(&send_buf), addr)

    recv_buf: [1024]u8
    bytes_read, _, _ := net.recv_udp(sock, recv_buf[:])

    fmt.printf("%s\n", hex.encode(recv_buf[0:bytes_read]))
}

write_query :: proc(id: u16be, domain_name: string, record_type: u16be, buf: ^bytes.Buffer) {
    header := DnsHeader {
        id            = id,
        flags         = RECURSION_DESIRED,
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
    write_query(0x8298, "www.example.com", TYPE_A, &buf)
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

question_destroy :: proc(question: DnsQuestion) {
    delete(question.name)
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
            name = string(name),
            type = transmute(u16be)type_bytes,
            class = transmute(u16be)class_bytes,
        } \
    )

}

@(test)
test_read_response :: proc(t: ^testing.T) {
    response := "`V\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00R\x9b\x00\x04]\xb8\xd8"
    response_rdr: bytes.Reader
    bytes.reader_init(&response_rdr, transmute([]u8)response)

    testing.expect_value(
        t,
        header_from_reader(&response_rdr),
        DnsHeader{
            id = 24662,
            flags = 33152,
            num_questions = 1,
            num_answers = 1,
            num_authorities = 0,
            num_additionals = 0,
        },
    )

    question := question_from_reader(&response_rdr)
    testing.expect_value(t, question.name, "www.example.com")
    testing.expect_value(t, question.type, 1)
    testing.expect_value(t, question.class, 1)
}

// caller frees
parse_domain_name :: proc(rdr: ^bytes.Reader) -> []u8 {
    buf: bytes.Buffer
    part_len_first, _ := bytes.reader_read_byte(rdr)
    if part_len_first == 0 do return bytes.buffer_to_bytes(&buf)
    for _ in 0 ..< part_len_first {
        b, _ := bytes.reader_read_byte(rdr)
        bytes.buffer_write_byte(&buf, b)
    }

    for {
        part_len, _ := bytes.reader_read_byte(rdr)
        if part_len == 0 do break
        bytes.buffer_write_byte(&buf, '.')
        for _ in 0 ..< part_len {
            b, _ := bytes.reader_read_byte(rdr)
            bytes.buffer_write_byte(&buf, b)
        }
    }

    return bytes.buffer_to_bytes(&buf)
}

@(test)
test_parse_domain_name :: proc(t: ^testing.T) {
    input := "\x03www\x07example\x03com\x00\x00\x01\x00\x01"
    input_rdr: bytes.Reader
    bytes.reader_init(&input_rdr, transmute([]u8)input)
    testing.expect(
        t,
        slice.equal(parse_domain_name(&input_rdr), transmute([]u8)string("www.example.com")),
    )
}
