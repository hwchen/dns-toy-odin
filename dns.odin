package dns_toy

import "core:bytes"
import "core:fmt"
import "core:encoding/hex"
import "core:net"
import "core:math/rand"
import "core:slice"
import "core:strings"
import "core:testing"

TYPE_A : u16be = 1;
CLASS_IN : u16be = 1;
RECURSION_DESIRED : u16be = 1 << 8;

main :: proc() {}

write_query :: proc(id: u16be, domain_name: string, record_type: u16be, buf: ^bytes.Buffer) {
    header := DnsHeader{
        id = id,
        flags = RECURSION_DESIRED,
        num_questions = 1,
    }
    question := DnsQuestion{
        name = domain_name,
        type = record_type,
        class = CLASS_IN,
    }

    header_write_buf(header, buf)
    question_write_buf(question, buf)
}

@(test)
test_write_query :: proc(t: ^testing.T) {
    buf: bytes.Buffer
    bytes.buffer_reset(&buf)

    write_query(0x8298, "www.example.com", TYPE_A, &buf)
    expected, _ := hex.decode(transmute([]u8) string("82980100000100000000000003777777076578616d706c6503636f6d0000010001"))
    testing.expect(t, slice.equal(bytes.buffer_to_bytes(&buf), expected))
}

DnsHeader :: struct #packed {
    id: u16be,
    flags: u16be,
    num_questions: u16be,
    num_answers: u16be,
    num_authorities: u16be,
    num_additionals: u16be,
}

header_write_buf :: proc(header: DnsHeader, buf: ^bytes.Buffer) {
    header_bytes := transmute([12]u8)header
    bytes.buffer_write(buf, header_bytes[:])
}

DnsQuestion :: struct {
    name: string,
    type: u16be,
    class: u16be,
}

question_destroy :: proc(question: DnsQuestion) {
    delete(question.name)
}

question_write_buf :: proc(question: DnsQuestion, buf: ^bytes.Buffer) {
    parts := strings.split(question.name, ".")

    for part in parts {
        bytes.buffer_write_byte(buf, cast(u8)len(part));
        bytes.buffer_write_string(buf, part);
    }

    bytes.buffer_write_byte(buf, 0);

    type_bytes := transmute([2]u8)question.type
    bytes.buffer_write(buf, type_bytes[:])

    class_bytes := transmute([2]u8)question.class
    bytes.buffer_write(buf, class_bytes[:])
}
