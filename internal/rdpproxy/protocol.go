package rdpproxy

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxElement      = 8 << 20
	maxInstruction  = 8 << 20
	protocolVersion = "VERSION_1_3_0"
)

// Encode writes one Guacamole instruction. The length prefix counts Unicode
// characters, which is what guacd 1.4.0 parses.
func Encode(opcode string, args ...string) []byte {
	var b strings.Builder
	writeElement(&b, opcode)
	for _, arg := range args {
		b.WriteByte(',')
		writeElement(&b, arg)
	}
	b.WriteByte(';')
	return []byte(b.String())
}

func writeElement(b *strings.Builder, s string) {
	b.WriteString(strconv.Itoa(utf8.RuneCountInString(s)))
	b.WriteByte('.')
	b.WriteString(s)
}

// TunnelOpen is the first instruction a guacamole-common-js 1.4.0 websocket
// tunnel expects. The empty opcode is internal to the tunnel and is not a
// guacd instruction.
func TunnelOpen() []byte {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return Encode("", hex.EncodeToString(buf))
}

// Reader pulls complete instructions from a stream. Bytes after the last
// instruction stay buffered.
type Reader struct {
	r   io.Reader
	buf []byte
	pos int
}

func NewReader(r io.Reader) *Reader {
	return &Reader{r: r}
}

// Next returns the next instruction. raw is the original bytes, including
// the terminating semicolon. io.EOF means the stream ended between instructions.
func (rd *Reader) Next() (opcode string, args []string, raw []byte, err error) {
	start := rd.pos
	opcode, err = rd.element()
	if err != nil {
		return "", nil, nil, err
	}
	for {
		if rd.pos-start > maxInstruction {
			return "", nil, nil, ErrHandshake
		}
		b, err := rd.nextByte()
		if err != nil {
			return "", nil, nil, err
		}
		switch b {
		case ';':
			raw = append([]byte(nil), rd.buf[start:rd.pos]...)
			rd.buf = append([]byte(nil), rd.buf[rd.pos:]...)
			rd.pos = 0
			return opcode, args, raw, nil
		case ',':
			arg, err := rd.element()
			if err != nil {
				return "", nil, nil, err
			}
			args = append(args, arg)
		default:
			return "", nil, nil, ErrHandshake
		}
	}
}

func (rd *Reader) element() (string, error) {
	length := 0
	saw := false
	for {
		b, err := rd.nextByte()
		if err != nil {
			return "", err
		}
		if b == '.' {
			break
		}
		if b < '0' || b > '9' {
			return "", ErrHandshake
		}
		saw = true
		digit := int(b - '0')
		if length > (maxElement-digit)/10 {
			return "", ErrHandshake
		}
		length = length*10 + digit
	}
	if !saw {
		return "", ErrHandshake
	}
	var b strings.Builder
	for i := 0; i < length; i++ {
		r, err := rd.nextRune()
		if err != nil {
			return "", err
		}
		b.WriteRune(r)
	}
	return b.String(), nil
}

func (rd *Reader) nextByte() (byte, error) {
	if err := rd.more(1); err != nil {
		return 0, err
	}
	b := rd.buf[rd.pos]
	rd.pos++
	return b, nil
}

func (rd *Reader) nextRune() (rune, error) {
	for {
		if rd.pos < len(rd.buf) && utf8.FullRune(rd.buf[rd.pos:]) {
			r, size := utf8.DecodeRune(rd.buf[rd.pos:])
			if r == utf8.RuneError && size == 1 {
				return 0, ErrHandshake
			}
			rd.pos += size
			return r, nil
		}
		if err := rd.fill(); err != nil {
			return 0, err
		}
	}
}

func (rd *Reader) more(n int) error {
	for len(rd.buf)-rd.pos < n {
		if err := rd.fill(); err != nil {
			return err
		}
	}
	return nil
}

func (rd *Reader) fill() error {
	if len(rd.buf) > maxInstruction {
		return ErrHandshake
	}
	tmp := make([]byte, 4096)
	n, err := rd.r.Read(tmp)
	if n > 0 {
		rd.buf = append(rd.buf, tmp[:n]...)
		if len(rd.buf) > maxInstruction+4096 {
			return ErrHandshake
		}
		return nil
	}
	if err != nil {
		return err
	}
	return io.ErrNoProgress
}
