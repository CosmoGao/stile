package rdpproxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
)

func TestEncodeCountsRunes(t *testing.T) {
	got := string(Encode("a", "é"))
	if got != "1.a,1.é;" {
		t.Fatalf("encode = %q", got)
	}
	rd := NewReader(strings.NewReader(got))
	op, args, raw, err := rd.Next()
	if err != nil {
		t.Fatal(err)
	}
	if op != "a" || len(args) != 1 || args[0] != "é" || string(raw) != got {
		t.Fatalf("parsed %q %q raw %q", op, args, raw)
	}
	if _, _, _, err := rd.Next(); err != io.EOF {
		t.Fatalf("next = %v", err)
	}
}

func TestReaderSplitsBytes(t *testing.T) {
	msg := Encode("", "ping", "5")
	rd := NewReader(&oneByte{b: msg})
	op, args, raw, err := rd.Next()
	if err != nil {
		t.Fatal(err)
	}
	if op != "" || len(args) != 2 || args[0] != "ping" || args[1] != "5" || !bytes.Equal(raw, msg) {
		t.Fatalf("op %q args %q raw %q", op, args, raw)
	}
}

func TestConnectArgsDisableDrive(t *testing.T) {
	names := []string{
		"hostname", "port", "username", "password",
		"enable-drive", "drive-name", "drive-path", "create-drive-path",
		"disable-download", "disable-upload", "enable-printing", "enable-sftp",
		"recording-path", "create-recording-path", "recording-include-keys",
		"gateway-password", "sftp-private-key",
	}
	got := ConnectArgs(names, Target{
		Host: "198.51.100.8", Port: 3391, Username: "win-user", Password: "p,a;ss词",
	})
	want := map[string]string{
		"hostname": "198.51.100.8", "port": "3391", "username": "win-user", "password": "p,a;ss词",
		"enable-drive": "false", "drive-name": "", "drive-path": "", "create-drive-path": "false",
		"disable-download": "true", "disable-upload": "true", "enable-printing": "false", "enable-sftp": "false",
		"recording-path": "", "create-recording-path": "false", "recording-include-keys": "false",
		"gateway-password": "", "sftp-private-key": "",
	}
	if len(got) != len(names) {
		t.Fatalf("len %d", len(got))
	}
	for i, name := range names {
		if got[i] != want[name] {
			t.Fatalf("%s = %q", name, got[i])
		}
	}
}

func TestHandshakeSkipsDialWhenTargetMissing(t *testing.T) {
	_, err := Handshake(context.Background(), "127.0.0.1:9", Target{}, func(context.Context, string) (net.Conn, error) {
		t.Fatal("dialed")
		return nil, nil
	})
	if err != ErrBadTarget {
		t.Fatalf("err = %v", err)
	}
}

func TestHandshakeFillsPassword(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	names := []string{"hostname", "port", "username", "password", "enable-drive", "drive-path", "disable-download", "disable-upload"}
	got := make(chan []string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		rd := NewReader(c)
		op, args, _, err := rd.Next()
		if err != nil || op != "select" || len(args) != 1 || args[0] != "rdp" {
			return
		}
		if err := writeFull(c, Encode("args", names...)); err != nil {
			return
		}
		var connect []string
		for {
			op, args, _, err = rd.Next()
			if err != nil {
				return
			}
			if op == "connect" {
				connect = args
				break
			}
		}
		got <- connect
		_, _ = c.Write(Encode("ready", "c1"))
		_, _ = c.Write(Encode("nop"))
	}()
	sess, err := Handshake(context.Background(), ln.Addr().String(), Target{
		Host: "198.51.100.8", Port: 3391, Username: "win-user", Password: "p,a;ss词",
		Width: 800, Height: 600, DPI: 96,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	connect := <-got
	if len(connect) != len(names)+1 || connect[0] != protocolVersion {
		t.Fatalf("connect = %#v", connect)
	}
	values := connect[1:]
	if values[0] != "198.51.100.8" || values[1] != "3391" || values[2] != "win-user" || values[3] != "p,a;ss词" {
		t.Fatalf("filled %#v", values)
	}
	if values[4] != "false" || values[5] != "" || values[6] != "true" || values[7] != "true" {
		t.Fatalf("drive %#v", values[4:])
	}
	op, _, _, err := sess.Next()
	if err != nil || op != "nop" {
		t.Fatalf("buffered %q %v", op, err)
	}
}

type oneByte struct {
	b []byte
	i int
}

func (o *oneByte) Read(p []byte) (int, error) {
	if o.i >= len(o.b) {
		return 0, io.EOF
	}
	p[0] = o.b[o.i]
	o.i++
	return 1, nil
}
