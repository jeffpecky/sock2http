package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestVerifyBytesSHA256(t *testing.T) {
	data := []byte("verified release data")
	sum := sha256.Sum256(data)
	if err := verifyBytesSHA256(data, hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("verifyBytesSHA256() error = %v", err)
	}
	if err := verifyBytesSHA256(data, "invalid"); err == nil {
		t.Fatal("verifyBytesSHA256() accepted an invalid checksum")
	}
}

func TestExtractWireproxyBinary(t *testing.T) {
	const expected = "wireproxy binary"
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "wireproxy.exe",
		Mode:     0700,
		Size:     int64(len(expected)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(expected)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	binary, err := extractWireproxyBinary(archive.Bytes())
	if err != nil {
		t.Fatalf("extractWireproxyBinary() error = %v", err)
	}
	if string(binary) != expected {
		t.Fatalf("extractWireproxyBinary() = %q, want %q", binary, expected)
	}
}

func TestExtractWireproxyBinaryMissing(t *testing.T) {
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "not-wireproxy.txt",
		Mode:     0600,
		Size:     1,
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := extractWireproxyBinary(archive.Bytes()); err == nil {
		t.Fatal("extractWireproxyBinary() succeeded without wireproxy.exe")
	}
}
