//go:build (!amd64 && !386 && !arm && !arm64 && !ppc64le && !mipsle && !mips64le && !mips64p32le && !wasm) || appengine
// +build !amd64,!386,!arm,!arm64,!ppc64le,!mipsle,!mips64le,!mips64p32le,!wasm appengine

package xorfilter

import (
	"encoding/binary"
	"io"
	"unsafe"
)

// Save writes the filter to the writer in little endian format.
// The fingerprints are stored in the filter's endianness format.
func (f *BinaryFuse[T]) Save(w io.Writer) error {
	if err := binary.Write(w, binary.LittleEndian, f.Seed); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, f.SegmentLength); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, f.SegmentLengthMask); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, f.SegmentCount); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, f.SegmentCountLength); err != nil {
		return err
	}
	// Write the length of Fingerprints
	fpLen := uint32(len(f.Fingerprints))
	if err := binary.Write(w, binary.LittleEndian, fpLen); err != nil {
		return err
	}
	// Write the fingerprints endianness
	if err := binary.Write(w, binary.LittleEndian, f.FingerprintsEndianness); err != nil {
		return err
	}
	// Write the Fingerprints as raw bytes.
	// The fingerprints in memory already represent the correct byte pattern for the
	// stored endianness (ConvertEndianness swaps bytes in-place).
	var zero T
	fpSize := int(unsafe.Sizeof(zero))
	buf := make([]byte, fpSize)
	for _, fp := range f.Fingerprints {
		// Write in native byte order (which matches the stored endianness after any conversion)
		switch fpSize {
		case 1:
			buf[0] = byte(fp)
		case 2:
			nativeEndian := nativeEndian()
			if nativeEndian == LittleEndian {
				binary.LittleEndian.PutUint16(buf, uint16(fp))
			} else {
				binary.BigEndian.PutUint16(buf, uint16(fp))
			}
		case 4:
			nativeEndian := nativeEndian()
			if nativeEndian == LittleEndian {
				binary.LittleEndian.PutUint32(buf, uint32(fp))
			} else {
				binary.BigEndian.PutUint32(buf, uint32(fp))
			}
		}
		if _, err := w.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

// LoadBinaryFuse reads the filter from the reader in little endian format.
// If the fingerprints endianness doesn't match the machine's native endianness,
// the fingerprints are converted to native endianness.
func LoadBinaryFuse[T Unsigned](r io.Reader) (*BinaryFuse[T], error) {
	var f BinaryFuse[T]
	if err := binary.Read(r, binary.LittleEndian, &f.Seed); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &f.SegmentLength); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &f.SegmentLengthMask); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &f.SegmentCount); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &f.SegmentCountLength); err != nil {
		return nil, err
	}
	// Read the length of Fingerprints
	var fpLen uint32
	if err := binary.Read(r, binary.LittleEndian, &fpLen); err != nil {
		return nil, err
	}
	// Read the fingerprints endianness
	if err := binary.Read(r, binary.LittleEndian, &f.FingerprintsEndianness); err != nil {
		return nil, err
	}
	// Read the Fingerprints as raw bytes.
	// We read them in native byte order, then convert from stored endianness to native.
	f.Fingerprints = make([]T, fpLen)
	var zero T
	fpSize := int(unsafe.Sizeof(zero))
	buf := make([]byte, fpSize)
	native := nativeEndian()
	for i := range f.Fingerprints {
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		// Read in native byte order
		switch fpSize {
		case 1:
			f.Fingerprints[i] = T(buf[0])
		case 2:
			if native == LittleEndian {
				f.Fingerprints[i] = T(binary.LittleEndian.Uint16(buf))
			} else {
				f.Fingerprints[i] = T(binary.BigEndian.Uint16(buf))
			}
		case 4:
			if native == LittleEndian {
				f.Fingerprints[i] = T(binary.LittleEndian.Uint32(buf))
			} else {
				f.Fingerprints[i] = T(binary.BigEndian.Uint32(buf))
			}
		}
	}
	// The fingerprints are read as raw bytes - the endianness field tells
	// Contains() how to interpret them. No conversion needed here.
	return &f, nil
}
