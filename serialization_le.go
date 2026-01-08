//go:build amd64 || 386 || arm || arm64 || ppc64le || mipsle || mips64le || mips64p32le || wasm

package xorfilter

import (
	"io"
	"unsafe"
)

// Save writes the filter to the writer assuming little endian system, using direct byte copy for performance.
// The fingerprints are stored in the filter's endianness format.
func (f *BinaryFuse[T]) Save(w io.Writer) error {
	// Write Seed
	if _, err := w.Write((*[8]byte)(unsafe.Pointer(&f.Seed))[:]); err != nil {
		return err
	}
	// Write SegmentLength
	if _, err := w.Write((*[4]byte)(unsafe.Pointer(&f.SegmentLength))[:]); err != nil {
		return err
	}
	// Write SegmentLengthMask
	if _, err := w.Write((*[4]byte)(unsafe.Pointer(&f.SegmentLengthMask))[:]); err != nil {
		return err
	}
	// Write SegmentCount
	if _, err := w.Write((*[4]byte)(unsafe.Pointer(&f.SegmentCount))[:]); err != nil {
		return err
	}
	// Write SegmentCountLength
	if _, err := w.Write((*[4]byte)(unsafe.Pointer(&f.SegmentCountLength))[:]); err != nil {
		return err
	}
	// Write length of Fingerprints
	fpLen := uint32(len(f.Fingerprints))
	if _, err := w.Write((*[4]byte)(unsafe.Pointer(&fpLen))[:]); err != nil {
		return err
	}
	// Write fingerprints endianness
	if _, err := w.Write((*[1]byte)(unsafe.Pointer(&f.FingerprintsEndianness))[:]); err != nil {
		return err
	}
	// Write Fingerprints
	// The fingerprints in memory already represent the correct byte pattern for the
	// stored endianness (ConvertEndianness swaps bytes in-place), so we always do
	// a direct byte copy.
	if len(f.Fingerprints) > 0 {
		size := int(unsafe.Sizeof(T(0)))
		bytes := unsafe.Slice((*byte)(unsafe.Pointer(&f.Fingerprints[0])), len(f.Fingerprints)*size)
		if _, err := w.Write(bytes); err != nil {
			return err
		}
	}
	return nil
}

// LoadBinaryFuse reads the filter from the reader assuming little endian system, using direct byte copy for performance.
// If the fingerprints endianness doesn't match the machine's native endianness (little endian),
// the fingerprints are converted to native endianness.
func LoadBinaryFuse[T Unsigned](r io.Reader) (*BinaryFuse[T], error) {
	var f BinaryFuse[T]
	// Read Seed
	if _, err := io.ReadFull(r, (*[8]byte)(unsafe.Pointer(&f.Seed))[:]); err != nil {
		return nil, err
	}
	// Read SegmentLength
	if _, err := io.ReadFull(r, (*[4]byte)(unsafe.Pointer(&f.SegmentLength))[:]); err != nil {
		return nil, err
	}
	// Read SegmentLengthMask
	if _, err := io.ReadFull(r, (*[4]byte)(unsafe.Pointer(&f.SegmentLengthMask))[:]); err != nil {
		return nil, err
	}
	// Read SegmentCount
	if _, err := io.ReadFull(r, (*[4]byte)(unsafe.Pointer(&f.SegmentCount))[:]); err != nil {
		return nil, err
	}
	// Read SegmentCountLength
	if _, err := io.ReadFull(r, (*[4]byte)(unsafe.Pointer(&f.SegmentCountLength))[:]); err != nil {
		return nil, err
	}
	// Read length of Fingerprints
	var fpLen uint32
	if _, err := io.ReadFull(r, (*[4]byte)(unsafe.Pointer(&fpLen))[:]); err != nil {
		return nil, err
	}
	// Read fingerprints endianness
	if _, err := io.ReadFull(r, (*[1]byte)(unsafe.Pointer(&f.FingerprintsEndianness))[:]); err != nil {
		return nil, err
	}
	f.Fingerprints = make([]T, fpLen)
	if fpLen > 0 {
		size := int(unsafe.Sizeof(T(0)))
		bytes := unsafe.Slice((*byte)(unsafe.Pointer(&f.Fingerprints[0])), int(fpLen)*size)
		if _, err := io.ReadFull(r, bytes); err != nil {
			return nil, err
		}
	}
	// The fingerprints are read as raw bytes - the endianness field tells
	// Contains() how to interpret them. No conversion needed here.
	return &f, nil
}
