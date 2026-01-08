package xorfilter

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"testing"
)

func TestBinaryFuse8Serialization(t *testing.T) {
	keys := []uint64{1, 2, 3, 4, 5, 100, 200, 300}
	filter, err := PopulateBinaryFuse8(keys)
	if err != nil {
		t.Fatal(err)
	}

	// Test generic serialization
	var buf bytes.Buffer
	err = filter.Save(&buf)
	if err != nil {
		t.Fatal(err)
	}

	loadedFilter, err := LoadBinaryFuse8(&buf)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(filter, loadedFilter) {
		t.Error("Generic serialization: Filters do not match after save/load")
	}

	for _, key := range keys {
		if !loadedFilter.Contains(key) {
			t.Errorf("Generic serialization: Key %d not found in loaded filter", key)
		}
	}
}

func TestBinaryFuseSerializationGeneric(t *testing.T) {
	keys := []uint64{1, 2, 3, 4, 5, 100, 200, 300}
	filter, err := NewBinaryFuse[uint16](keys)
	if err != nil {
		t.Fatal(err)
	}

	// Test generic serialization
	var buf bytes.Buffer
	err = filter.Save(&buf)
	if err != nil {
		t.Fatal(err)
	}

	// Note: The serialized format includes the endianness byte (0x00 for little endian)
	if "wVwCiewtCpEIAAAABwAAAAEAAAAIAAAAGAAAAAAAAAAAWO/6wQAAAAAKKgAANpD2+QAAAAAAAAAAAAAAALi5MNkAAAAAAAB9bAAAAAA=" != base64.StdEncoding.EncodeToString(buf.Bytes()) {
		t.Log("Base64 serialized data:", base64.StdEncoding.EncodeToString(buf.Bytes()))
		t.Error("Generic serialization: Unexpected serialized data")
	}

	loadedFilter, err := LoadBinaryFuse[uint16](&buf)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(filter, loadedFilter) {
		t.Error("Generic serialization: Filters do not match after save/load")
	}

	for _, key := range keys {
		if !loadedFilter.Contains(key) {
			t.Errorf("Generic serialization: Key %d not found in loaded filter", key)
		}
	}
}

func TestBinaryFuseEndiannessHandling(t *testing.T) {
	keys := []uint64{1, 2, 3, 4, 5, 100, 200, 300, 1000, 2000}

	// Test uint16 with non-native endianness
	t.Run("uint16", func(t *testing.T) {
		filter, err := NewBinaryFuse[uint16](keys)
		if err != nil {
			t.Fatal(err)
		}

		// Verify all keys work with native endianness
		for _, key := range keys {
			if !filter.Contains(key) {
				t.Errorf("Key %d not found with native endianness", key)
			}
		}

		// Store original fingerprints
		originalFPs := make([]uint16, len(filter.Fingerprints))
		copy(originalFPs, filter.Fingerprints)

		// Setting opposite endianness should NOT change fingerprints (they're read-only safe)
		// but Contains() should still work by converting on-the-fly
		originalEndianness := filter.FingerprintsEndianness
		var oppositeEndianness Endianness
		if originalEndianness == LittleEndian {
			oppositeEndianness = BigEndian
		} else {
			oppositeEndianness = LittleEndian
		}

		// If we lie about endianness, Contains should fail
		filter.SetFingerprintsEndianness(oppositeEndianness)

		// Fingerprints should be unchanged
		for i := range filter.Fingerprints {
			if filter.Fingerprints[i] != originalFPs[i] {
				t.Errorf("Fingerprint %d changed when setting endianness", i)
			}
		}

		// Contains should now fail (we lied about the endianness)
		// This proves the endianness field affects Contains() behavior
		workingCount := 0
		for _, key := range keys {
			if filter.Contains(key) {
				workingCount++
			}
		}
		// With wrong endianness, most/all keys should fail (unless by chance the swap gives same value)
		if workingCount == len(keys) {
			t.Error("All keys still work after setting wrong endianness - endianness not being used")
		}

		// Restore correct endianness
		filter.SetFingerprintsEndianness(originalEndianness)

		// Now all keys should work again
		for _, key := range keys {
			if !filter.Contains(key) {
				t.Errorf("Key %d not found after restoring correct endianness", key)
			}
		}
	})

	// Test uint8 - endianness should have no effect
	t.Run("uint8", func(t *testing.T) {
		filter, err := NewBinaryFuse[uint8](keys)
		if err != nil {
			t.Fatal(err)
		}

		// Verify all keys work
		for _, key := range keys {
			if !filter.Contains(key) {
				t.Errorf("Key %d not found", key)
			}
		}

		// Set opposite endianness - should have no effect for uint8
		filter.SetFingerprintsEndianness(BigEndian)

		// All keys should still work (uint8 has no byte order)
		for _, key := range keys {
			if !filter.Contains(key) {
				t.Errorf("Key %d not found after endianness change (uint8 should be unaffected)", key)
			}
		}
	})
}

func TestBinaryFuseSerializationWithDifferentEndianness(t *testing.T) {
	keys := []uint64{1, 2, 3, 4, 5, 100, 200, 300, 1000, 2000}

	// Test that save/load preserves endianness and Contains works
	t.Run("uint16_save_load_preserves_endianness", func(t *testing.T) {
		filter, err := NewBinaryFuse[uint16](keys)
		if err != nil {
			t.Fatal(err)
		}

		// Verify original works
		for _, key := range keys {
			if !filter.Contains(key) {
				t.Errorf("Key %d not found in original filter", key)
			}
		}

		// Save the filter
		var buf bytes.Buffer
		if err := filter.Save(&buf); err != nil {
			t.Fatal(err)
		}

		// Load the filter
		loadedFilter, err := LoadBinaryFuse[uint16](&buf)
		if err != nil {
			t.Fatal(err)
		}

		// Verify endianness is preserved
		if loadedFilter.FingerprintsEndianness != filter.FingerprintsEndianness {
			t.Errorf("Endianness not preserved: got %v, want %v",
				loadedFilter.FingerprintsEndianness, filter.FingerprintsEndianness)
		}

		// Verify all keys work in loaded filter
		for _, key := range keys {
			if !loadedFilter.Contains(key) {
				t.Errorf("Key %d not found in loaded filter", key)
			}
		}
	})
}
