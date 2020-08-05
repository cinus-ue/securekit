package img

import (
	"encoding/binary"
	"image"
	"image/color"
	"image/draw"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	_ "image/png"
	"io"
)

// setBit will set the LSB of n to the requested value
func setBit(n uint32, is1 bool) uint8 {
	n = n >> 8
	n = n & 0xFE
	if is1 {
		n = n | 0x1
	}
	return uint8(n)
}

// convertByteToBits is a helper function that takes one byte and
// returns a slice of booleans representing the binary value of that byte
func convertByteToBits(b byte) []bool {
	result := make([]bool, 8)
	for j := 0; j < 8; j++ {
		mask := byte(1 << uint(j))
		result[7-j] = b&mask>>uint(j) == 1
	}
	return result
}

// getBits returns a slice of booleans representing the binary value of data
func getBits(data []byte) []bool {
	bs := make([]byte, 4)
	binary.BigEndian.PutUint32(bs, uint32(len(data)))
	data = append(bs, data...)
	var results []bool
	for _, b := range data {
		results = append(results, convertByteToBits(b)...)
	}
	return results
}

// Encode takes an image and encodes a payload into the LSB
func LSBEncoder(w io.Writer, r io.Reader, payload []byte) error {
	img, _, err := image.Decode(r)
	if err != nil {
		return err
	}
	bounds := img.Bounds()
	cimg := image.NewRGBA(bounds)
	draw.Draw(cimg, bounds, img, image.Point{}, draw.Over)

	data := getBits(payload)
	dataIdx := 0
	dataLen := len(data)
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, a := cimg.At(x, y).RGBA()
			r8 := uint8(r >> 8)
			g8 := uint8(g >> 8)
			b8 := uint8(b >> 8)
			a8 := uint8(a >> 8)

			if dataIdx < dataLen {
				r8 = setBit(r, data[dataIdx])
				dataIdx++
			}
			if dataIdx < dataLen {
				g8 = setBit(g, data[dataIdx])
				dataIdx++
			}
			if dataIdx < dataLen {
				b8 = setBit(b, data[dataIdx])
				dataIdx++
			}
			cimg.Set(x, y, color.RGBA{R: r8, G: g8, B: b8, A: a8})
		}
	}
	return png.Encode(w, cimg)
}

// assemble takes the LSB data from a payload and reconstructes the original message
func assemble(data []uint8) []byte {
	var result []byte
	length := len(data)
	for i := 0; i < len(data)/8; i++ {
		b := uint8(0)
		for j := 0; j < 8; j++ {
			if i*8+j < length {
				b = b<<1 + data[i*8+j]
			}
		}
		result = append(result, b)
	}
	payloadSize := binary.BigEndian.Uint32(result[0:4])
	return result[4 : payloadSize+4]
}

// Decode takes an image and prints the payload that was encoded
func LSBDecoder(r io.Reader) ([]byte, error) {
	img, err := png.Decode(r)
	if err != nil {
		return nil, err
	}
	bounds := img.Bounds()

	var data []uint8
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			data = append(data, uint8(r>>8)&1)
			data = append(data, uint8(g>>8)&1)
			data = append(data, uint8(b>>8)&1)
		}
	}
	payload := assemble(data)
	return payload, nil
}
