package img

import (
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"math"
	"os"

	"github.com/disintegration/imaging"
	"github.com/golang/freetype/truetype"
	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/goregular"
	"golang.org/x/image/math/fixed"
)

type Wmk struct {
	image *image.NRGBA
}

func Watermark(r io.Reader, text string, space int, fontSize, opacity, angle float64) (*Wmk, error) {
	img, _, err := image.Decode(r)
	if err != nil {
		return nil, err
	}
	wmkWidth := int(math.Sqrt(math.Pow(float64(img.Bounds().Max.X), 2) + math.Pow(float64(img.Bounds().Max.Y), 2)))
	mark := imaging.New(wmkWidth, wmkWidth, color.RGBA{})
	f, _ := truetype.Parse(goregular.TTF)
	var x, y = 0, 0
	for x < wmkWidth {
		for y < wmkWidth {
			d := &font.Drawer{
				Dst: mark,
				Src: image.NewUniform(color.RGBA{R: 128, G: 128, B: 128, A: 255}),
				Face: truetype.NewFace(f, &truetype.Options{
					Size: fontSize,
					DPI:  72,
				}),
				Dot: fixed.Point26_6{X: fixed.Int26_6(x * 64 * space), Y: fixed.Int26_6(y * 64 * space)},
			}
			d.DrawString(text)
			y += 13
		}
		y = 0
		x += 6 * len(text)
	}
	mark = imaging.Rotate(mark, angle, color.RGBA{})
	imgOut := imaging.OverlayCenter(img, mark, opacity)
	return &Wmk{image: imgOut}, nil
}

func (w *Wmk) SaveJPG(name string) error {
	out, err := os.Create(name)
	if err != nil {
		return err
	}
	defer out.Close()
	var opt jpeg.Options
	opt.Quality = 100
	if err := jpeg.Encode(out, w.image, &opt); err != nil {
		return err
	}
	return nil
}

func (w *Wmk) SavePNG(name string) error {
	out, err := os.Create(name)
	if err != nil {
		return err
	}
	defer out.Close()
	if err := png.Encode(out, w.image); err != nil {
		return err
	}
	return nil
}
