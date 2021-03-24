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
	"github.com/golang/freetype"
	"golang.org/x/image/font/gofont/goregular"
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
	font, _ := freetype.ParseFont(goregular.TTF)
	context := freetype.NewContext()
	context.SetDPI(72)
	context.SetFont(font)
	context.SetFontSize(fontSize)
	context.SetClip(mark.Bounds())
	context.SetDst(mark)
	context.SetSrc(image.NewUniform(color.RGBA{R: 128, G: 128, B: 128, A: 255}))
	var x, y = 0, 0
	for x < wmkWidth {
		var X = 0
		for y < wmkWidth {
			pt, _ := context.DrawString(text, freetype.Pt(x, y))
			X = pt.X.Ceil()
			y = pt.Y.Ceil() + space
		}
		y = 0
		x = X + space
	}
	mark = imaging.Rotate(mark, angle, color.RGBA{})
	return &Wmk{image: imaging.OverlayCenter(img, mark, opacity)}, nil
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
