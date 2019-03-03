package img

import (
	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"image/png"
	"io"
	"os"
)

type Wmk struct {
	image *image.RGBA
}

func Watermark(r io.Reader, text string, x, y int) (*Wmk, error) {
	img, _, err := image.Decode(r)
	if err != nil {
		return nil, err
	}
	bounds := img.Bounds()
	cimg := image.NewRGBA(bounds)
	draw.Draw(cimg, bounds, img, image.Point{}, draw.Src)

	col := color.RGBA{89, 89, 89, 255}
	point := fixed.Point26_6{fixed.Int26_6(x * 64), fixed.Int26_6(y * 64)}

	d := &font.Drawer{
		Dst:  cimg,
		Src:  image.NewUniform(col),
		Face: basicfont.Face7x13,
		Dot:  point,
	}
	d.DrawString(text)

	return &Wmk{image: cimg}, nil
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
