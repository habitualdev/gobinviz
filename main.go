package binviz

import (
	"github.com/roaldi/richdiff"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"github.com/corona10/goimagehash"
	"os"
)

type BinViz struct {
	RichDiffResults richdiff.Results
	Image image.Image
	BinAverageHash *goimagehash.ImageHash
	BinDifferenceHash *goimagehash.ImageHash
	RichAverageHash *goimagehash.ImageHash
	RichDifferenceHash *goimagehash.ImageHash
}

func (b BinViz) AverageDistance(altBinViz BinViz) int {
	distance, err := b.BinAverageHash.Distance(altBinViz.BinAverageHash)
	if err != nil {
		return 0
	}
	return distance
}

func (b BinViz) DifferenceDistance(altBinViz BinViz) int {
	distance, err := b.BinDifferenceHash.Distance(altBinViz.BinDifferenceHash)
	if err != nil {
		return 0
	}
	return distance
}

func (b BinViz) SaveImage(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	err = png.Encode(file, b.Image)
	if err != nil {
		return err
	}
	return nil
}

func ProcessBinary(data []byte) (BinViz, error) {
	var binViz BinViz
	var err error
	binViz.RichDiffResults, err = richdiff.RichExtraction(data)
	if err != nil {
		log.Println(err.Error())
	}
	binViz.Image, err = byteToPng(data)
	if err != nil {
		log.Println(err.Error())
		return BinViz{}, err
	}
	binViz.BinAverageHash, err = goimagehash.AverageHash(binViz.Image)
	if err != nil {
		log.Println(err.Error())
	}
	binViz.BinDifferenceHash, err = goimagehash.DifferenceHash(binViz.Image)
	if err != nil {
		log.Println(err.Error())
	}
	binViz.RichAverageHash, err = goimagehash.AverageHash(binViz.RichDiffResults.ByteImage)
	if err != nil {
		log.Println(err.Error())
	}
	binViz.RichDifferenceHash, err = goimagehash.DifferenceHash(binViz.RichDiffResults.ByteImage)
	if err != nil {
		log.Println(err.Error())
	}
	return binViz, nil
}

func byteToPng(data []byte) (image.Image, error) {
	byteSize := len(data)
	sideLength := math.Sqrt(float64(byteSize))
	imageSideLength := int(math.Ceil(sideLength))
	sizeDiff := (imageSideLength * imageSideLength) - byteSize
	if sizeDiff > 0 {
		data = append(data, make([]byte, sizeDiff)...)
	}
	img := image.NewRGBA(image.Rect(0, 0, imageSideLength, imageSideLength))
	for i := 0; i < imageSideLength; i++ {
		for j := 0; j < imageSideLength; j++ {
			img.Set(i, j, color.RGBA{
				uint8(data[j*imageSideLength+i]),
				uint8(255 - data[j*imageSideLength+i]),
				uint8(255 - data[j*imageSideLength+i]),
				uint8(data[j*imageSideLength+i]),
			})
		}
	}
	return img, nil
}