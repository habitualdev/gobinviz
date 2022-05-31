package binviz

import (
	"github.com/ajdnik/imghash"
	"github.com/ajdnik/imghash/hashtype"
	"github.com/ajdnik/imghash/similarity"
	"github.com/corona10/goimagehash"
	"github.com/roaldi/richdiff"
	"github.com/dsoprea/hilbert"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
	"github.com/saferwall/pe"
)

type BinViz struct {
	BinaryBytes []byte
	RichDiffResults richdiff.Results
	Image image.Image
	BinAverageHash *goimagehash.ExtImageHash
	BinDifferenceHash *goimagehash.ExtImageHash
	RichAverageHash *goimagehash.ImageHash
	RichDifferenceHash *goimagehash.ImageHash
	BlockHash hashtype.Binary
	MedianHash hashtype.Binary
	MarrHildeHash hashtype.Binary
	PEInfo *pe.File
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

func (b BinViz) RichAverageDistance(altBinViz BinViz) int {
	distance, err := b.RichAverageHash.Distance(altBinViz.RichAverageHash)
	if err != nil {
		return 0
	}
	return distance
}

func (b BinViz) RichDifferenceDistance(altBinViz BinViz) int {
	distance, err := b.RichDifferenceHash.Distance(altBinViz.RichDifferenceHash)
	if err != nil {
		return 0
	}
	return distance
}

func (b BinViz) BlockHashDistance(altBinViz BinViz) int {
	distance := similarity.Hamming(b.BlockHash, altBinViz.BlockHash)
	return int(distance)
}

func (b BinViz) MedianDistance(altBinViz BinViz) int {
	distance := similarity.Hamming(b.MedianHash, altBinViz.MedianHash)
	return int(distance)
}

func (b BinViz) MarrHildeDistance(altBinViz BinViz) int {
	distance := similarity.Hamming(b.MarrHildeHash, altBinViz.MarrHildeHash)
	return int(distance)
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
	binViz.PEInfo, _ = pe.NewBytes(data, &pe.Options{})
	binViz.BinaryBytes = data
	binViz.PEInfo.Parse()
	binViz.RichDiffResults, err = richdiff.RichExtraction(data)
	if err != nil {
		log.Println(err.Error())
	}
	binViz.Image, err = byteToPng(binViz)
	if err != nil {
		log.Println(err.Error())
		return BinViz{}, err
	}
	binViz.BinAverageHash, err = goimagehash.ExtAverageHash(binViz.Image, 16, 16)
	if err != nil {
		log.Println(err.Error())
	}
	binViz.BinDifferenceHash, err = goimagehash.ExtDifferenceHash(binViz.Image, 32, 32)
	if err != nil {
		log.Println(err.Error())
	}
	if binViz.RichDiffResults.ByteImage != nil {
		binViz.RichAverageHash, err = goimagehash.AverageHash(binViz.RichDiffResults.ByteImage)
		if err != nil {
			log.Println(err.Error())
		}
		binViz.RichDifferenceHash, err = goimagehash.DifferenceHash(binViz.RichDiffResults.ByteImage)
		if err != nil {
			log.Println(err.Error())
		}
	}
	bmhash := imghash.NewBlockMean()
	binViz.BlockHash = bmhash.Calculate(binViz.Image)
	medianHash := imghash.NewMedian()
	binViz.MedianHash = medianHash.Calculate(binViz.Image)
	marrHash := imghash.NewMarrHildreth()
	binViz.MarrHildeHash = marrHash.Calculate(binViz.Image)
	return binViz, nil
}

func byteToPng(b BinViz) (image.Image, error) {
	var sectionAddresses []uint32
	byteSize := len(b.BinaryBytes)
	sideLength := math.Sqrt(float64(byteSize))
	imageSideLength := int(math.Ceil(sideLength))
	sizeDiff := (imageSideLength * imageSideLength) - byteSize
	if sizeDiff > 0 {
		b.BinaryBytes = append(b.BinaryBytes, make([]byte, sizeDiff)...)
	}
	img := image.NewRGBA(image.Rect(0, 0, imageSideLength, imageSideLength))
	hilbertSize := 2
	for hilbertSize < byteSize {
		hilbertSize *= 2
	}
	for _, section := range b.PEInfo.Sections{
		sectionAddresses =  append(sectionAddresses, section.Header.VirtualAddress)
	}

	sectionStep := 1
	if len(sectionAddresses) > 1 {
		sectionStep = 255 / len(sectionAddresses)
	}
	sectionColor := 0
	for i := 0; i <byteSize; i++{
		for _, address := range sectionAddresses{
			if i == int(address/4){
				sectionColor = sectionColor + sectionStep
			}
		}
		h, _ := hilbert.NewHilbert64(uint64(hilbertSize))
		x, y, _ := h.Map(uint64(i+1))
		img.SetRGBA(int(x), int(y), color.RGBA{uint8(128 - sectionColor/2), b.BinaryBytes[i], 32, 255})
	}
	return img, nil
}