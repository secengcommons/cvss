package mixedradix

func FillStrides(strides, radices []uint64, initial uint64) {
	if len(strides) != len(radices) || initial == 0 {
		panic("invalid mixed-radix layout")
	}
	stride := initial
	for index, radix := range radices {
		if radix < 2 || stride > ^uint64(0)/radix {
			panic("invalid mixed-radix layout")
		}
		strides[index] = stride
		stride *= radix
	}
}

func Digit(raw, stride, radix uint64) uint64 { return raw / stride % radix }

func Replace(raw, stride, radix, replacement uint64) uint64 {
	current := Digit(raw, stride, radix)
	if replacement >= current {
		return raw + (replacement-current)*stride
	}
	return raw - (current-replacement)*stride
}
