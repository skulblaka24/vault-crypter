package functions

import (
	"fmt"
)

type Color string

const (
    ColorBlack  Color = "\u001b[30m"
    ColorRed          = "\u001b[31m"
    ColorGreen        = "\u001b[32m"
    ColorYellow       = "\u001b[33m"
    ColorBlue         = "\u001b[34m"
    ColorMagenta      = "\u001b[35m"
    ColorCyan         = "\u001b[36m"
    ColorWhite        = "\u001b[37m"
    ColorReset        = "\u001b[0m"
)

func Colorize(color Color, message string) {
    fmt.Printf("%v%v%v", string(color), message, string(ColorReset))
}