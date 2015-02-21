package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nyushi/tlschk"
)

func main() {
	result := tlschk.DoCheck(os.Stdin)
	outBytes, _ := json.MarshalIndent(result, "", "  ")
	fmt.Printf("%s", outBytes)
}
