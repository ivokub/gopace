package main

import (
	"fmt"

	"github.com/ivokub/gopace"
)

func main() {
	card, cancel, err := gopace.Connect()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer cancel()
	_, _ = gopace.PACE(card, nil)
}
