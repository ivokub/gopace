package main

import (
	"fmt"
)

func main() {
	card, cancel, err := Connect()
	if err != nil {
		fmt.Println(err)
		return
	}
	defer cancel()
	_, _ = PACE(card, nil)
}
