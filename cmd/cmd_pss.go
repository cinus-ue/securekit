package cmd

import (
	"fmt"
	"strconv"

	"github.com/cinus-ue/securekit/kit/pass"
	"github.com/cinus-ue/securekit/util"
	"github.com/urfave/cli/v2"
)

var Pss = &cli.Command{
	Name:   "pss",
	Usage:  "Generate secure, random password",
	Action: PassAction,
}

func PassAction(*cli.Context) error {
	length, err := strconv.Atoi(util.GetInput("Password Length:"))
	if err != nil {
		return err
	}
	password := pass.GenerateRandomString(true, true, length)
	fmt.Println("Your new password is:", password)
	return nil
}
