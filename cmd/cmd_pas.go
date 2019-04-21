package cmd

import (
	"fmt"
	"strconv"

	"github.com/cinus-ue/securekit-go/kit/pass"
	"github.com/cinus-ue/securekit-go/util"
	"github.com/urfave/cli"
)

var Pas = cli.Command{
	Name:   "pas",
	Usage:  "Generate secure, random password",
	Action: PassAction,
}

func PassAction(*cli.Context) error {
	source := util.GetInput("Password Length:")
	len, err := strconv.Atoi(source)
	if err != nil {
		return err
	}
	password, err := pass.GenerateRandomPass(len)
	if err != nil {
		return err
	}
	fmt.Printf("Your new password is:%s\n", password[:len])
	return nil
}
