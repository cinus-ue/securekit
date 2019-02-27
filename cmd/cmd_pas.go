package cmd

import (
	"fmt"
	"github.com/cinus-ue/securekit-go/kit/pass"
	"strconv"

	"github.com/cinus-ue/securekit-go/util"
	"github.com/urfave/cli"
	)

var Pas = cli.Command{
	Name:  "pas",
	Usage: "Secure password generator",
	Action: passAction,
}


func passAction(*cli.Context)error{
	source := util.GetInput("Password Length:")
	len, err := strconv.Atoi(source)
	if err != nil {
		return err
	}
	password,err :=pass.GenerateRandomString(len)
	if err !=nil {
		return err
	}
	fmt.Printf("Your new password is:%s\n",password[:len])
	return nil
}