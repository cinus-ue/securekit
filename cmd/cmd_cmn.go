package cmd

import (
	"fmt"
	"runtime"

	"github.com/cinus-ue/securekit/kit"
	"github.com/cinus-ue/securekit/kit/sema"
	"github.com/cinus-ue/securekit/util"
)

var semaphore = sema.NewSemaphore(runtime.NumCPU())

type FileFunc func(path string) error

func ApplyAllFiles(files *kit.Stack, fn FileFunc) error {
	for files.Len() > 0 {
		path := files.Pop()
		go func() {
			defer semaphore.Done()
			semaphore.Add(1)
			fmt.Printf("\n[*]processing file:%s", path)
			err := fn(path.(string))
			util.CheckErr(err)
		}()
	}
	semaphore.Wait()
	OperationCompleted()
	return nil
}

func ApplyOrderedFiles(files *kit.Stack, fn FileFunc) error {
	for files.Len() > 0 {
		path := files.Pop()
		fmt.Printf("\n[*]processing file:%s", path)
		err := fn(path.(string))
		if err != nil {
			return err
		}
	}
	OperationCompleted()
	return nil
}

func OperationCompleted() {
	fmt.Print("\n[*]Operation Completed\n")
}
