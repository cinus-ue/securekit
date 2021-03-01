package cmd

import (
	"fmt"
	"runtime"

	"github.com/cinus-ue/securekit/kit"
	"github.com/cinus-ue/securekit/kit/sema"
)

var semaphore = sema.NewSemaphore(runtime.NumCPU())

type FileFunc func(path string) error

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

func ApplyAllFiles(files *kit.Stack, fn FileFunc) error {
	for files.Len() > 0 {
		path := files.Pop()
		semaphore.Add(1)
		go func() {
			defer semaphore.Done()
			fmt.Printf("\n[*]processing file:%s", path)
			err := fn(path.(string))
			if err != nil {
				fmt.Printf("\n[*]ERROR-[%s]", err.Error())
				files.Clear()
			}
		}()
	}
	semaphore.Wait()
	OperationCompleted()
	return nil
}

func OperationCompleted() {
	fmt.Print("\n[*]Operation Completed\n")
}
