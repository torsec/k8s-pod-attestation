package logger

import (
	"fmt"
	"github.com/fatih/color"
	"os"
	"time"
)

const timeFormat = "02-01-2006 15:04:05"

var (
	red    = color.New(color.FgRed)
	green  = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)
	cyan   = color.New(color.FgCyan)
)

func Success(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Printf(green.Sprintf("[%s] %s\n", time.Now().Format(timeFormat), message))
}

func Error(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Printf(red.Sprintf("[%s] %s \n", time.Now().Format(timeFormat), message))
}

func Warning(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Printf(yellow.Sprintf("[%s] %s \n", time.Now().Format(timeFormat), message))
}

func Info(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Printf(cyan.Sprintf("[%s] %s \n", time.Now().Format(timeFormat), message))
}

func Fatal(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Printf(red.Sprintf("[%s] %s \n", time.Now().Format(timeFormat), message))
	os.Exit(1)
}
