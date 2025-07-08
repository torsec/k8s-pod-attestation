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
	fmt.Printf(green.Sprintf("[SUCCESS] [%s] %s\n", time.Now().Format(timeFormat), message))
}

func Error(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Printf(red.Sprintf("[ERROR] [%s] %s \n", time.Now().Format(timeFormat), message))
}

func Warning(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Printf(yellow.Sprintf("[WARNING] [%s] %s \n", time.Now().Format(timeFormat), message))
}

func Info(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Printf(cyan.Sprintf("[INFO] [%s] %s \n", time.Now().Format(timeFormat), message))
}

func Fatal(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Printf(red.Sprintf("[FATAL] [%s] %s \n", time.Now().Format(timeFormat), message))
	os.Exit(1)
}
