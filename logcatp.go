///bin/true; exec /usr/bin/env go run "$0" "$@"

package main

import (
	_ "bufio"
	"flag"
	"fmt"
	"github.com/omakoto/mlib"
	_ "io"
	"io/ioutil"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	pidPatterns = []*regexp.Regexp{
		// brief
		regexp.MustCompile(`^[A-Z]/.+?\(\s*(\d+)`),
		// process or thread
		regexp.MustCompile(`^[A-Z]\(\s*(\d+)`),
		// threadtime
		regexp.MustCompile(`^\d{2}-\d{2}\s+[\d\:\.]+\s+(\d+)`),
		// time
		regexp.MustCompile(`^\d{2}-\d{2} [\d\:\.]+ [A-Z]\/.*?\(\s*(\d+)`),
		// regexp.MustCompile(`^.*?\(\s*(\d+)`),
		// long
		regexp.MustCompile(`^\[\s*\d{2}-\d{2}\s+[\d\:\.]+\s+(\d+)`),
	}

	diePatterns = []*regexp.Regexp{
		regexp.MustCompile(`ActivityManager.*?Process .*?\(pid (\d+)\) has died`),
		regexp.MustCompile(`ActivityManager.*?Killing (\d+)`),
		// Any more?
	}

	whiteSpaces = regexp.MustCompile(`\s+`)

	// Flags
	// autoflush = flag.Bool("f", false, "autoflush") // ?? Not needed?
	width = flag.Int("w", 40, "formatting width")

	// PID -> process name
	procecces = make(map[int]string)

	// Output line format
	outFormat string
)

const (
	PRE_INITIALIZED                       = "<pre-initialized>"
	MAX_PRE_INITIALIZED_RETRY             = 5
	MAX_PRE_INITIALIZED_RETRY_INTERVAL_MS = 200
)

func getProcessNameFromAdbRaw(pid int) string {
	cmd := exec.Command("adb", "shell", fmt.Sprintf("cat /proc/%d/cmdline 2>/dev/null", pid))
	stdout, err := cmd.StdoutPipe()
	mlib.Check(err)

	err = cmd.Start()
	mlib.Check(err)
	defer cmd.Wait()

	cmdline, err := ioutil.ReadAll(stdout)
	mlib.Check(err)

	procname := string(cmdline)
	procname = strings.TrimRight(procname, "\000")
	return procname
}

// Same as getProcessNameFromAdbRaw, but retries when getting PRE_INITIALIZED
func getProcessNameFromAdb(pid int) string {
	var pname string = "(unknown)"

	for i := 0; i <= MAX_PRE_INITIALIZED_RETRY; i++ {
		rawName := getProcessNameFromAdbRaw(pid)
		if rawName == PRE_INITIALIZED {
			mlib.Debug("%s detected\n", PRE_INITIALIZED)
			time.Sleep(MAX_PRE_INITIALIZED_RETRY_INTERVAL_MS * time.Millisecond)
			continue
		}
		if rawName != "" {
			pname = rawName
		}
		break
	}
	return fmt.Sprintf("%s %d", pname, pid)
}

func getProcessNameWithCache(pid int) string {
	name := procecces[pid]
	if name == "" {
		name = getProcessNameFromAdb(pid)
		procecces[pid] = name
	}
	return name
}

// Run for each line
func processLine(line string) {
	var pid = 0
	var processName = ""

	// Find the pid from the line and get the process name
	for _, re := range pidPatterns {
		s := re.FindStringSubmatch(line)
		if s != nil {
			pid, _ = strconv.Atoi(s[1])
			// mlib.Debug("pid=%d\n", pid)
			processName = getProcessNameWithCache(pid)
			break
		}
	}

	// Any process died?
	for _, re := range diePatterns {
		s := re.FindStringSubmatch(line)
		if s != nil {
			diedPid, _ := strconv.Atoi(s[1])
			mlib.Debug("Process %d died\n", diedPid)
			delete(procecces, diedPid)
			break
		}
	}

	fmt.Printf(outFormat, processName, line)
}

func main() {
	flag.Parse()

	outFormat = fmt.Sprintf("[%%-%ds] %%s", *width)

	for line := range mlib.ReadFilesFromArgs() {
		processLine(line)
	}
}