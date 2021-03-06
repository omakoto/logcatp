///bin/true; exec /usr/bin/env go run "$0" "$@"

package main

import (
	"flag"
	"fmt"
	"github.com/omakoto/go-common/src/common"
	"github.com/omakoto/go-common/src/textio"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// Patterns to extract PIDs from logs.
	pidPatterns = []*regexp.Regexp{
		// uid
		regexp.MustCompile(`^\d{2}-\d{2}\s+[\d\:\.]+\s+[a-zA-Z_0-9]+\s+(\d+)\s+\d`),
		// threadtime
		regexp.MustCompile(`^\d{2}-\d{2}\s+[\d\:\.]+\s+(\d+)`),
		// brief
		regexp.MustCompile(`^[A-Z]/.+?\(\s*(\d+)`),
		// process or thread
		regexp.MustCompile(`^[A-Z]\(\s*(\d+)`),
		// time
		regexp.MustCompile(`^\d{2}-\d{2} [\d\:\.]+ [A-Z]\/.*?\(\s*(\d+)`),
		// regexp.MustCompile(`^.*?\(\s*(\d+)`),
		// long
		regexp.MustCompile(`^\[\s*\d{2}-\d{2}\s+[\d\:\.]+\s+(\d+)`),
	}

	// Patterns to extract PIDs for process deaths logs.
	diePatterns = []*regexp.Regexp{
		regexp.MustCompile(`ActivityManager.*?Process .*?\(pid (\d+)\) has died`),
		regexp.MustCompile(`ActivityManager.*?Killing (\d+)`),
		// Any more?
	}

	whiteSpaces = regexp.MustCompile(`\s+`)

	// Flags
	width = flag.Int("w", 40, "formatting width")
	// autoflush = flag.Bool("f", false, "autoflush") // Stdout seems like always flushing

	// Output line format
	outFormat string

	// Process info cache.
	procecces = make(map[int]processInfo)

	cacheExpiration = time.Minute * 10
)

const (
	PRE_INITIALIZED                       = "<pre-initialized>"
	MAX_PRE_INITIALIZED_RETRY             = 5
	MAX_PRE_INITIALIZED_RETRY_INTERVAL_MS = 200
)

type processInfo struct {
	name       string
	expiration time.Time
}

func getProcessNameFromAdbRaw(pid int) string {
	cmd := exec.Command("adb", "shell", fmt.Sprintf("cat /proc/%d/cmdline 2>/dev/null", pid))
	out, err := cmd.Output()
	if err != nil {
		return "(not found)"
	}

	procname := string(out)
	procname = strings.TrimRight(procname, "\000")
	procname = strings.Replace(procname, "\000", " ", -1)
	return procname
}

// Same as getProcessNameFromAdbRaw, but retries when getting PRE_INITIALIZED
func getProcessNameFromAdb(pid int) string {
	var pname string = "(unknown)"

	common.Debugf("Getting process name for %d\n", pid)

	for i := 0; i <= MAX_PRE_INITIALIZED_RETRY; i++ {
		rawName := getProcessNameFromAdbRaw(pid)
		if rawName == PRE_INITIALIZED {
			common.Debugf("%s detected\n", PRE_INITIALIZED)
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
	now := time.Now()
	pinfo, ok := procecces[pid]
	if !ok || now.After(pinfo.expiration) {
		name := getProcessNameFromAdb(pid)
		pinfo = processInfo{name: name, expiration: now.Add(cacheExpiration)}
		procecces[pid] = pinfo
	}
	return pinfo.name
}

// Run for each line
func processLine(line []byte) {
	var pid = 0
	var processName = "(pid not found)"

	// Find the pid from the line and get the process name
	for _, re := range pidPatterns {
		s := re.FindSubmatch(line)
		if s != nil {
			pid, _ = strconv.Atoi(string(s[1]))
			processName = getProcessNameWithCache(pid)
			break
		}
	}

	// Any process died?
	for _, re := range diePatterns {
		s := re.FindSubmatch(line)
		if s != nil {
			diedPid, _ := strconv.Atoi(string(s[1]))
			log.Printf("Process %d died\n", diedPid)
			delete(procecces, diedPid)
			break
		}
	}

	fmt.Printf(outFormat, processName, line)
}

func main() {
	log.SetPrefix("logcatp: ")
	log.SetFlags(0)
	flag.Parse()

	outFormat = fmt.Sprintf("[%%-%ds] %%s", *width)

	textio.ReadFiles(os.Args[1:], func(line []byte, lineNo int, filename string) error {
		processLine(line)
		return nil
	})
}
