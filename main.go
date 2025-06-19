package main

import (
	"encoding/binary"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
)

var (
	globalHeader []byte
	once         sync.Once
	outLock      sync.Mutex
)

func usageExit() {
	log.Printf("Usage: %s ssh host [host..] -- <tcpdump command>", os.Args[0])
	log.Printf("Usage: %s run 'tcpdump -i en0 -U -w -' 'tcpdump -i en1 -U -w -'", os.Args[0])
	os.Exit(1)
}

func main() {
	if len(os.Args) < 3 {
		usageExit()
	}

	var wg sync.WaitGroup
	var cmd = os.Args[1]
	if cmd == "ssh" {
		args := os.Args[2:]
		sep := -1
		for i, a := range args {
			if a == "--" {
				sep = i
				break
			}
		}
		if sep == -1 || sep == len(args)-1 {
			log.Fatal("Missing '--' or tcpdump command")
		}

		hosts := args[:sep]
		command := strings.Join(args[sep+1:], " ")

		for _, host := range hosts {
			if err := wrapCommand(&wg, host, "ssh", host, command); err != nil {
				os.Exit(1)
			}
		}
	} else if cmd == "run" {
		for _, subcmd := range os.Args[2:] {
			if err := wrapCommand(&wg, subcmd, "sh", "-c", subcmd); err != nil {
				os.Exit(1)
			}
		}
	} else {
		usageExit()
	}
	wg.Wait()
	log.Printf("[pcapmux exiting]")
}

func wrapCommand(wg *sync.WaitGroup, desc string, command string, args ...string) error {
	log.Printf("[%s] start", desc)

	cmd := exec.Command(command, args...)
	cmd.Stderr = os.Stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("[%s] Failed to get stdout: %v", desc, err)
		return err
	}

	if err := cmd.Start(); err != nil {
		log.Printf("[%v] %v failed: %v", desc, args, err)
		return err
	}

	// read pcap header before spawning goroutine
	// which gives the remote machine time to prompt for input first
	localHeader := make([]byte, 24)
	if _, err := io.ReadFull(stdout, localHeader); err != nil {
		if err != io.EOF {
			log.Printf("[%s] Failed to read global header: %v", desc, err)
		}
		return err
	}

	// only write global header once
	once.Do(func() {
		outLock.Lock()
		defer outLock.Unlock()
		_, err := os.Stdout.Write(localHeader)
		if err != nil && err != io.EOF {
			log.Printf("[%s] Error writing global header: %v", desc, err)
		}
	})

	wg.Add(1)
	go func() {
		wrapStream(desc, stdout)
		wg.Done()
	}()
	return nil
}

func wrapStream(desc string, stream io.Reader) {
	// stream each packet
	header := make([]byte, 16)
	packetBuf := make([]byte, 65536)
	for {
		if _, err := io.ReadFull(stream, header); err != nil {
			if err != io.EOF {
				log.Printf("[%s] Error reading packet header: %v", desc, err)
			}
			break
		}

		inclLen := binary.LittleEndian.Uint32(header[8:12])
		packet := packetBuf[:inclLen]
		if _, err := io.ReadFull(stream, packet); err != nil {
			if err != io.EOF {
				log.Printf("[%s] Error reading packet data: %v", desc, err)
			}
			break
		}

		// write header and packet together
		outLock.Lock()
		_, err1 := os.Stdout.Write(header)
		_, err2 := os.Stdout.Write(packet)
		outLock.Unlock()
		if err1 != nil {
			if err1 != io.EOF {
				log.Printf("[%s] Error writing packet header: %v", desc, err1)
			}
			break
		}
		if err2 != nil {
			if err2 != io.EOF {
				log.Printf("[%s] Error writing packet body: %v", desc, err2)
			}
			break
		}
	}
}

