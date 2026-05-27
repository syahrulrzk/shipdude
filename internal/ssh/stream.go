package ssh

import (
	"bufio"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"
)

// RunCommandStream executes a command on the remote server and streams stdout/stderr line-by-line.
func RunCommandStream(client *ssh.Client, cmd string, onLine func(string)) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return err
	}

	if err := session.Start(cmd); err != nil {
		return err
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	safeOnLine := func(line string) {
		mu.Lock()
		defer mu.Unlock()
		onLine(line)
	}

	copyStream := func(r io.Reader) {
		defer wg.Done()
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			safeOnLine(scanner.Text())
		}
	}

	wg.Add(2)
	go copyStream(stdout)
	go copyStream(stderr)

	wg.Wait()
	return session.Wait()
}
