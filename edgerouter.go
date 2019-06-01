package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"regexp"
	"time"

	"github.com/dparrish/go-autoconfig"
	expect "github.com/google/goexpect"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

var promptRE = regexp.MustCompile(`(?:gw-1#|gw-1:~\$)`)

type EdgeRouter struct {
	config  *autoconfig.Config
	client  *ssh.Client
	session *ssh.Session
	expect  *expect.GExpect
}

func (e *EdgeRouter) Connect(ctx context.Context) error {
	key, err := ioutil.ReadFile(e.config.Get("edgerouter.ssh_key"))
	if err != nil {
		return fmt.Errorf("unable to read private key %q: %v", e.config.Get("edgerouter.ssh_key"), err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("unable to parse private key %q: %v", e.config.Get("edgerouter.ssh_key"), err)
	}

	config := &ssh.ClientConfig{
		User:            e.config.Get("edgerouter.user"),
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", e.config.Get("edgerouter.ip_port"), config)
	if err != nil {
		return fmt.Errorf("error connecting to EdgeRouter at %s: %v", e.config.Get("edgerouter.ip_port"), err)
	}

	e.client = client

	x, _, err := expect.SpawnSSH(e.client, 10*time.Minute)
	if err != nil {
		e.Close()
		return fmt.Errorf("couldn't start expect: %v", err)
	}
	e.expect = x
	e.expect.Expect(promptRE, 10*time.Minute)

	if _, err := e.run(ctx, "configure"); err != nil {
		e.Close()
		return fmt.Errorf("couldn't enter configuration mode: %v", err)
	}

	return nil
}

func (e *EdgeRouter) Close() error {
	e.client.Close()
	return nil
}

func (e *EdgeRouter) Clear(ctx context.Context) error {
	if _, err := e.run(ctx, "delete firewall group address-group rootblocker address"); err != nil {
		return fmt.Errorf("failed to clear ruleset: %v", err)
	}
	return nil
}

func (e *EdgeRouter) AddIP(ctx context.Context, ip string) error {
	if _, err := e.run(ctx, fmt.Sprintf("set firewall group address-group rootblocker address %s", ip)); err != nil {
		return fmt.Errorf("failed to add IP: %v", err)
	}
	return nil
}

func (e *EdgeRouter) RemoveIP(ctx context.Context, ip string) error {
	return nil
}

func (e *EdgeRouter) Commit(ctx context.Context) error {
	if _, err := e.run(ctx, "commit"); err != nil {
		return fmt.Errorf("failed to commit: %v", err)
	}
	return nil
}

func (e *EdgeRouter) run(ctx context.Context, cmd string) (string, error) {
	log.Infof("Sending command: %s", cmd)
	e.expect.Send(fmt.Sprintf("%s\n", cmd))
	result, _, _ := e.expect.Expect(promptRE, 10*time.Minute)
	log.Infof("Got response: %s", string(result))
	return result, nil
}
