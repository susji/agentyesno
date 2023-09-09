package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func main() {
	var listen, agent string
	ac := AgentConfig{
		signlock: &sync.Mutex{},
		sigs:     new(atomic.Uint64),
	}

	flag.StringVar(&listen, "listen", getsocketdefault(), "Path for our listening agent socket")
	flag.StringVar(&agent, "agent", getagentdefault(), "Path to real SSH agent's domain socket")
	flag.BoolVar(&ac.fullkeys, "fullkeys", false, "Dump public keys on sign requests instead of digests")
	flag.BoolVar(&ac.easyyes, "easyyes", false, "Use `yes` instead of counter for permitting Sign requests")
	flag.BoolVar(&ac.verbose, "verbose", false, "Verbose logging")
	flag.DurationVar(
		&ac.timeout,
		"timeout",
		15*time.Second,
		"Duration to wait for user input on sign request")
	flag.Parse()

	log.Print("listen: ", listen)
	log.Print("agent: ", agent)
	log.Print("timeout: ", ac.timeout)
	log.Print("fullkeys: ", ac.fullkeys)
	log.Print("easyyes: ", ac.easyyes)
	log.Print("verbose: ", ac.verbose)
	ensurepaths(listen, agent)

	inerr := 0
	if len(listen) == 0 {
		inerr++
		ac.Important("missing listen path")
	}
	if len(agent) == 0 {
		inerr++
		ac.Important("missing agent path")
	}
	if inerr > 0 {
		ac.Important("errors, bailing")
	}

	if err := os.RemoveAll(listen); err != nil {
		log.Fatal("cannot remove existing listening socket:", err)
	}
	syscall.Umask(0177)
	l, err := net.Listen("unix", listen)
	if err != nil {
		log.Fatal("cannot open listening socket:", err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		sig := <-c
		ac.Important("bailing, got signal %s", sig)
		l.Close()
		if err := os.RemoveAll(listen); err != nil {
			ac.Important("cannot cleanup listening socket: %v", err)
		}
		os.Exit(1)
	}()

	for {
		c, err := l.Accept()
		if err != nil {
			ac.Fatal("cannot accept on listening socket: %v", err)
		}
		ac.Verbose("new client")
		go handle(c, agent, ac)
	}
}

func handle(cc net.Conn, ap string, config AgentConfig) {
	defer cc.Close()
	ca, err := net.Dial("unix", ap)
	if err != nil {
		log.Print("cannot dial real agent:", err)
		return
	}
	defer ca.Close()

	a := agent.NewClient(ca)
	ayn := &AgentYesNo{agent: a, AgentConfig: config}
	agent.ServeAgent(ayn, cc)
}

type AgentConfig struct {
	timeout  time.Duration
	signlock *sync.Mutex
	sigs     *atomic.Uint64
	fullkeys bool
	easyyes  bool
	verbose  bool
}

func (ac *AgentConfig) Verbose(fmt string, va ...interface{}) {
	if ac.verbose {
		log.Printf(fmt, va...)
	}
}

func (ac *AgentConfig) Important(fmt string, va ...interface{}) {
	log.Printf(fmt, va...)
}

func (ac *AgentConfig) Fatal(fmt string, va ...interface{}) {
	log.Fatalf(fmt, va...)
}

type AgentYesNo struct {
	agent agent.Agent
	AgentConfig
}

func (a *AgentYesNo) Add(key agent.AddedKey) error {
	a.Verbose("request: Add")
	return a.agent.Add(key)
}

func (a *AgentYesNo) List() ([]*agent.Key, error) {
	a.Verbose("request: List")
	return a.agent.List()
}

func (a *AgentYesNo) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	log.Println("request: Sign")
	id := a.sigs.Add(1)
	p := func(fmt string, va ...interface{}) {
		args := []interface{}{id}
		args = append(args, va...)
		log.Printf("[%d] "+fmt, args...)
	}

	var keydump string
	if a.fullkeys {
		keydump = fmt.Sprintf("%v", key)
	} else {
		keydump = ssh.FingerprintSHA256(key)
	}
	p("Sign request incoming for key: %s", keydump)
	a.signlock.Lock()
	defer a.signlock.Unlock()

	t0 := time.Now()
	if a.easyyes {
		p("Do you want to accept [yes means 'yes', everything else means 'no']?")
	} else {
		p("Do you want to accept [%d means 'yes', everything else means 'no']?", id)
	}
	var yn string
	fmt.Scanln(&yn)
	t1 := time.Now()
	if t1.After(t0.Add(a.timeout)) {
		p("timed out")
		return nil, errors.New("approval timed out")
	}
	ynf := strings.TrimSpace(yn)
	if (a.easyyes && ynf != "yes") ||
		(!a.easyyes && ynf != strconv.FormatUint(id, 10)) {
		p("request denied")
		return nil, errors.New("request denied")
	}
	p("request accepted, forwarding Sign Request")
	retsig, reterr := a.agent.Sign(key, data)
	if reterr != nil {
		p("sign request failed: %v", reterr)
		return nil, reterr
	}
	p(
		"-> format=%s, blob=%d bytes, rest=%d bytes",
		retsig.Format, len(retsig.Blob), len(retsig.Rest))
	return retsig, reterr
}

func (a *AgentYesNo) Remove(key ssh.PublicKey) error {
	a.Verbose("request: Remove")
	return a.agent.Remove(key)
}

func (a *AgentYesNo) RemoveAll() error {
	a.Verbose("request: RemoveAll")
	return a.agent.RemoveAll()
}

func (a *AgentYesNo) Lock(passphrase []byte) error {
	a.Verbose("request: Lock")
	return a.agent.Lock(passphrase)
}

func (a *AgentYesNo) Unlock(passphrase []byte) error {
	a.Verbose("request: Unlock")
	return a.agent.Unlock(passphrase)
}

func (a *AgentYesNo) Signers() ([]ssh.Signer, error) {
	a.Verbose("request: Signers")
	return a.agent.Signers()
}

func getsocketdefault() string {
	sockdir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: unable to get home directory: %v\n", err)
		fmt.Fprintln(os.Stderr, "set the listening path manually to some safe location with `-listen`")
		return ""
	}
	return path.Join(sockdir, ".agentyesno.socket")
}

func getagentdefault() string {
	val, ok := os.LookupEnv("SSH_AUTH_SOCK")
	if !ok {
		return ""
	}
	return val
}

func ensurepaths(one, two string) {
	// This is very much not a complete solution, but much better than
	// nothing. If someone really separates their agent files with only
	// spaces, we'll gladly break that setup. Also, we could try digging
	// through Stat->Sys to find some inode numbers, but this is good
	// enough.
	if strings.TrimSpace(one) == strings.TrimSpace(two) {
		fmt.Fprintf(os.Stderr, "identical agent and listening paths: %s", one)
		os.Exit(1)
	}
}
