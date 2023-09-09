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
	var timeout time.Duration
	var fullkeys, easyyes bool

	flag.StringVar(&listen, "listen", getsockpath(), "Path to `agentyesno` domain socket")
	flag.StringVar(&agent, "agent", getagentdefault(), "Path to real SSH agent's domain socket")
	flag.BoolVar(&fullkeys, "fullkeys", false, "Dump public keys on sign requests instead of digests")
	flag.BoolVar(&easyyes, "easyyes", false, "Use `yes` instead of counter for permitting Sign requests")
	flag.DurationVar(
		&timeout,
		"timeout",
		15*time.Second,
		"Duration to wait for user input on sign request")
	flag.Parse()

	log.Print("listen: ", listen)
	log.Print("agent: ", agent)
	ensurepaths(listen, agent)

	inerr := 0
	if len(listen) == 0 {
		inerr++
		log.Print("missing listen path")
	}
	if len(agent) == 0 {
		inerr++
		log.Print("missing agent path")
	}
	if inerr > 0 {
		log.Fatal("errors, bailing")
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
		log.Print("bailing, got signal ", sig)
		l.Close()
		if err := os.RemoveAll(listen); err != nil {
			log.Print("cannot cleanup listening socket:", err)
		}
		os.Exit(1)
	}()

	ac := AgentConfig{
		timeout:  timeout,
		signlock: &sync.Mutex{},
		sigs:     new(atomic.Uint64),
		fullkeys: fullkeys,
		easyyes:  easyyes,
	}
	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatal("cannot accept on listening socket:", err)
		}
		log.Print("new client")
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
	ayn := &AgentYesNo{agent: a, config: config}
	agent.ServeAgent(ayn, cc)
}

type AgentConfig struct {
	timeout  time.Duration
	signlock *sync.Mutex
	sigs     *atomic.Uint64
	fullkeys bool
	easyyes  bool
}

type AgentYesNo struct {
	agent  agent.Agent
	config AgentConfig
}

func (a *AgentYesNo) Add(key agent.AddedKey) error {
	log.Println("request: Add")
	return a.agent.Add(key)
}

func (a *AgentYesNo) List() ([]*agent.Key, error) {
	log.Println("request: List")
	return a.agent.List()
}

func (a *AgentYesNo) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	log.Println("request: Sign")
	id := a.config.sigs.Add(1)
	p := func(fmt string, va ...interface{}) {
		args := []interface{}{id}
		args = append(args, va...)
		log.Printf("[%d] "+fmt, args...)
	}

	var keydump string
	if a.config.fullkeys {
		keydump = fmt.Sprintf("%v", key)
	} else {
		keydump = ssh.FingerprintSHA256(key)
	}
	p("Sign request incoming for key: %s", keydump)
	a.config.signlock.Lock()
	defer a.config.signlock.Unlock()

	t0 := time.Now()
	if a.config.easyyes {
		p("Do you want to accept [yes means 'yes', everything else means 'no']?")
	} else {
		p("Do you want to accept [%d means 'yes', everything else means 'no']?", id)
	}
	var yn string
	fmt.Scanln(&yn)
	t1 := time.Now()
	if t1.After(t0.Add(a.config.timeout)) {
		p("timed out")
		return nil, errors.New("approval timed out")
	}
	ynf := strings.TrimSpace(yn)
	if (a.config.easyyes && ynf != "yes") ||
		(!a.config.easyyes && ynf != strconv.FormatUint(id, 10)) {
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
	log.Println("request: Remove")
	return a.agent.Remove(key)
}

func (a *AgentYesNo) RemoveAll() error {
	log.Println("request: RemoveAll")
	return a.agent.RemoveAll()
}

func (a *AgentYesNo) Lock(passphrase []byte) error {
	log.Println("request: Lock")
	return a.agent.Lock(passphrase)
}

func (a *AgentYesNo) Unlock(passphrase []byte) error {
	log.Println("request: Unlock")
	return a.agent.Unlock(passphrase)
}

func (a *AgentYesNo) Signers() ([]ssh.Signer, error) {
	log.Println("request: Signers")
	return a.agent.Signers()
}

func getsockpath() string {
	sockdir, err := os.UserHomeDir()
	if err != nil {
		sockdir = os.TempDir()
		log.Print("warning: unable to get home directory, using temp directory:", sockdir)
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
		log.Fatal("identical agent and listening paths: ", one)
	}
}
