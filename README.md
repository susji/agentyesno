# agentyesno

# Why?

Didn't you always want to use SSH agent forwarding when connecting to vaguely
trusted computers? Me neither. Sometimes one may have to and in that case
`agentyesno` might be useful.

`agentyesno` is a tiny interactive terminal program which acts an intercepting
proxy for SSH agent protocol's Sign Requests. It is meant to stand between
remote agent requests and your local SSH agent. It *may* work with local agent
requests, but local clients can easily circumvent the agent.

# Disclaimer

Use `agentyesno` at your own risk. It is untested and experimental. This kind of
a tool may offer you some protection in certain scenarios, but there are many
scenarios where it will not help you. There is a reason why for example OpenSSH
does *not* enable forwarding of agent connections by default. If you don't know
what you're doing, don't use agent forwarding. Before you use a tool like this,
make sure that ProxyJump (`-J`) and locking the agent (`-x`) aren't better
suited for your needs.

# How does it work?

`agentyesno` uses Go's SSH library for handling client and agent communications.
The program pauses on Sign Requests and asks the user's opinion before passing
the request to the actual agent. The user has to explicitly accept this sign
request by typing something. If the user does not give permission or responding
takes too long, then the Sign Request is dropped and not forwarded to the actual
agent. All other supported agent operations are passed transparently and
non-interactively.

```
.---------------.  domain socket  .---------------.  domain socket  .---------------.
|   ssh agent   |-----------------|   agentyesno  |-----------------|  agent client |
'---------------'                 '---------------'                 '---------------'

                             <------------------------- Sign Request
               Sign Response ------------------------->
```


To make usage clearer, `agentyesno` will only serve one Sign Request at a time.
Other clients will have to wait for their turn.

# How to use?

`agentyesno` listens on a domain socket as locally running SSH agents typically
do and you instruct your SSH client to use `agentyesno` as the agent. With
OpenSSH, this would mean setting your `SSH_AUTH_SOCK` to point at `agentyesno`
domain socket on the filesystem, perhaps like this:

    $ export SSH_AUTH_SOCK="$HOME/.agentyesno.socket"

If you don't wish to make the change persist in the shell session, invoke
something like this:

    $ SSH_AUTH_SOCK="$HOME/.agentyesno.socket" ssh user@host

Somewhere on the background and easily reachable, perhaps in a different
terminal window or a tmux pane, you would have `agentyesno` ready and waiting
for agent requests:

    $ agentyesno

`agentyesno` will default to finding your real agent via `$SSH_AUTH_SOCK`. You
can override the listening socket and real agent paths with `-listen` and
`-agent`, respectively. For more instructions, see the short code and

    $ agentyesno -h
