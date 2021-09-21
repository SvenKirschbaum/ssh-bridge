package ssh_agent

import (
	"github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh/agent"
	"io"
	"log"
)

const sshPipe = `\\.\pipe\openssh-ssh-agent`

func Serve(sshAgent agent.Agent) {
	go func() {
		pipe, err := winio.ListenPipe(sshPipe, &winio.PipeConfig{})
		if err != nil {
			return
		}

		for true {
			accept, err := pipe.Accept()
			if err != nil {
				continue
			}

			go func() {
				err := agent.ServeAgent(sshAgent, accept)
				if err != nil && err != io.EOF {
					log.Println("Error during communication with namedpipe client", err)
				}
			}()
		}
	}()
}
