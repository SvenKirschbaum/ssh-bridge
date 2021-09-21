package consumer

import (
	"github.com/fallobst22/ssh-bridge/consumer/pageant"
	"github.com/fallobst22/ssh-bridge/consumer/ssh-agent"
	"github.com/fallobst22/ssh-bridge/internal"
)

var Consumer = [...]internal.Consumer{
	ssh_agent.Serve,
	pageant.Serve,
}
