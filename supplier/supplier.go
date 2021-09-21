package supplier

import (
	"github.com/fallobst22/ssh-bridge/internal"
	onepassword "github.com/fallobst22/ssh-bridge/supplier/1password"
)

var Suppliers = [...]internal.Supplier{
	//&random.Supplier{},
	//&static.Supplier{},
	&onepassword.Supplier{},
}
