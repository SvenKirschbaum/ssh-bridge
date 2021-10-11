package onepassword

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/fallobst22/ssh-bridge/internal"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const CliFileName = "op.exe"

type Supplier struct {
	cliFile    string
	sessionKey string
}

type Tags []string

type opItem struct {
	UUID         string    `json:"uuid"`
	TemplateUUID string    `json:"templateUuid"`
	Trashed      string    `json:"trashed"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	ChangerUUID  string    `json:"changerUuid"`
	ItemVersion  int       `json:"itemVersion"`
	VaultUUID    string    `json:"vaultUuid"`
	Details      struct {
		DocumentAttributes struct {
			DocumentID    string `json:"documentId"`
			EncryptedSize int    `json:"encryptedSize"`
			EncryptionKey struct {
				Alg    string   `json:"alg"`
				Kid    string   `json:"kid"`
				K      string   `json:"k"`
				KeyOps []string `json:"key_ops"`
				Ext    bool     `json:"ext"`
				Kty    string   `json:"kty"`
			} `json:"encryptionKey"`
			FileName      string `json:"fileName"`
			IntegrityHash string `json:"integrityHash"`
			Nonce         string `json:"nonce"`
			SigningKey    struct {
				Alg    string   `json:"alg"`
				Kid    string   `json:"kid"`
				K      string   `json:"k"`
				KeyOps []string `json:"key_ops"`
				Ext    bool     `json:"ext"`
				Kty    string   `json:"kty"`
			} `json:"signingKey"`
			UnencryptedSize int `json:"unencryptedSize"`
		} `json:"documentAttributes"`
		NotesPlain      string        `json:"notesPlain"`
		PasswordHistory []interface{} `json:"passwordHistory"`
		Sections        []struct {
			Name   string `json:"name"`
			Title  string `json:"title"`
			Fields []struct {
				K string `json:"k"`
				N string `json:"n"`
				T string `json:"t"`
				V string `json:"v"`
			} `json:"fields,omitempty"`
		} `json:"sections"`
	} `json:"details"`
	Overview struct {
		Ainfo string   `json:"ainfo"`
		Tags  []string `json:"tags"`
		Title string   `json:"title"`
	} `json:"overview"`
}

type opDocument struct {
	UUID         string    `json:"uuid"`
	TemplateUUID string    `json:"templateUuid"`
	Trashed      string    `json:"trashed"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	ChangerUUID  string    `json:"changerUuid"`
	ItemVersion  int       `json:"itemVersion"`
	VaultUUID    string    `json:"vaultUuid"`
	Overview     struct {
		Ainfo string `json:"ainfo"`
		Tags  Tags   `json:"tags"`
		Title string `json:"title"`
	} `json:"overview"`
}

func (t *Tags) contains(search string) bool {
	search = strings.ToLower(search)

	for _, v := range *t {
		if strings.ToLower(v) == search {
			return true
		}
	}

	return false
}

func (t *Supplier) Init() error {

	t.cliFile = internal.CacheDirectory + "/" + CliFileName

	if _, err := os.Stat(t.cliFile); os.IsNotExist(err) {
		//Download cli file
		//TODO:
		println(t.cliFile)
		panic("not implemented")
	}

	return nil
}

func (t *Supplier) Login() error {
	//TODO: handle initial login
	//TODO: handle 2fa?
	for {
		prompt := internal.NewPrompt(internal.PromptConfig{
			HideInput: true,
			InputHint: "1Password Password",
		})

		select {
		case password := <-prompt.Output:
			if password != "" {
				output, err := t.callOp(password, "signin", "-r")

				if err == nil {
					t.sessionKey = strings.TrimRight(output, "\r\n")
					return nil
				} else {
					println(err.Error())
				}
			} else {
				//window has been closed
				return errors.New("User aborted")
			}
		}
	}

}

func (k *Supplier) Keys() ([]internal.PlainKey, error) {
	err := k.Login()
	if err != nil {
		return nil, err
	}

	documentJson, err := k.callOp("", "list", "documents")
	if err != nil {
		return nil, err
	}

	var documents []opDocument

	err = json.Unmarshal([]byte(documentJson), &documents)
	if err != nil {
		return nil, err
	}

	ch := make(chan internal.PlainKey, len(documents))
	var wg sync.WaitGroup

	for _, document := range documents {
		if document.Overview.Tags.contains("ssh-key") && document.Trashed == "N" {
			wg.Add(1)
			go func(document opDocument) {
				defer wg.Done()
				keystring, err := k.callOp("", "get", "document", document.UUID)
				if err != nil {
					panic(err)
				}

				itemJson, err := k.callOp("", "get", "item", document.UUID)
				if err != nil {
					panic(err)
				}

				var item opItem
				err = json.Unmarshal([]byte(itemJson), &item)
				if err != nil {
					panic(err)
				}

				priority := 0
				password := ""

				for _, section := range item.Details.Sections {
					for _, field := range section.Fields {
						if field.T == "Priority" {
							atoi, err := strconv.Atoi(field.V)
							if err == nil {
								priority = atoi
							}
						}
						if field.T == "password" {
							password = field.V
						}
					}
				}

				ch <- internal.PlainKey{
					Key:      keystring,
					Comment:  fmt.Sprintf("[OnePassword] %v", document.Overview.Title),
					Priority: priority,
					Password: password,
				}
			}(document)
		}
	}
	wg.Wait()
	close(ch)

	var keys []internal.PlainKey
	for key := range ch {
		keys = append(keys, key)
	}

	return keys, nil
}

func (k *Supplier) callOp(stdin string, arg ...string) (string, error) {
	arg = append(arg, "--config", internal.CacheDirectory, "--session", k.sessionKey)

	command := exec.Command(k.cliFile, arg...)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	var outb, errb bytes.Buffer
	command.Stdout = &outb
	command.Stderr = &errb
	command.Stdin = bytes.NewBufferString(stdin)

	err := command.Run()

	//println("STDOUT:", outb.String(),"END");
	//println("STDERR:", errb.String(),"END")
	//if err != nil {
	//	println("ERROR: ", err.Error())
	//}

	return outb.String(), err
}
