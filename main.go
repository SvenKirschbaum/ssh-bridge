package main

import (
	"github.com/fallobst22/ssh-bridge/consumer"
	"github.com/fallobst22/ssh-bridge/internal"
	"github.com/fallobst22/ssh-bridge/supplier"
	"log"
)

func main() {
	err := internal.LoadConfig()
	if err != nil {
		panic(err)
	}

	for _, supplierImpl := range supplier.Suppliers {
		err := supplierImpl.Init()
		if err != nil {
			panic(err)
		}
	}

	var sshAgent *internal.CustomAgent
	sshAgent = internal.NewAgent(func() error {
		//Supplier
		for _, supplierImpl := range supplier.Suppliers {
			keys, err := supplierImpl.Keys()
			if err != nil {
				return err
			}
			for _, key := range keys {
				err := sshAgent.AddInternal(key.Key, key.Comment, key.Priority, key.Password)
				if err != nil {
					log.Println("Error adding key", err)
				}
			}
		}
		return nil
	})

	//Consumer
	for _, consumerImpl := range consumer.Consumer {
		consumerImpl(sshAgent)
	}

	//Block
	select {}
}
