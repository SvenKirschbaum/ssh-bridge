package internal

import (
	"os"
)

const (
	CacheSubfolder = "ssh-bridge"
)

var (
	CacheDirectory string
)

func LoadConfig() error {
	cachePath, err := os.UserCacheDir()
	if err != nil {
		return err
	}

	cachePath = cachePath + "/" + CacheSubfolder

	err = os.MkdirAll(cachePath, 0755)
	if err != nil {
		return err
	}

	CacheDirectory = cachePath

	return nil
}
