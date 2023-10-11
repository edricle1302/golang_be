package config

import (
	"github.com/spf13/viper"
)

func GetConfig(path string) *viper.Viper {
	viper.SetConfigFile(path)
	err := viper.ReadInConfig()
	if err != nil {
		panic(err)
	}
	return viper.GetViper()
}
