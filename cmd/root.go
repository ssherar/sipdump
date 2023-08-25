package cmd

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/ssherar/go-sipdump/pkg"
)

var config = pkg.Config{}

var rootCmd = &cobra.Command{
	Use:   "sipdump",
	Short: "sipdump is a SIP capture tool that breaks up SIP calls into individual pcap files",
	Long:  `sipdump is a SIP capture tool that breaks up SIP calls into individual pcap files`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := config.Validate(); err != nil {
			log.Println(err)
			os.Exit(1)
		}

		log.Println("Starting sipdump")
		log.Println("Capturing on device", config.Device, "with snaplen", config.Snaplen, "and promisc", config.Promisc)
		capture := pkg.NewCapture(&config)

		if err := capture.StartPcap(); err != nil {
			log.Println(err)
			os.Exit(1)
		}
	},
}

func init() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	rootCmd.PersistentFlags().StringVarP(&config.Device, "interface", "i", "", "Device to capture on")
	rootCmd.PersistentFlags().Int32VarP(&config.Snaplen, "snaplen", "s", 1600, "Snaplen")
	rootCmd.PersistentFlags().BoolVarP(&config.Promisc, "promisc", "p", true, "Promiscuous mode")
	rootCmd.PersistentFlags().StringVarP(&config.BasePath, "directory", "d", "/tmp", "Base directory to store pcap files")
	rootCmd.PersistentFlags().Uint32Var(&config.CallTableClearInterval, "calltable-clear-interval", 300, "How often to clear the calltable in seconds")
	rootCmd.PersistentFlags().Uint32Var(&config.CallTableTimeout, "calltable-timeout", 1900, "How long to keep a call in the calltable in seconds if there is no logged writes")
	rootCmd.PersistentFlags().StringVarP(&config.FilenameTemplateString, "filename-template", "f", "{{.DateFormatted}}_{{.TimeFormatted}}_{{.From.Number}}_{{.To.Number}}_{{.CallID}}.pcap", "Template for pcap filenames using golang Template strings. More info can be found in the README")

	rootCmd.MarkPersistentFlagRequired("interface")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
