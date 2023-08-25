package pkg

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"text/template"

	log "github.com/sirupsen/logrus"
)

type Config struct {
	Device                 string
	Snaplen                int32
	Promisc                bool
	BasePath               string
	CallTableClearInterval uint32
	CallTableTimeout       uint32
	FilenameTemplateString string
	FilenameTemplate       *template.Template
	NumberSearch           string
	NumberRegex            *regexp.Regexp
}

func (c *Config) Validate() error {
	var err error
	if err = c.validatedevice(); err != nil {
		return err
	}

	if err = c.validatebasepath(); err != nil {
		return err
	}

	if err = c.validatesnaplen(); err != nil {
		return err
	}

	if err = c.validatefilenametemplate(); err != nil {
		return err
	}

	if err = c.validatenumberregex(); err != nil {

	}

	return nil
}

func (c *Config) validatebasepath() error {
	var err error

	if c.BasePath == "" {
		return errors.New("BasePath is required")
	}

	if c.BasePath, err = filepath.Abs(c.BasePath); err != nil {
		return err
	}

	log.Println("BasePath is", c.BasePath)

	err = os.MkdirAll(c.BasePath, os.ModePerm)
	if err != nil {
		return err
	}

	return nil
}

func (c *Config) validatesnaplen() error {
	if c.Snaplen == 0 {
		c.Snaplen = 1600
	}

	return nil
}

func (c *Config) validatedevice() error {
	if c.Device == "" {
		return errors.New("Device is required")
	}

	return nil
}

func (c *Config) validatefilenametemplate() error {
	c.FilenameTemplateString = "{{.DateFormatted}}_{{.TimeFormatted}}_{{.From.Number}}_{{.To.Number}}_{{.CallID}}.pcap"
	c.FilenameTemplate = template.Must(template.New("filename").Parse(c.FilenameTemplateString))

	return nil
}

func (c *Config) PopulateFilenameTemplate(sip *SIPMetadata) (string, error) {
	var err error
	var filename bytes.Buffer

	if err = c.FilenameTemplate.Execute(&filename, sip); err != nil {
		return "", err
	}

	return filename.String(), nil
}

func (c *Config) validatenumberregex() error {
	var err error

	if len(c.NumberSearch) == 0 || c.NumberSearch == "" {
		return nil
	}

	if c.NumberRegex, err = regexp.Compile(c.NumberSearch); err != nil {
		return err
	}
	log.Println("Regex compiled, matching for to/from with the following regex", c.NumberSearch)

	return nil
}
