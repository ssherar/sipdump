package pkg

import (
	"fmt"
	"os"
	"regexp"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	pcap "github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type Capture struct {
	Handle    *pcap.Handle
	CallTable *CallTable
	Config    *Config
}

type SIPMetadata struct {
	CallID        string
	From          *SIPContactInfoHeader
	To            *SIPContactInfoHeader
	DateFormatted string
	TimeFormatted string
	Datetime      time.Time
}

func NewSIPMetaData(sipLayer *layers.SIP, timestamp time.Time) *SIPMetadata {
	sip := &SIPMetadata{
		CallID:        sipLayer.GetCallID(),
		From:          ProcessSipContactHeader(sipLayer.GetTo()),
		To:            ProcessSipContactHeader(sipLayer.GetFrom()),
		DateFormatted: timestamp.Local().Format("20060102"),
		TimeFormatted: timestamp.Local().Format("150405"),
		Datetime:      timestamp,
	}
	return sip
}

type SIPContactInfoHeader struct {
	User   string
	Number string
	Host   string
	Tag    string
}

var SIPContactHeaderRegex = regexp.MustCompile("(?:\"(.+)\"\\s+)?<sips?:([^@\n]+)@(.+)(?:;(.+))?>(?:;tag=(.+))?")

func ProcessSipContactHeader(header string) *SIPContactInfoHeader {
	matches := SIPContactHeaderRegex.FindStringSubmatch(header)

	if len(matches) == 0 {
		return nil
	}

	return &SIPContactInfoHeader{
		User:   matches[1],
		Number: matches[2],
		Host:   matches[3],
		Tag:    matches[4],
	}

}

func NewCapture(Config *Config) *Capture {
	rt := &Capture{
		CallTable: NewCallTable(Config.CallTableClearInterval, Config.CallTableTimeout),
		Config:    Config,
	}
	return rt
}

func (c Capture) StartPcap() (err error) {
	if handle, err := pcap.OpenLive(c.Config.Device, c.Config.Snaplen, c.Config.Promisc, -1); err != nil {
		return err
	} else if err := handle.SetBPFFilter("udp and port 5060"); err != nil {
		return err
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range packetSource.Packets() {
			sip, ok := packet.Layer(layers.LayerTypeSIP).(*layers.SIP)
			if !ok {
				log.Println("Couldn't get SIP layer from packet")
				continue
			}
			log.Println(sip.GetCallID(), sip.GetFrom(), sip.GetTo(), packet.Metadata().Timestamp.Local())
			c.HandlePacket(packet)
		}
	}

	return nil
}

func (c Capture) HandlePacket(packet gopacket.Packet) {
	sip, ok := packet.Layer(layers.LayerTypeSIP).(*layers.SIP)
	if !ok {
		panic("Couldn't get SIP layer from packet")
	}

	// Have we seen this call before?
	record := c.CallTable.GetCall(sip.GetCallID())

	if record != nil && PCAPExists(record.Path) {
		f, err := OpenPcap(record.Path)
		if err != nil {
			panic(err)
		}
		if err := WritePacket(f, packet); err != nil {
			panic(err)
		}

		c.CallTable.UpdateLastWrite(sip.GetCallID())

		f.Close()
	} else {
		// PCAP doesn't exist, check if its an INVITE and if so create it
		if sip.Method != layers.SIPMethodInvite {
			return
		}

		// If the record exists but someone deleted the file, we need to recreate it
		var path string
		if record != nil {
			path = record.Path
		} else {
			sipMetadata := NewSIPMetaData(sip, packet.Metadata().Timestamp)
			fname, err := c.Config.PopulateFilenameTemplate(sipMetadata)
			if err != nil {
				log.Printf("Error populating filename template: %s", err)
				return
			}
			path = fmt.Sprintf("%s/%s", c.Config.BasePath, fname)
		}

		f, err := CreatePCAP(path)
		if err != nil {
			panic(err)
		}
		if err := WritePacket(f, packet); err != nil {
			panic(err)
		}

		c.CallTable.AddCall(sip.GetCallID(), path)
		f.Close()
	}
}

func PCAPExists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	} else {
		return false
	}
}

func CreatePCAP(path string) (*os.File, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	pcapw := pcapgo.NewWriter(f)
	if err := pcapw.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		return nil, err
	}

	return f, nil
}

func OpenPcap(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0700)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func WritePacket(f *os.File, packet gopacket.Packet) error {
	pcapw := pcapgo.NewWriter(f)
	if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
		return err
	}
	return nil
}
