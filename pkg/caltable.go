package pkg

import (
	"time"

	log "github.com/sirupsen/logrus"
)

type CallTableRecord struct {
	Path      string
	LastWrite int64
}

type CallTable struct {
	Ticker  *time.Ticker
	Stopper chan struct{}
	Records map[string]*CallTableRecord
}

func NewCallTable(cleaninterval uint32, timeout uint32) *CallTable {
	ct := &CallTable{
		Ticker:  time.NewTicker(time.Second * time.Duration(cleaninterval)),
		Stopper: make(chan struct{}),
		Records: make(map[string]*CallTableRecord, 0),
	}

	go func() {
		for {
			select {
			case <-ct.Ticker.C:
				log.Println("Running cleanup")
				for callid, record := range ct.Records {
					if time.Now().Unix()-record.LastWrite > int64(timeout) {
						log.Println("Deleting callid", callid)
						delete(ct.Records, callid)
					}
				}
			case <-ct.Stopper:
				ct.Ticker.Stop()
				return
			}
		}
	}()

	return ct
}

func (ct *CallTable) AddCall(callid string, path string) {
	ct.Records[callid] = &CallTableRecord{Path: path, LastWrite: time.Now().Unix()}
}

func (ct *CallTable) DeleteCall(callid string) {
	delete(ct.Records, callid)
}

func (ct *CallTable) GetCall(callid string) *CallTableRecord {
	return ct.Records[callid]
}

func (ct *CallTable) UpdateLastWrite(callid string) {
	if record, ok := ct.Records[callid]; !ok {
		log.Println("Callid", callid, "not found in call table")
	} else {
		record.LastWrite = time.Now().Unix()
	}
}

func (ct *CallTable) StopCleanup() {
	ct.Stopper <- struct{}{}
}
