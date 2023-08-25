package pkg

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type CallTableRecord struct {
	Path      string
	LastWrite int64
}

type CallTable struct {
	mu      sync.RWMutex
	Ticker  *time.Ticker
	Stopper chan struct{}
	Records map[string]*CallTableRecord
}

func NewCallTable(cleaninterval uint32, timeout uint32) *CallTable {
	ct := &CallTable{
		mu:      sync.RWMutex{},
		Ticker:  time.NewTicker(time.Second * time.Duration(cleaninterval)),
		Stopper: make(chan struct{}),
		Records: make(map[string]*CallTableRecord, 0),
	}

	go func() {
		for {
			select {
			case <-ct.Ticker.C:
				log.Println("Running cleanup")
				ct.mu.Lock()
				for callid, record := range ct.Records {
					if time.Now().Unix()-record.LastWrite > int64(timeout) {
						log.Println("Deleting callid", callid)
						delete(ct.Records, callid)
					}
				}
				ct.mu.Unlock()
			case <-ct.Stopper:
				ct.Ticker.Stop()
				return
			}
		}
	}()

	return ct
}

func (ct *CallTable) AddCall(callid string, path string) {
	ct.mu.Lock()
	ct.Records[callid] = &CallTableRecord{Path: path, LastWrite: time.Now().Unix()}
	ct.mu.Unlock()
}

func (ct *CallTable) DeleteCall(callid string) {
	ct.mu.Lock()
	delete(ct.Records, callid)
	ct.mu.Unlock()
}

func (ct *CallTable) GetCall(callid string) *CallTableRecord {
	ct.mu.RLock()
	records := ct.Records[callid]
	ct.mu.RUnlock()
	return records
}

func (ct *CallTable) UpdateLastWrite(callid string) {
	ct.mu.Lock()
	if record, ok := ct.Records[callid]; !ok {
		log.Println("Callid", callid, "not found in call table")
	} else {
		record.LastWrite = time.Now().Unix()
	}
	ct.mu.Unlock()
}

func (ct *CallTable) StopCleanup() {
	ct.Stopper <- struct{}{}
}
