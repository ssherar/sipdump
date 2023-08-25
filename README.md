# SIPDump

Based of the idea of [pcapsipdump](https://github.com/fairwaves/pcapsipdump) that has been abondoned in many different states for over 6 years, we've decided to rekindle the idea underneath and port it to golang, as pcapsipdump does a couple of things well

* Capturing RTP/RTPEvent/R38 packets inside the same pcap
* Capturing SIP packets and dumping them to a dedicated file
* Number and method grep for what packets to capture
* Running for days/weeks without falling over

While there is are other tools out there (such as [SipGrep](https://github.com/sipcapture/sipgrep) and [sngrep](https://github.com/irontec/sngrep)), they don't work out a clean and simple way of dumping SIP/RTP into individual pcaps for later analysis.


## Usage
```
$ sipdump --help
sipdump is a SIP capture tool that breaks up SIP calls into individual pcap files

Usage:
  sipdump [flags]

Flags:
      --calltable-clear-interval uint32   How often to clear the calltable in seconds (default 300)
      --calltable-timeout uint32          How long to keep a call in the calltable in seconds if there is no logged writes (default 1900)
  -d, --directory string                  Base directory to store pcap files (default "/tmp")
  -f, --filename-template string          Template for pcap filenames using golang Template strings. More info can be found in the README (default "{{.DateFormatted}}_{{.TimeFormatted}}_{{.From.Number}}_{{.To.Number}}_{{.CallID}}.pcap")
  -h, --help                              help for sipdump
  -i, --interface string                  Device to capture on
  -n, --number string                     Number to be searched for in the from/to (regex friendly)
  -p, --promisc                           Promiscuous mode (default true)
  -s, --snaplen int32                     Snaplen (default 1600)
```

## Filename Template Values
| Value | Description |
| --- | --- |
| `.DateFormatted` | Date formatted as YYYYMMDD |
| `.TimeFormatted` | Time formatted as HHMMSS |
| `.From.Number` | Number of the caller |
| `.From.User` | User of the caller |
| `.From.Host` | Host of the caller |
| `.From.Tag` | Tag of the caller |
| `.To.Number` | Number of the callee |
| `.To.Host` | Host of the callee |
| `.To.Tag` | Tag of the callee |
| `.CallID` | CallID of the call |
| `.Datetime` | The direct `time.Time` object of the start of the call |

## Todo list
- [ ] Implement logrus to track sip CallIDs properly
- [X] Regex number matching both on to and froms
- [ ] Capture RTP streams and save them to the pcap file
- [ ] Capture RTCP streams and sav ethem to the pcap file
- [ ] Dump to JSON (or have some JSON processing ability?)
- [ ] Make it ERSPAN friendly?
- [ ] Implement EEP protocol
- [X] Implement github actions to build and release binaries

## Author
* Sam Sherar <sbsherar@gmail.com>

## License
TBC
