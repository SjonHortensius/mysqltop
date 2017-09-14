package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/miekg/pcap"
	"os"
	"regexp"
)

var (
	listenInterface string
	qCount          = map[string]int{}
)

type ByCount []string

func (q ByCount) Len() int           { return len(qCount) }
func (q ByCount) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }
func (q ByCount) Less(i, j int) bool { return qCount[q[i]] < qCount[q[j]] }

func init() {
	flag.StringVar(&listenInterface, "interface", "eth0", "interface to listen on")

	flag.Parse()
}

// Listen on listenInterface, process queries and send to incomingQuery
func main() {
	c, err := pcap.OpenLive(listenInterface, 65535, true, 500)
	if err != nil {
		fmt.Fprintf(os.Stderr, "while opening %s: %s", listenInterface, err)
		os.Exit(1)
	}
	defer c.Close()

	if err := c.SetFilter("tcp dst port 3306"); err != nil {
		fmt.Fprintf(os.Stderr, "while setting filter: %s", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "ready\n")

	func() {
		var data []byte
		rNormalize := regexp.MustCompile("\\s+")

		for pkt, r := c.NextEx(); r >= 0; pkt, r = c.NextEx() {
			if r == 0 {
				// timeout, continue
				continue
			}

			data = packetGetPayload(pkt)

			// from https://github.com/elastic/beats/blob/master/packetbeat/protos/mysql/mysql.go#L203
			if len(data) < 5 {
				continue
			}

			hdr := data[0:5]
			length := uint32(hdr[0]) | uint32(hdr[1])<<8 | uint32(hdr[2])<<16
			seq := uint8(hdr[3])
			typ := uint8(hdr[4])

			if seq == 0 && typ == 3 && len(data) >= int(length)+4 {
				q := string(data[5 : 4+length])

				// normalize
				q = rNormalize.ReplaceAllString(q, " ")

				// remove whitespace from start
				if q[0] == 0x020 {
					q = q[1:]
				}

fmt.Printf("[%s] %s\n", pkt.Time.Format("15:04:05.000"), q)
			}
		}
	}()
}

func packetGetPayload(pkt *pcap.Packet) []byte {
	// Avoid pkt.Decode(), construct pkt.Payload ourselves
	// from https://github.com/miekg/pcap/blob/master/packet.go#L34
	data := pkt.Data[14:]

	if len(data) > 19 {
		switch int(binary.BigEndian.Uint16(pkt.Data[12:14])) {
		case 0x0800: // TYPE_IP
			// from decodeIp
			pEnd := int(binary.BigEndian.Uint16(data[2:4]))
			if pEnd > len(data) {
				pEnd = len(data)
			}

			pIhl := int(uint8(data[0])&0x0F) * 4
			if pIhl > pEnd {
				pIhl = pEnd
			}
			data = data[pIhl:pEnd]
		case 0x86DD: // TYPE_IP6
			data = data[40:]
		}

		// from decodeTcp
		pDataOffset := int(((data[12] & 0xF0) >> 4) * 4)
		if pDataOffset > len(data) {
			pDataOffset = len(data)
		}
		data = data[pDataOffset:]
	}

	return data
}
