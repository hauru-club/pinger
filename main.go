package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/hauru-club/ping/pkg/models"
)

var (
	snaplen int32         = 65535
	promisc bool          = false
	timeout time.Duration = -1 * time.Second
)

var (
	device  string
	address string
	key     string
)

type sender struct {
	address string
	key     string
}

func (s *sender) send(apiKey string, packet models.Packet) (*http.Response, error) {
	client := &http.Client{}

	data := new(bytes.Buffer)
	if err := json.NewEncoder(data).Encode(packet); err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, s.address, data)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Auth-Publish-Key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func main() {
	flag.StringVar(&device,
		"device",
		"eth0",
		"network device to listen from",
	)
	flag.StringVar(&device,
		"d",
		"eth0",
		"network device to listen from (shorthand)",
	)
	flag.StringVar(&address,
		"address",
		"https://ping.hauru.club",
		"http(s) address of ping server",
	)
	flag.StringVar(&address,
		"a",
		"https://ping.hauru.club",
		"http(s) address of ping server (shorthand)",
	)
	flag.StringVar(&key,
		"key",
		"somesecretkey",
		"api key",
	)
	flag.StringVar(&key,
		"k",
		"somesecretkey",
		"api key (shorthand)",
	)
	flag.Parse()

	s := &sender{
		address: address + "/publish",
		key:     key,
	}

	handle, err := pcap.OpenLive(device, snaplen, promisc, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter("icmp")
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		toSend := models.Packet{}

		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			ipv4Parsed, ok := ipv4Layer.(*layers.IPv4)
			if ok {
				toSend.Dst = ipv4Parsed.DstIP.String()
				toSend.Src = ipv4Parsed.SrcIP.String()
			}
		}
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmpParsed, ok := icmpLayer.(*layers.ICMPv4)
			if ok {
				toSend.Seq = int(icmpParsed.Seq)
				toSend.Len = len(icmpParsed.Contents) + len(icmpParsed.Payload)
			}
		}

		resp, err := s.send(key, toSend)
		if err != nil {
			log.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			fmt.Println(resp.Status)
			io.Copy(os.Stderr, resp.Body)
		}
		resp.Body.Close()
	}

}
