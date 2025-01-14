package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"net"
	"strconv"
	"strings"
	"time"
)

// HEP chuncks
const (
	Version   = 1  // Chunk 0x0001 IP protocol family (0x02=IPv4, 0x0a=IPv6)
	Protocol  = 2  // Chunk 0x0002 IP protocol ID (0x06=TCP, 0x11=UDP)
	IP4SrcIP  = 3  // Chunk 0x0003 IPv4 source address
	IP4DstIP  = 4  // Chunk 0x0004 IPv4 destination address
	IP6SrcIP  = 5  // Chunk 0x0005 IPv6 source address
	IP6DstIP  = 6  // Chunk 0x0006 IPv6 destination address
	SrcPort   = 7  // Chunk 0x0007 Protocol source port
	DstPort   = 8  // Chunk 0x0008 Protocol destination port
	Tsec      = 9  // Chunk 0x0009 Unix timestamp, seconds
	Tmsec     = 10 // Chunk 0x000a Unix timestamp, microseconds
	ProtoType = 11 // Chunk 0x000b Protocol type (DNS, LOG, RTCP, SIP)
	NodeID    = 12 // Chunk 0x000c Capture client ID
	NodePW    = 14 // Chunk 0x000e Authentication key (plain text / TLS connection)
	Payload   = 15 // Chunk 0x000f Captured packet payload
	CID       = 17 // Chunk 0x0011 Correlation ID
	Vlan      = 18 // Chunk 0x0012 VLAN
	NodeName  = 19 // Chunk 0x0013 NodeName
)

type Packet struct {
	Version   byte
	Protocol  byte
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Tsec      uint32
	Tmsec     uint32
	ProtoType byte
	Payload   []byte
	CID       []byte
	Vlan      uint16
}

type HepMsg struct {
	Version   byte
	Protocol  byte
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Tsec      uint32
	Tmsec     uint32
	ProtoType byte
	NodeID    uint32
	NodePW    string
	Payload   []byte
	CID       []byte
	Vlan      uint16
	NodeName  string
}

// HEP represents HEP packet
type HEP struct {
	Version     uint32 `protobuf:"varint,1,req,name=Version" json:"Version"`
	Protocol    uint32 `protobuf:"varint,2,req,name=Protocol" json:"Protocol"`
	SrcIP       string
	DstIP       string
	SrcPort     uint32 `protobuf:"varint,5,req,name=SrcPort" json:"SrcPort"`
	DstPort     uint32 `protobuf:"varint,6,req,name=DstPort" json:"DstPort"`
	Tsec        uint32 `protobuf:"varint,7,req,name=Tsec" json:"Tsec"`
	Tmsec       uint32 `protobuf:"varint,8,req,name=Tmsec" json:"Tmsec"`
	ProtoType   uint32 `protobuf:"varint,9,req,name=ProtoType" json:"ProtoType"`
	NodeID      uint32 `protobuf:"varint,10,req,name=NodeID" json:"NodeID"`
	NodePW      string `protobuf:"bytes,11,req,name=NodePW" json:"NodePW"`
	Payload     string `protobuf:"bytes,12,req,name=Payload" json:"Payload"`
	CID         string `protobuf:"bytes,13,req,name=CID" json:"CID"`
	Vlan        uint32 `protobuf:"varint,14,req,name=Vlan" json:"Vlan"`
	ProtoString string
	Timestamp   time.Time
	NodeName    string
	TargetName  string
	SID         string
}

// DecodeHEP returns a parsed HEP message
func DecodeHEP(packet []byte) (*HEP, error) {
	hep := &HEP{}
	err := hep.parse(packet)
	if err != nil {
		return nil, err
	}
	//	log.Printf("HEP decoded ", hep)
	return hep, nil
}

func (h *HEP) parse(packet []byte) error {
	var err error
	if bytes.HasPrefix(packet, []byte{0x48, 0x45, 0x50, 0x33}) {
		err = h.parseHEP(packet)
		if err != nil {
			log.Println("Warning>", err)
			return err
		}
	} else {
		//err = h.Unmarshal(packet)
		//if err != nil {
		//		log.Println("malformed packet with length %d which is neither hep nor protobuf encapsulated", len(packet))
		return err
		//	}
	}

	h.Timestamp = time.Unix(int64(h.Tsec), int64(h.Tmsec*1000))
	if h.Tsec == 0 && h.Tmsec == 0 {
		log.Println("Debug> got null timestamp from nodeID: ", h.NodeID)
		h.Timestamp = time.Now()
	}

	if h.NodeName == "" {
		h.NodeName = strconv.FormatUint(uint64(h.NodeID), 10)
	}

	//log.Println("Debug> %+v\n\n", h)
	return nil
}

//--------------------------

func (h *HEP) parseHEP(packet []byte) error {
	length := binary.BigEndian.Uint16(packet[4:6])
	//	if int(length) != len(packet) {
	//		return fmt.Errorf("HEP packet length is %d but should be %d", len(packet), length)
	//	}
	currentByte := uint16(6)

	for currentByte < length {
		hepChunk := packet[currentByte:]
		if len(hepChunk) < 6 {
			return fmt.Errorf("HEP chunk must be >= 6 byte long but is %d", len(hepChunk))
		}
		//chunkVendorId := binary.BigEndian.Uint16(hepChunk[:2])
		chunkType := binary.BigEndian.Uint16(hepChunk[2:4])
		chunkLength := binary.BigEndian.Uint16(hepChunk[4:6])
		if len(hepChunk) < int(chunkLength) || int(chunkLength) < 6 {
			return fmt.Errorf("HEP chunk with %d byte < chunkLength %d or chunkLength < 6", len(hepChunk), chunkLength)
		}
		chunkBody := hepChunk[6:chunkLength]

		switch chunkType {
		case Version, Protocol, ProtoType:
			if len(chunkBody) != 1 {
				return fmt.Errorf("HEP chunkType %d should be 1 byte long but is %d", chunkType, len(chunkBody))
			}
		case SrcPort, DstPort, Vlan:
			if len(chunkBody) != 2 {
				return fmt.Errorf("HEP chunkType %d should be 2 byte long but is %d", chunkType, len(chunkBody))
			}
		case IP4SrcIP, IP4DstIP, Tsec, Tmsec, NodeID:
			if len(chunkBody) != 4 {
				return fmt.Errorf("HEP chunkType %d should be 4 byte long but is %d", chunkType, len(chunkBody))
			}
		case IP6SrcIP, IP6DstIP:
			if len(chunkBody) != 16 {
				return fmt.Errorf("HEP chunkType %d should be 16 byte long but is %d", chunkType, len(chunkBody))
			}
		}

		switch chunkType {
		case Version:
			h.Version = uint32(chunkBody[0])
		case Protocol:
			h.Protocol = uint32(chunkBody[0])
		case IP4SrcIP:
			h.SrcIP = net.IP(chunkBody).To4().String()
		case IP4DstIP:
			h.DstIP = net.IP(chunkBody).To4().String()
		case IP6SrcIP:
			h.SrcIP = net.IP(chunkBody).To16().String()
		case IP6DstIP:
			h.DstIP = net.IP(chunkBody).To16().String()
		case SrcPort:
			h.SrcPort = uint32(binary.BigEndian.Uint16(chunkBody))
		case DstPort:
			h.DstPort = uint32(binary.BigEndian.Uint16(chunkBody))
		case Tsec:
			h.Tsec = binary.BigEndian.Uint32(chunkBody)
		case Tmsec:
			h.Tmsec = binary.BigEndian.Uint32(chunkBody)
		case ProtoType:
			h.ProtoType = uint32(chunkBody[0])
			switch h.ProtoType {
			case 1:
				h.ProtoString = "sip"
			case 5:
				h.ProtoString = "rtcp"
			case 34:
				h.ProtoString = "rtpagent"
			case 35:
				h.ProtoString = "rtcpxr"
			case 38:
				h.ProtoString = "horaclifix"
			case 53:
				h.ProtoString = "dns"
			case 100:
				h.ProtoString = "log"
			default:
				h.ProtoString = strconv.Itoa(int(h.ProtoType))
			}
		case NodeID:
			h.NodeID = binary.BigEndian.Uint32(chunkBody)
		case NodePW:
			h.NodePW = string(chunkBody)
		case Payload:
			h.Payload = string(chunkBody)
		case CID:
			h.CID = string(chunkBody)
		case Vlan:
			h.Vlan = uint32(binary.BigEndian.Uint16(chunkBody))
		case NodeName:
			h.NodeName = string(chunkBody)
		default:
		}
		currentByte += chunkLength
	}
	return nil
}

func (h *HepMsg) Marshal() (dAtA []byte, err error) {
	size := h.Size()
	dAtA = make([]byte, size)
	n, err := h.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (h *HepMsg) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i

	i += copy(dAtA[i:], []byte{0x48, 0x45, 0x50, 0x33})
	binary.BigEndian.PutUint16(dAtA[i:], uint16(len(dAtA)))
	i += 2

	i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x07})
	dAtA[i] = h.Version
	i++

	i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x07})
	dAtA[i] = h.Protocol
	i++

	if h.Version == 0x02 {
		if h.SrcIP != nil {
			i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x03})
			binary.BigEndian.PutUint16(dAtA[i:], 6+uint16(len(h.SrcIP)))
			i += 2
			i += copy(dAtA[i:], h.SrcIP)
		}

		if h.DstIP != nil {
			i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x04})
			binary.BigEndian.PutUint16(dAtA[i:], 6+uint16(len(h.DstIP)))
			i += 2
			i += copy(dAtA[i:], h.DstIP)
		}
	} else {
		if h.SrcIP != nil {
			i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x05})
			binary.BigEndian.PutUint16(dAtA[i:], 6+uint16(len(h.SrcIP)))
			i += 2
			i += copy(dAtA[i:], h.SrcIP)
		}

		if h.DstIP != nil {
			i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x06})
			binary.BigEndian.PutUint16(dAtA[i:], 6+uint16(len(h.DstIP)))
			i += 2
			i += copy(dAtA[i:], h.DstIP)
		}
	}

	i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x07, 0x00, 0x08})
	binary.BigEndian.PutUint16(dAtA[i:], h.SrcPort)
	i += 2

	i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x08, 0x00, 0x08})
	binary.BigEndian.PutUint16(dAtA[i:], h.DstPort)
	i += 2

	i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x09, 0x00, 0x0a})
	binary.BigEndian.PutUint32(dAtA[i:], h.Tsec)
	i += 4

	i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x0a, 0x00, 0x0a})
	binary.BigEndian.PutUint32(dAtA[i:], h.Tmsec)
	i += 4

	i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x0b, 0x00, 0x07})
	dAtA[i] = h.ProtoType
	i++

	i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a})
	binary.BigEndian.PutUint32(dAtA[i:], h.NodeID)
	i += 4

	if h.NodePW != "" {
		i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x0e})
		binary.BigEndian.PutUint16(dAtA[i:], 6+uint16(len(h.NodePW)))
		i += 2
		i += copy(dAtA[i:], h.NodePW)
	}

	if h.Payload != nil {
		i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x0f})
		binary.BigEndian.PutUint16(dAtA[i:], 6+uint16(len(h.Payload)))
		i += 2
		i += copy(dAtA[i:], h.Payload)
	}

	if h.CID != nil {
		i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x11})
		binary.BigEndian.PutUint16(dAtA[i:], 6+uint16(len(h.CID)))
		i += 2
		i += copy(dAtA[i:], h.CID)
	}

	i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x12, 0x00, 0x08})
	binary.BigEndian.PutUint16(dAtA[i:], h.Vlan)
	i += 2

	if h.NodeName != "" {
		i += copy(dAtA[i:], []byte{0x00, 0x00, 0x00, 0x13})
		binary.BigEndian.PutUint16(dAtA[i:], 6+uint16(len(h.NodeName)))
		i += 2
		i += copy(dAtA[i:], h.NodeName)
	}

	return i, nil
}

func (h *HepMsg) Size() (n int) {
	n += 4 + 2     // len("HEP3") + 2
	n += 4 + 2 + 1 // len(vendor) + len(chunk) + len(Version)
	n += 4 + 2 + 1 // len(vendor) + len(chunk) + len(Protocol)
	if h.SrcIP != nil {
		n += 4 + 2 + len(h.SrcIP) // len(vendor) + len(chunk) + len(SrcIP)
	}
	if h.DstIP != nil {
		n += 4 + 2 + len(h.DstIP) // len(vendor) + len(chunk) + len(DstIP)
	}
	n += 4 + 2 + 2 // len(vendor) + len(chunk) + len(SrcPort)
	n += 4 + 2 + 2 // len(vendor) + len(chunk) + len(DstPort)
	n += 4 + 2 + 4 // len(vendor) + len(chunk) + len(Tsec)
	n += 4 + 2 + 4 // len(vendor) + len(chunk) + len(Tmsec)
	n += 4 + 2 + 1 // len(vendor) + len(chunk) + len(ProtoType)
	n += 4 + 2 + 4 // len(vendor) + len(chunk) + len(NodeID)
	if h.NodePW != "" {
		n += 4 + 2 + len(h.NodePW) // len(vendor) + len(chunk) + len(NodePW)
	}
	if h.Payload != nil {
		n += 4 + 2 + len(h.Payload) // len(vendor) + len(chunk) + len(Payload)
	}
	if h.CID != nil {
		n += 4 + 2 + len(h.CID) // len(vendor) + len(chunk) + len(CID)
	}
	n += 4 + 2 + 2 // len(vendor) + len(chunk) + len(Vlan)
	if h.NodeName != "" {
		n += 4 + 2 + len(h.NodeName) // len(vendor) + len(chunk) + len(NodeName)
	}
	return n
}

// MakeHEPPing creates the HEP Packet which
// will be send to wire
func MakeHEPPing() (hepMsg []byte, err error) {
	hep := &HepMsg{
		Version:   0x02,
		Protocol:  0x01,
		SrcIP:     net.ParseIP("192.168.0.1"),
		DstIP:     net.ParseIP("192.168.0.2"),
		SrcPort:   5060,
		DstPort:   5060,
		Tsec:      uint32(time.Now().Second()),
		Tmsec:     uint32(0),
		ProtoType: 0x01,
		NodeID:    uint32(999),
		NodePW:    *HepNodePW,
		Payload:   []byte("HEP PING"),
	}

	hepMsg, err = hep.Marshal()

	return hepMsg, err
}

func Human2FileSize(size string) (int64, error) {

	suffixes := [5]string{"B", "KB", "MB", "GB", "TB"} // Intialized with values
	var bytesSize int64

	for i, suffix := range suffixes {

		if i == 0 {
			continue
		}

		if strings.HasSuffix(size, suffix) {
			dataBytes := strings.TrimSuffix(size, suffix)
			baseVar, err := strconv.Atoi(dataBytes)
			if err != nil {
				return 0, err
			} else {
				bytesSize = int64(math.Pow(float64(1024), float64(i))) * int64(baseVar)
				return int64(bytesSize), nil
			}
		}
	}

	if strings.HasSuffix(size, "B") {

		dataBytes := strings.TrimSuffix(size, "B")
		baseVar, err := strconv.Atoi(dataBytes)
		if err != nil {
			return 0, err
		} else {
			return int64(baseVar), nil
		}
	}

	return bytesSize, fmt.Errorf("not found a valid suffix")
}
