package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/guumaster/logsymbols"
	"github.com/ivlovric/HFP/queue"
)

const AppVersion = "0.56.2"

var localAddr *string = flag.String("l", ":9060", "Local HEP listening address")
var remoteAddr *string = flag.String("r", "192.168.2.2:9060", "Remote HEP address")
var remoteProto *string = flag.String("p", "tcp", "Remote Proto type : tcp / tls")
var HepNodePW *string = flag.String("hp", "", "HEP node PW")
var skipVerify *bool = flag.Bool("s", false, "Skip verify tls certificate")
var IPfilter *string = flag.String("ipf", "", "IP filter address from HEP SRC or DST chunks. Option can use multiple IP as comma sepeated values. Default is no filter without processing HEP acting as high performance HEP proxy")
var IPfilterAction *string = flag.String("ipfa", "pass", "IP filter Action. Options are pass or reject")
var Debug *string = flag.String("d", "off", "Debug options are off or on")
var PrometheusPort *string = flag.String("prom", "8090", "Prometheus metrics port")
var KeepAlive *uint = flag.Uint("keepalive", 5, "keep alive internal - 5 seconds by default. 0 - disable")
var ReconnectCheck *uint = flag.Uint("reconnect", 5, "reconnect after 5 packets. 0 - disable")
var noDelayTCP *bool = flag.Bool("nodelay", true, "no delay in tcp connection. True by default")
var decodeIncomingHEP *bool = flag.Bool("hepdecode", false, "decode incoming hep packets and print out into LOG")
var maxBufferSize *string = flag.String("maxbuffer", "0", "max buffer size, can be B, MB, GB, TB. By default - unlimited")

var (
	AppLogger          *log.Logger
	filterIPs          []string
	HFPlog             string = "HFP.log"
	HEPsavefile        string = "HEP/HEP-saved.arch"
	MaxBufferSizeBytes int64  = 0
	productsQueue      *queue.Queue
	hepConnect         net.Conn
	reconnectCount     uint
)

// read messages from queue - make asynchonouse process
func doQueueJob() {

	defer func() {
		if r := recover(); r != nil {
			log.Println(fmt.Printf("Panic: %v,\n%s", r, debug.Stack()))
			return
		}
	}()

	worker := queue.NewWorker(productsQueue)
	worker.DoWork()
}

func connectToHEPBackend() error {

	defer func() {
		if r := recover(); r != nil {
			log.Println(fmt.Printf("Panic: %v,\n%s", r, debug.Stack()))
			return
		}
	}()

	if hepConnect != nil {
		log.Println("Lets close the connection first")
		hepConnect.Close()
	}

	dst := *remoteAddr
	proto := *remoteProto

	var err error

	if proto == "tls" {
		hepConnect, err = tls.Dial("tcp", dst, &tls.Config{InsecureSkipVerify: *skipVerify})
	} else {
		hepConnect, err = net.Dial("tcp", dst)
	}

	if err != nil {
		log.Println("Unable to connect to server: ", err)
		connectionStatus.Set(0)
		return fmt.Errorf("couldn't connect to server: %s", err.Error())
	} else {
		log.Println("Connected to server successfully")
		var tcpCon *net.TCPConn
		if proto == "tls" {
			tcpCon = hepConnect.(*tls.Conn).NetConn().(*net.TCPConn)
		} else {
			tcpCon = hepConnect.(*net.TCPConn)
		}
		//Keep Alive
		if *KeepAlive > 0 {
			tcpCon.SetKeepAlive(true)
			tcpCon.SetKeepAlivePeriod(time.Second * time.Duration(*KeepAlive))
		}
		//Nodelay
		tcpCon.SetNoDelay(*noDelayTCP)
		SendPingHEPPacket(hepConnect)
		time.Sleep(time.Second * 1)
		connectionStatus.Set(1)

		if _, err := copyHEPFileOut(); err != nil {
			log.Println("||-->", logsymbols.Error, "Sending HEP from file error....:", err)
		}
		return nil
	}

}

func handleConnection(clientConn net.Conn) {

	defer func() {
		if r := recover(); r != nil {
			log.Println(fmt.Printf("Handle connection panic: %v,\n%s", r, debug.Stack()))
			return
		}
	}()

	// use a buffer to transfer data between connections
	buf := make([]byte, 65535)

	defer clientConn.Close()

	//reader := bufio.NewReader(clientConn)
	for {
		//n, err := reader.Read(buf)

		n, err := clientConn.Read(buf)
		if err != nil {
			log.Println("Client connection closed:", err)
			return
		}

		if *Debug == "on" {
			log.Println("-->|| Got", n, "bytes on wire -- Total buffer size:", len(buf))
		}

		if *decodeIncomingHEP {
			hepPkt, err := DecodeHEP(buf[:n])
			if err != nil {
				log.Println("Error decoding HEP in decode mode", err)
			} else {
				log.Println("HEP decoded START ====================================================")
				log.Println("HEP decoded SRC IP/Port", hepPkt.SrcIP, ":", hepPkt.SrcPort)
				log.Println("HEP decoded DST IP/Port", hepPkt.DstIP, ":", hepPkt.DstPort)
				log.Println("HEP decoded Timestamp: ", hepPkt.Tsec, ", Usec:", hepPkt.Tmsec)
				log.Println("HEP decoded correlation ID: ", hepPkt.CID)
				log.Println("HEP Payload len: ", len(hepPkt.Payload), ", message: ", hepPkt.Payload)
				log.Println("HEP decoded END ======================================================")
			}
		}

		//Prometheus timestamp metric of incoming packet to detect lack of inbound HEP traffic
		clientLastMetricTimestamp.SetToCurrentTime()

		//
		if *IPfilter != "" && *IPfilterAction == "pass" {
			hepPkt, err := DecodeHEP(buf[:n])
			if err != nil {
				log.Println("Error decoding HEP", err)
			}

			if *Debug == "on" {
				//log.Println("HEP decoded ", hepPkt)
				log.Println("HEP decoded SRC IP", hepPkt.SrcIP)
				log.Println("HEP decoded DST IP", hepPkt.DstIP)
			}

			var accepted bool = false
			for _, ipf := range filterIPs {
				if hepPkt.SrcIP == string(ipf) || hepPkt.DstIP == string(ipf) || string(buf[:n]) == "HELLO HFP" {

					//Send HEP out to backend
					hepJob := queue.Job{Type: 1, Data: buf[:n], Len: n, Action: sendHepOut}
					productsQueue.AddJob(hepJob)

					if *Debug == "on" {
						if string(buf[:n]) == "HELLO HFP" {
							log.Println("||--> Sending init HELLO HFP successful with filter for", string(ipf))
						} else {
							log.Println("||--> Sending HEP OUT successful with filter for", string(ipf))
						}
					}
				}
			}

			if !accepted {
				if *Debug == "on" {
					log.Println("-->", logsymbols.Error, "|| HEP filter not matched with source or destination IP in HEP packet", hepPkt.SrcIP, "or", hepPkt.DstIP)
				}
			}

		} else if *IPfilter != "" && *IPfilterAction == "reject" {
			hepPkt, err := DecodeHEP(buf[:n])
			if err != nil {
				log.Println("Error decoding HEP", err)
			}

			if *Debug == "on" {
				//log.Println("HEP decoded ", hepPkt)
				log.Println("HEP decoded SRC IP", hepPkt.SrcIP)
				log.Println("HEP decoded DST IP", hepPkt.DstIP)
			}

			var rejected bool = false
			for _, ipf := range filterIPs {
				if hepPkt.SrcIP == string(ipf) || hepPkt.DstIP == string(ipf) {
					clientConn.Write([]byte("Rejecting IP"))
					if *Debug == "on" {
						log.Printf("-->|| Rejecting IP:%q", ipf)
					}
					rejected = true
					break
				}
			}

			if !rejected {
				//Send HEP out to backend
				hepJob := queue.Job{Type: 1, Data: buf[:n], Len: n, Action: sendHepOut}
				productsQueue.AddJob(hepJob)
				if *Debug == "on" {
					log.Println("||-->", logsymbols.Success, " Sending HEP OUT successful with filter")
				}
			}

		} else {

			//Send HEP out to backend
			hepJob := queue.Job{Type: 1, Data: buf[:n], Len: n, Action: sendHepOut}
			productsQueue.AddJob(hepJob)

			if *Debug == "on" {
				if string(buf[:n]) == "HELLO HFP" {
					log.Println("||-->", logsymbols.Success, " Sending init HELLO HFP successful without filters")
				} else {
					log.Println("||-->", logsymbols.Success, " Sending HEP OUT successful without filters")
				}
			}

		}
	}
}

func sendHepOut(data []byte, len int) error {

	defer func() {
		if r := recover(); r != nil {
			log.Println(fmt.Printf("sendHepOut to panic: %v,\n%s", r, debug.Stack()))
			return
		}
	}()

	//If socket is nil - reconnect....
	if hepConnect == nil {
		if *Debug == "on" {
			log.Println("||-->", logsymbols.Error, "socket is nil:")
		}
		connectionStatus.Set(0)
		copyHEPbufftoFile(data, HEPsavefile)
		//Starts reopen connection
		reconnectCount++
		if reconnectCount%*ReconnectCheck == 0 || *ReconnectCheck == 0 {
			if err := connectToHEPBackend(); err != nil {
				if *Debug == "on" {
					log.Println("||-->", logsymbols.Error, " reconnect to HEP backend error: ", err.Error())
				}
			}
			reconnectCount = 0
		}

		//Last check
		if hepConnect == nil {
			return fmt.Errorf("socket is still nil")
		}
	}

	//
	if _, err_HEPout := hepConnect.Write(data); err_HEPout != nil {

		if *Debug == "on" {
			log.Println("||-->", logsymbols.Error, "Sending HEP OUT error:", err_HEPout)
		}

		connectionStatus.Set(0)
		copyHEPbufftoFile(data, HEPsavefile)

		//Starts reopen connection
		reconnectCount++
		if reconnectCount%*ReconnectCheck == 0 || *ReconnectCheck == 0 {
			if err := connectToHEPBackend(); err != nil {
				if *Debug == "on" {
					log.Println("||-->", logsymbols.Error, " reconnect to HEP backend error: ", err.Error())
				}
			}
			reconnectCount = 0
		}
	} else {
		if *Debug == "on" {
			log.Println("||-->", logsymbols.Success, " Sent HEP successful. Size: ", len)
		}
	}

	return nil
}

func copyHEPbufftoFile(inbytes []byte, file string) (int64, error) {

	defer func() {
		if r := recover(); r != nil {
			log.Println(fmt.Printf("copy buffer to panic: %v,\n%s", r, debug.Stack()))
			return
		}
	}()

	destination, err := os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("Open HEP file error", err)
	}

	defer destination.Close()

	if MaxBufferSizeBytes > 0 {
		fi, err := destination.Stat()
		if err != nil {
			log.Println("||-->", logsymbols.Error, "couldn't retrive stats from buffer file error", err)
			return 0, err
		} else {
			if fi.Size() >= MaxBufferSizeBytes {
				log.Println("||-->", logsymbols.Error, "Buffer size has been excited error: Maxsize: ", MaxBufferSizeBytes, " vs CurrentSize: ", fi.Size())
				return 0, fmt.Errorf("buffer size has been excited: %d", fi.Size())
			}
		}
	}

	nBytes, err := destination.Write(inbytes)

	if err != nil {
		if *Debug == "on" {
			log.Println("||-->", logsymbols.Error, " File Send HEP from buffer to file error", err)
			AppLogger.Println("||-->", logsymbols.Error, " File Send HEP from buffer to file error", err)
		}

	} else {
		if *Debug == "on" {
			log.Println("||-->", logsymbols.Success, " File Send HEP from buffer to file OK")
			AppLogger.Println("||-->", logsymbols.Success, "File Send HEP from buffer to file OK")
		}

		go hepBytesInFile.Add(float64(nBytes))

	}

	return int64(nBytes), err

}

func copyHEPFileOut() (int, error) {

	defer func() {
		if r := recover(); r != nil {
			log.Println(fmt.Printf("copy hep file out panic: %v,\n%s", r, debug.Stack()))
			return
		}
	}()

	HEPFileData, HEPFileDataerr := os.ReadFile(HEPsavefile)
	if HEPFileDataerr != nil {
		fmt.Println("Read HEP file error", HEPFileDataerr)
	}

	if hepConnect == nil {
		log.Println("||-->", logsymbols.Error, " connection is broken....")
		return 0, fmt.Errorf("connection is broken")
	}

	//Send Logged HEP upon reconnect out to backend
	hl, err := hepConnect.Write(HEPFileData)
	if err != nil {
		log.Println("||-->X Send HEP from LOG error", err)
		AppLogger.Println("||-->X Send HEP from LOG error", err)
		hepFileFlushesError.Inc()
	} else {
		fi, err := os.Stat(HEPsavefile)
		if err != nil {
			log.Println("Cannot stat HEP log file", err)
			AppLogger.Println("Cannot stat HEP log file", err)
		}

		if fi.Size() > 0 {
			log.Println("||-->", logsymbols.Success, " Send HEP from LOG OK -", hl, "bytes")
			log.Println("Clearing HEP file")
			AppLogger.Println("||-->", logsymbols.Success, " Send HEP from LOG OK -", hl, "bytes")
			AppLogger.Println("Clearing HEP file")
			//Recreate file, thus cleaning the content
			os.Create(HEPsavefile)
			hepFileFlushesSuccess.Inc()
		}
	}

	return hl, err
}

func main() {

	var wg sync.WaitGroup
	logsymbols.ForceColors()

	defer func() {
		if r := recover(); r != nil {
			log.Println(fmt.Printf("main panic: %v,\n%s", r, debug.Stack()))
			return
		}
	}()

	version := flag.Bool("v", false, "Prints current HFP version")
	flag.Parse()

	if *version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	if *IPfilter != "" {
		filterIPs = strings.Split(*IPfilter, ",")
		log.Println("Generated filtersIP array", *IPfilter, ", LEN: ", len(filterIPs))
	}

	errmkdir := os.Mkdir("HEP", 0755)
	if errmkdir != nil {
		log.Println("Mkdir error:", errmkdir)
	}

	if _, errhfexist := os.Stat(HEPsavefile); errhfexist != nil {
		if os.IsNotExist(errhfexist) {
			fmt.Println("HEP File doesnt exists - Creating", errhfexist)
			_, errhfcreate := os.Create(HEPsavefile)
			fmt.Println(logsymbols.Info, "-->|| Creating HEP file")
			if errhfcreate != nil {
				fmt.Println("Create file error", errhfcreate)
				return
			}
		}
	}

	applog, err := os.OpenFile(HFPlog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	AppLogger = log.New(applog, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)

	fi, err := os.Stat(HEPsavefile)
	if err != nil {
		log.Println(logsymbols.Error, err)
	}
	fmt.Println(logsymbols.Info, "Saved HEP file is ", fi.Size(), "bytes")

	if *maxBufferSize != "0" && *maxBufferSize != "" {
		MaxBufferSizeBytes, err = Human2FileSize(*maxBufferSize)
		if err != nil {
			fmt.Println(logsymbols.Error, "|| couldn't convert buffer size to bytes", err)
			os.Exit(1)
		} else {
			fmt.Println(logsymbols.Info, "Maximum HEP file size is ", MaxBufferSizeBytes, "bytes. You provided: ", *maxBufferSize)
		}
	}

	productsQueue = queue.NewQueue("NewProducts")

	go func() {
		connectToHEPBackend()
	}()

	go func() {
		doQueueJob()
	}()

	fmt.Printf("Listening for HEP on: %v\nProxying HEP to: %v\nProto HEP: %v\nIPFilter: %v\nIPFilterAction: %v\nPrometheus metrics: %v\n\n", *localAddr, *remoteAddr, *remoteProto, *IPfilter, *IPfilterAction, *PrometheusPort)
	AppLogger.Println("Listening for HEP on:", *localAddr, "\n", "Proxying HEP to:", *remoteAddr, "\n", "Proto HEP:", *remoteProto, "\n", "IPFilter:", *IPfilter, "\n", "IPFilterAction:", *IPfilterAction, "\n", "Prometheus metrics:", *PrometheusPort)
	if *IPfilter == "" {
		fmt.Println(logsymbols.Success, "HFP starting in proxy high performance mode\n__________________________________________")
		AppLogger.Println(logsymbols.Success, "HFP starting in proxy high performance mode\n__________________________________________")
	} else {
		fmt.Println(logsymbols.Success, "HFP starting in proxy processing mode\n_____________________________________")
		AppLogger.Println(logsymbols.Success, "HFP starting in proxy processing mode\n_____________________________________")
	}

	addr, err := net.ResolveTCPAddr("tcp", *localAddr)
	if err != nil {
		log.Println(logsymbols.Error, "IP ResolvTCP: ", err)
		return
	}
	listener, err := net.ListenTCP("tcp4", addr)
	if err != nil {
		fmt.Println(logsymbols.Error, "|| HFP starting error", err)
		os.Exit(1)
	}

	defer listener.Close()

	go startMetrics(&wg)

	wg.Wait()

	for {
		clientConn, err := listener.AcceptTCP()
		log.Println(logsymbols.Success, "-->|| New connection from", clientConn.RemoteAddr())
		AppLogger.Println(logsymbols.Success, "-->|| New connection from", clientConn.RemoteAddr())
		connectedClients.Inc()

		if err != nil {
			log.Println(logsymbols.Error, "Accept connection error:", err)
			return
		}

		go handleConnection(clientConn)
	}
}

func SendPingHEPPacket(conn net.Conn) {

	defer func() {
		if r := recover(); r != nil {
			log.Println(fmt.Printf("hep ping panic: %v,\n%s", r, debug.Stack()))
			return
		}
	}()

	if *HepNodePW == "" {
		return
	}

	//this is PING
	msg, err := MakeHEPPing()
	if err != nil {
		log.Println("||-->X Make HEP PING", err)
		return
	}

	//Send Logged HEP upon reconnect out to backend
	_, err = conn.Write(msg)
	if err != nil {
		log.Println("||-->X Send HEP PING", err)
		AppLogger.Println("||-->X Send HEP PING", err)
	} else if *Debug == "on" {
		log.Println("-->|| Sent HEP Ping")
	}
}
