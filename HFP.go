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
)

const AppVersion = "0.55.14"

var localAddr *string = flag.String("l", ":9060", "Local HEP listening address")
var remoteAddr *string = flag.String("r", "192.168.2.2:9060", "Remote HEP address")
var remoteProto *string = flag.String("p", "tcp", "Remote Proto type : tcp / tls")
var HepNodePW *string = flag.String("hp", "", "HEP node PW")
var skipVerify *bool = flag.Bool("s", false, "Skip verify tls certificate")
var IPfilter *string = flag.String("ipf", "", "IP filter address from HEP SRC or DST chunks. Option can use multiple IP as comma sepeated values. Default is no filter without processing HEP acting as high performance HEP proxy")
var IPfilterAction *string = flag.String("ipfa", "pass", "IP filter Action. Options are pass or reject")
var Debug *string = flag.String("d", "off", "Debug options are off or on")
var PrometheusPort *string = flag.String("prom", "8090", "Prometheus metrics port")
var KeepAlive *uint = flag.Uint("keepalive", 5, "keep alive internal - 5 seconds by default. 0 - disables")
var noDelayTCP *bool = flag.Bool("nodelay", true, "no delay in tcp connection. True by default")
var maxBufferSize *string = flag.String("maxbuffer", "0", "max buffer size, can be B, MB, GB, TB. By default - unlimited")

var (
	AppLogger          *log.Logger
	filterIPs          []string
	HFPlog             string = "HFP.log"
	HEPsavefile        string = "HEP/HEP-saved.arch"
	MaxBufferSizeBytes int64  = 0
)

func initLoopbackConn(wg *sync.WaitGroup) {

	defer func() {
		if r := recover(); r != nil {
			log.Println(fmt.Printf("initLoopbackConn: %v,\n%s", r, debug.Stack()))
			return
		}
	}()

	//Connect loopback in
	outnet, err := net.Dial("tcp4", *localAddr)

	if err != nil {
		log.Println("c==>", logsymbols.Error, "|| INITIAL Loopback IN", err)
		AppLogger.Println("c==>", logsymbols.Error, "|| INITIAL Loopback IN error", err)

	} else {
		_, err := outnet.Write([]byte("HELLO HFP"))
		if err != nil {
			log.Println("HELLO HFP c==>", logsymbols.Error, "|| Send HELLO HFP error", err)
			AppLogger.Println("HELLO HFP c==>", logsymbols.Error, "|| Send HELLO HFP error", err)
		} else {
			log.Println("HELLO HFP c==>", logsymbols.Success, "|| INITIAL Dial LOOPBACK IN success")
			AppLogger.Println("HELLO HFP c==>", logsymbols.Success, "|| INITIAL Dial LOOPBACK IN success")
		}

	}

	wg.Add(1)
	wg.Done()

}

func connectToHEPBackend(dst, proto string) net.Conn {

	defer func() {
		if r := recover(); r != nil {
			log.Println(fmt.Printf("Panic: %v,\n%s", r, debug.Stack()))
			return
		}
	}()

	for {

		var conn net.Conn
		var err error

		if proto == "tls" {
			conn, err = tls.Dial("tcp", dst, &tls.Config{InsecureSkipVerify: *skipVerify})
		} else {
			conn, err = net.Dial("tcp", dst)
		}

		if err != nil {
			log.Println("Unable to connect to server: ", err)
			connectionStatus.Set(0)
			time.Sleep(time.Second * 5) // wait for 5 seconds before reconnecting

		} else {
			log.Println("Connected to server successfully")

			var tcpCon *net.TCPConn
			if proto == "tls" {
				tcpCon = conn.(*tls.Conn).NetConn().(*net.TCPConn)
			} else {
				tcpCon = conn.(*net.TCPConn)
			}
			//Keep Alive
			if *KeepAlive > 0 {
				tcpCon.SetKeepAlive(true)
				tcpCon.SetKeepAlivePeriod(time.Second * time.Duration(*KeepAlive))

			}
			//Nodelay
			tcpCon.SetNoDelay(*noDelayTCP)

			SendPingHEPPacket(conn)
			time.Sleep(time.Second * 1)
			connectionStatus.Set(1)
			copyHEPFileOut(conn)
			return conn
		}
	}
}

func handleConnection(clientConn net.Conn, destAddr, destProto string) {
	var destConn net.Conn
	//var err error

	defer func() {
		if r := recover(); r != nil {
			log.Println(fmt.Printf("Handle connection panic: %v,\n%s", r, debug.Stack()))
			return
		}
	}()

	// use a buffer to transfer data between connections
	buf := make([]byte, 65535)

	//	for {
	//		destConn, err = net.Dial("tcp", destAddr)
	//		if err != nil {
	//			log.Println("||-->", logsymbols.Error, "Dial OUT reconnect failure - retrying", err)
	//			AppLogger.Println("||-->", logsymbols.Error, " Dial OUT reconnect failure - retrying")
	//			copyHEPbufftoFile(buf[:n2], HEPsavefile)
	//
	//			//log.Println(err)
	//			time.Sleep(time.Second * 5) // wait for 5 seconds before reconnecting
	//			continue
	//		}
	//		break
	//	}
	//defer destConn.Close()

	go func() {
		destConn = connectToHEPBackend(destAddr, destProto)
	}()

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

		//Prometheus timestamp metric of incoming packet to detect lack of inbound HEP traffic
		clientLastMetricTimestamp.SetToCurrentTime()

		if destConn != nil {
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
						if _, err_HEPout := destConn.Write(buf[:n]); err_HEPout != nil {
							log.Println("||-->", logsymbols.Error, " Sending HEP OUT error:", err_HEPout)
							//	rb := bytes.NewReader(buf[:data])
							connectionStatus.Set(0)
							copyHEPbufftoFile(buf[:n], HEPsavefile)
							accepted = true

							for {
								if destProto == "tls" {
									destConn, err = tls.Dial("tcp", destAddr, &tls.Config{InsecureSkipVerify: *skipVerify})
								} else {
									destConn, err = net.Dial("tcp", destAddr)
								}

								if err != nil {
									log.Println("||-->", logsymbols.Error, " Dial OUT reconnect failure - retrying", err)
									AppLogger.Println("||-->", logsymbols.Error, " Dial OUT reconnect failure - retrying")
									time.Sleep(time.Second * 5) // wait for 5 seconds before reconnecting
									continue
								} else {
									log.Println("||--> Connected to ", destAddr, ", proto:", destProto)
									//Keep Alive
									var tcpCon *net.TCPConn
									if destProto == "tls" {
										tcpCon = destConn.(*tls.Conn).NetConn().(*net.TCPConn)
									} else {
										tcpCon = destConn.(*net.TCPConn)
									}
									//Keep Alive
									if *KeepAlive > 0 {
										tcpCon.SetKeepAlive(true)
										tcpCon.SetKeepAlivePeriod(time.Second * time.Duration(*KeepAlive))

									}
									//Nodelay
									tcpCon.SetNoDelay(*noDelayTCP)

									SendPingHEPPacket(destConn)
									time.Sleep(time.Second * 1)
									connectionStatus.Set(1)
									copyHEPFileOut(destConn)
								}
								break
							}
							continue

						} else {
							if *Debug == "on" {
								if string(buf[:n]) == "HELLO HFP" {
									log.Println("||--> Sending init HELLO HFP successful with filter for", string(ipf), "to", destConn.RemoteAddr())
								} else {
									log.Println("||--> Sending HEP OUT successful with filter for", string(ipf), "to", destConn.RemoteAddr())
								}
							}
							accepted = true
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
					if _, err_HEPout := destConn.Write(buf[:n]); err_HEPout != nil {
						log.Println("||-->", logsymbols.Error, " Sending HEP OUT error:", err_HEPout)
						//rb := bytes.NewReader(buf[:data])
						connectionStatus.Set(0)
						copyHEPbufftoFile(buf[:n], HEPsavefile)

						for {

							if destProto == "tls" {
								destConn, err = tls.Dial("tcp", destAddr, &tls.Config{InsecureSkipVerify: *skipVerify})
							} else {
								destConn, err = net.Dial("tcp", destAddr)
							}

							if err != nil {
								log.Println("||-->", logsymbols.Error, " Dial OUT reconnect failure - retrying", err)
								AppLogger.Println("||-->", logsymbols.Error, " Dial OUT reconnect failure - retrying")
								time.Sleep(time.Second * 5) // wait for 5 seconds before reconnecting
								continue
							} else {
								log.Println("||--> Diallout to ", destAddr, ", proto:", destProto)

								//Keep Alive
								var tcpCon *net.TCPConn
								if destProto == "tls" {
									tcpCon = destConn.(*tls.Conn).NetConn().(*net.TCPConn)
								} else {
									tcpCon = destConn.(*net.TCPConn)
								}
								//Keep Alive
								if *KeepAlive > 0 {
									tcpCon.SetKeepAlive(true)
									tcpCon.SetKeepAlivePeriod(time.Second * time.Duration(*KeepAlive))

								}
								//Nodelay
								tcpCon.SetNoDelay(*noDelayTCP)

								SendPingHEPPacket(destConn)
								time.Sleep(time.Second * 1)
								connectionStatus.Set(1)
								copyHEPFileOut(destConn)
							}
							break
						}
						continue

						//return
					} else {
						if *Debug == "on" {
							log.Println("||-->", logsymbols.Success, " Sending HEP OUT successful with filter to", destConn.RemoteAddr())
						}
					}
				}

			} else {
				//Send HEP out to backend
				bSend, err_HEPout := destConn.Write(buf[:n])
				if err_HEPout != nil {
					log.Println("||-->", logsymbols.Error, " Sending HEP OUT error:", err_HEPout)
					// rb := bytes.NewReader(buf[:data])
					connectionStatus.Set(0)
					copyHEPbufftoFile(buf[:n], HEPsavefile)

					for {

						if destProto == "tls" {
							destConn, err = tls.Dial("tcp", destAddr, &tls.Config{InsecureSkipVerify: *skipVerify})
						} else {
							destConn, err = net.Dial("tcp", destAddr)
						}

						if err != nil {
							log.Println("||-->", logsymbols.Error, " Dial OUT reconnect failure - retrying", err)
							AppLogger.Println("||-->", logsymbols.Error, " Dial OUT reconnect failure - retrying")
							time.Sleep(time.Second * 5) // wait for 5 seconds before reconnecting
							continue
						} else {
							log.Println("||--> Diallout after reconnect to ", destAddr, ", proto:", destProto)

							//Keep Alive
							var tcpCon *net.TCPConn
							if destProto == "tls" {
								tcpCon = destConn.(*tls.Conn).NetConn().(*net.TCPConn)
							} else {
								tcpCon = destConn.(*net.TCPConn)
							}
							//Keep Alive
							if *KeepAlive > 0 {
								tcpCon.SetKeepAlive(true)
								tcpCon.SetKeepAlivePeriod(time.Second * time.Duration(*KeepAlive))

							}
							//Nodelay
							tcpCon.SetNoDelay(*noDelayTCP)

							SendPingHEPPacket(destConn)
							time.Sleep(time.Second * 1)
							connectionStatus.Set(1)
							copyHEPFileOut(destConn)
						}
						break
					}
					continue
				} else {
					if *Debug == "on" {
						if string(buf[:n]) == "HELLO HFP" {
							log.Println("||-->", logsymbols.Success, " Sending init HELLO HFP successful without filters to", destConn.RemoteAddr())
						} else {
							log.Println("||-->", logsymbols.Success, " Sending HEP OUT successful without filters to ", destConn.RemoteAddr(), ", sendout: ", bSend)
						}
					}
				}
			}

			//
			//_, err = destConn.Write(buf[:n])
			//	if err != nil {
			//		log.Println(logsymbols.Error, err)
			//		destConn.Close()
			//		copyHEPbufftoFile(buf[:n], HEPsavefile)
			//		for {
			//			destConn, err = net.Dial("tcp4", destAddr)
			//			if err != nil {
			//				log.Println("||-->X Dial OUT reconnect failure - retrying", err)
			//				AppLogger.Println("||-->X Dial OUT reconnect failure - retrying")
			//				time.Sleep(time.Second * 5) // wait for 5 seconds before reconnecting
			//				continue
			//			} else {
			//				copyHEPFileOut(destConn)
			//			}
			//			break
			//		}
			//		continue
			//	}
		} else {

			hepPkt, err := DecodeHEP(buf[:n])
			if err != nil {
				log.Println("Error decoding HEP", err)
			}

			if *Debug == "on" {
				//log.Println("HEP decoded ", hepPkt)
				log.Println("HEP decoded SRC IP", hepPkt.SrcIP)
				log.Println("HEP decoded DST IP", hepPkt.DstIP)
			}

			for _, ipf := range filterIPs {
				if ((hepPkt.SrcIP == string(ipf) || hepPkt.DstIP == string(ipf) || string(buf[:n]) == "HELLO HFP") && *IPfilterAction == "pass") || ((hepPkt.SrcIP != string(ipf) || hepPkt.DstIP != string(ipf)) && *IPfilterAction == "reject") {
					copyHEPbufftoFile(buf[:n], HEPsavefile)
				} else {
					log.Println("Not logging filtered HEP traffic: ", ipf, ", Len: ", len(filterIPs))
				}
			}
		}
	}
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
		log.Println("||-->", logsymbols.Error, " File Send HEP from buffer to file error", err)
		AppLogger.Println("||-->", logsymbols.Error, " File Send HEP from buffer to file error", err)

	} else {
		log.Println("||-->", logsymbols.Success, " File Send HEP from buffer to file OK")
		AppLogger.Println("||-->", logsymbols.Success, "File Send HEP from buffer to file OK")

		go hepBytesInFile.Add(float64(nBytes))

	}

	return int64(nBytes), err

}

func copyHEPFileOut(outnet net.Conn) (int, error) {

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

	//Send Logged HEP upon reconnect out to backend
	hl, err := outnet.Write(HEPFileData)
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
		//	} else {
		//		fmt.Println(logsymbols.Success, "|| HFP listener started")
		//
		//	}
	}
	defer listener.Close()

	go startMetrics(&wg)
	go initLoopbackConn(&wg)

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

		//for i := 1; i <= 2; i++ {
		go handleConnection(clientConn, *remoteAddr, *remoteProto)
		//}
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
