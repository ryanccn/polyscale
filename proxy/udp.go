package proxy

import (
	"net"
	"sync"

	"github.com/charmbracelet/log"

	"github.com/ryanccn/polyscale/config"
)

func UDPReverseProxy(wg *sync.WaitGroup, srvConfig *config.ConfigServer, dstConn net.PacketConn) {
	defer wg.Done()
	defer dstConn.Close()

	var srcAddress *net.UDPAddr

	switch srvConfig.Src.Scheme {
	case "unix", "unixpacket", "unixgram":
		addr, err := net.ResolveUDPAddr(srvConfig.Src.Scheme, srvConfig.Src.Path)
		if err != nil {
			log.Fatal(err)
		}
		srcAddress = addr

	default:
		addr, err := net.ResolveUDPAddr(srvConfig.Src.Scheme, srvConfig.Src.Host)
		if err != nil {
			log.Fatal(err)
		}
		srcAddress = addr
	}

	for {
		incomingBuf := make([]byte, 1024)
		incomingSize, addr, err := dstConn.ReadFrom(incomingBuf)
		if err != nil {
			log.Error(err)
			continue
		}

		go func() {
			srcConn, err := net.DialUDP(srvConfig.Src.Scheme, nil, srcAddress)
			if err != nil {
				log.Error(err)
				return
			}

			_, err = srcConn.Write(incomingBuf[:incomingSize])
			if err != nil {
				log.Error(err)
				return
			}

			responseBuf := make([]byte, 1024)
			responseSize, err := srcConn.Read(responseBuf)
			if err != nil {
				log.Error(err)
				return
			}

			_, err = dstConn.WriteTo(responseBuf[:responseSize], addr)
			if err != nil {
				log.Error(err)
				return
			}
		}()
	}
}
