package proxy

import (
	"io"
	"net"
	"sync"

	"github.com/charmbracelet/log"
	"github.com/pires/go-proxyproto"

	"github.com/ryanccn/polyscale/config"
)

func TCPReverseProxy(wg *sync.WaitGroup, srvConfig *config.ConfigServer, cfg *config.Config, listener net.Listener) {
	defer wg.Done()
	defer listener.Close()

	for {
		dstConn, err := listener.Accept()
		if err != nil {
			log.Error(err)
			continue
		}

		var srcAddress *net.TCPAddr

		switch srvConfig.Src.Scheme {
		case "unix", "unixpacket", "unixgram":
			addr, err := net.ResolveTCPAddr(srvConfig.Src.Scheme, srvConfig.Src.Path)
			if err != nil {
				log.Fatal(err)
			}
			srcAddress = addr

		default:
			addr, err := net.ResolveTCPAddr(srvConfig.Src.Scheme, srvConfig.Src.Host)
			if err != nil {
				log.Fatal(err)
			}
			srcAddress = addr
		}

		srcConn, err := net.DialTCP(srvConfig.Src.Scheme, nil, srcAddress)
		if err != nil {
			log.Error(err)
			continue
		}

		if srvConfig.ProxyProtocol {
			dstRemoteAddr := dstConn.RemoteAddr().(*net.TCPAddr)
			var fakeDstLocalAddr net.Addr

			if len(dstRemoteAddr.IP) == net.IPv6len {
				fakeDstLocalAddr = &net.TCPAddr{IP: net.IPv6unspecified}
			} else {
				fakeDstLocalAddr = &net.TCPAddr{IP: net.IPv4zero}
			}

			proxyHeader := proxyproto.HeaderProxyFromAddrs(
				2,
				dstRemoteAddr,
				fakeDstLocalAddr,
			)

			_, err = proxyHeader.WriteTo(srcConn)
			if err != nil {
				log.Error(err)
				continue
			}
		}

		go func() {
			_, err = io.Copy(dstConn, srcConn)
			if err != nil {
				log.Error(err)
			}
		}()

		go func() {
			_, err = io.Copy(srcConn, dstConn)
			if err != nil {
				log.Error(err)
			}
		}()
	}
}
