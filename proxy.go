package multiserver

import "log"

func Proxy(src, dst *Peer) {
	for {
		pkt, err := src.Recv()
		if !src.Forward() {
			return
		} else if !dst.Forward() {
			break
		}
		if err != nil {
			if err == ErrClosed {
				msg := src.Addr().String() + " disconnected"
				if src.TimedOut() {
					msg += " (timed out)"
				}
				log.Print(msg)
				
				if !src.IsSrv() {
					connectedPeers--
					processLeave(src.ID())
				}
				
				break
			}
			
			log.Print(err)
			continue
		}
		
		// Process
		if pkt.Data[0] == uint8(0x00) && pkt.Data[1] == uint8(0x32) && !src.IsSrv() {
			if processChatMessage(src.ID(), pkt.Data) {
				continue
			}
		}
		
		// Forward
		if _, err := dst.Send(pkt); err != nil {
			log.Print(err)
		}
	}
	
	dst.SendDisco(0, true)
	dst.Close()
}
