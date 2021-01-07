package multiserver

import (
	"encoding/binary"
	"log"
	
	"github.com/yuin/gopher-lua"
)

func getPlayerName(L *lua.LState) int {
	id := L.ToInt(1)
	l := GetListener()
	p := l.GetPeerByID(PeerID(id))
	
	L.Push(lua.LString(p.username))
	
	return 1
}

func kickPlayer(L *lua.LState) int {
	id := L.ToInt(1)
	reason := L.ToString(2)
	l := GetListener()
	p := l.GetPeerByID(PeerID(id))
	
	if reason == "" {
		reason = "Kicked."
	} else {
		reason = "Kicked. " + reason
	}
	
	msg := []byte(reason)
	
	data := make([]byte, 6 + len(msg))
	data[0] = uint8(0x00)
	data[1] = uint8(0x0A)
	data[2] = uint8(0x0A)
	binary.BigEndian.PutUint16(data[3:5], uint16(len(msg)))
	copy(data[5:5 + len(msg)], msg)
	data[5 + len(msg)] = uint8(0x00)
	
	ack, err := p.Send(Pkt{Data: data, ChNo: 0, Unrel: false})
	if err != nil {
		log.Print(err)
	}
	<-ack
	
	p.SendDisco(0, true)
	p.Close()
	
	return 0
}
