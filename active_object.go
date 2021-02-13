package main

import (
	"encoding/binary"
)

func processAoRmAdd(p *Peer, data []byte) []byte {
	countRm := binary.BigEndian.Uint16(data[2:4])
	var aoRm []uint16
	for i := uint16(0); i < countRm; i += 2 {
		aoRm = append(aoRm, binary.BigEndian.Uint16(data[4+i:6+i]))
	}

	countAdd := binary.BigEndian.Uint16(data[4+countRm*2 : 6+countRm*2])
	var aoAdd []uint16
	si := 6 + uint32(countRm)*2
	for i := uint32(0); i < uint32(countAdd); i++ {
		initDataLen := binary.BigEndian.Uint32(data[3+si : 7+si])

		namelen := binary.BigEndian.Uint16(data[8+si : 10+si])
		name := data[10+si : 10+si+uint32(namelen)]
		if string(name) == p.Username() {
			if p.initAoReceived {
				binary.BigEndian.PutUint16(data[4+countRm*2:6+countRm*2], countAdd-1)
				data = append(data[:si], data[7+si+initDataLen:]...)
				si -= 7 + initDataLen
			} else {
				p.initAoReceived = true
			}

			si += 7 + initDataLen
			continue
		}

		aoAdd = append(aoAdd, binary.BigEndian.Uint16(data[si:2+si]))

		si += 7 + initDataLen
	}

	p.redirectMu.Lock()
	for i := range aoAdd {
		if aoAdd[i] != 0 {
			p.aoIDs[aoAdd[i]] = true
		}
	}

	for i := range aoRm {
		p.aoIDs[aoRm[i]] = false
	}
	p.redirectMu.Unlock()

	return data
}
