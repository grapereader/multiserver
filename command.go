package multiserver

import (
	"crypto/subtle"
	"encoding/binary"
	"github.com/HimbeerserverDE/srp"
	"log"
)

const (
	ToClientHello                 = 0x02
	ToClientAuthAccept            = 0x03
	ToClientAcceptSudoMode        = 0x04
	ToClientDenySudoMode          = 0x05
	ToClientAccessDenied          = 0x0A
	ToClientBlockdata             = 0x20
	ToClientAddNode               = 0x21
	ToClientRemoveNode            = 0x22
	ToClientInventory             = 0x27
	ToClientTimeOfDay             = 0x29
	ToClientCsmRestrictionFlags   = 0x2A
	ToClientPlayerSpeed           = 0x2B
	ToClientMediaPush             = 0x2C
	ToClientChatMessage           = 0x2F
	ToClientActiveObjectRemoveAdd = 0x31
	ToClientActiveObjectMessages  = 0x32
	ToClientHp                    = 0x33
	ToClientMovePlayer            = 0x34
	ToClientFov                   = 0x36
	ToClientDeathscreen           = 0x37
	ToClientMedia                 = 0x38
	ToClientTooldef               = 0x39
	ToClientNodedef               = 0x3A
	ToClientCraftitemdef          = 0x3B
	ToClientAnnounceMedia         = 0x3C
	ToClientItemdef               = 0x3D
	ToClientPlaySound             = 0x3F
	ToClientStopSound             = 0x40
	ToClientPrivileges            = 0x41
	ToClientInventoryFormspec     = 0x42
	ToClientDetachedInventory     = 0x43
	ToClientShowFormspec          = 0x44
	ToClientMovement              = 0x45
	ToClientSpawnParticle         = 0x46
	ToClientAddParticlespawner    = 0x47
	ToClientHudAdd                = 0x49
	ToClientHudRm                 = 0x4A
	ToClientHudChange             = 0x4B
	ToClientHudSetFlags           = 0x4C
	ToClientHudSetParam           = 0x4D
	ToClientBreath                = 0x4E
	ToClientSetSky                = 0x4F
	ToClientOverrideDayNightRatio = 0x50
	ToClientLocalPlayerAnimations = 0x51
	ToClientEyeOffset             = 0x52
	ToClientDeleteParticlespawner = 0x53
	ToClientCloudParams           = 0x54
	ToClientFadeSound             = 0x55
	ToClientUpdatePlayerList      = 0x56
	ToClientModchannelMsg         = 0x57
	ToClientModchannelSignal      = 0x58
	ToClientNodeMetaChanged       = 0x59
	ToClientSetSun                = 0x5A
	ToClientSetMoon               = 0x5B
	ToClientSetStars              = 0x5C
	ToClientSrpBytesSB            = 0x60
	ToClientFormspecPrepend       = 0x61
	ToClientMinimapModes          = 0x62
)

const (
	ToServerInit            = 0x02
	ToServerInit2           = 0x11
	ToServerModchannelJoin  = 0x17
	ToServerModchannelLeave = 0x18
	ToServerModchannelMsg   = 0x19
	ToServerPlayerPos       = 0x23
	ToServerGotblocks       = 0x24
	ToServerDeletedblocks   = 0x25
	ToServerInventoryAction = 0x31
	ToServerChatMessage     = 0x32
	ToServerDamage          = 0x35
	ToServerPlayerItem      = 0x37
	ToServerRespawn         = 0x38
	ToServerInteract        = 0x39
	ToServerRemovedSounds   = 0x3A
	ToServerNodeMetaFields  = 0x3B
	ToServerInventoryFields = 0x3C
	ToServerRequestMedia    = 0x40
	ToServerClientReady     = 0x43
	ToServerFirstSrp        = 0x50
	ToServerSrpBytesA       = 0x51
	ToServerSrpBytesM       = 0x52
)

const (
	AccessDeniedWrongPassword = iota
	AccessDeniedUnexpectedData
	AccessDeniedSingleplayer
	AccessDeniedWrongVersion
	AccessDeniedWrongCharsInName
	AccessDeniedWrongName
	AccessDeniedTooManyUsers
	AccessDeniedEmptyPassword
	AccessDeniedAlreadyConnected
	AccessDeniedServerFail
	AccessDeniedCustomString
	AccessDeniedShutdown
	AccessDeniedCrash
)

func processPktCommand(src, dst *Peer, pkt *Pkt) bool {
	if src.IsSrv() {
		switch cmd := binary.BigEndian.Uint16(pkt.Data[0:2]); cmd {
		case ToClientActiveObjectRemoveAdd:
			pkt.Data = processAoRmAdd(dst, pkt.Data)
			return false
		default:
			return false
		}
	} else {
		switch cmd := binary.BigEndian.Uint16(pkt.Data[0:2]); cmd {
		case ToServerChatMessage:
			return processChatMessage(src, *pkt)
		case ToServerClientReady:
			go processJoin(src)
			return false
		case ToServerFirstSrp:
			if src.sudoMode {
				src.sudoMode = false

				// This is a password change, save verifier and salt
				lenS := binary.BigEndian.Uint16(pkt.Data[2:4])
				s := pkt.Data[4 : 4+lenS]

				lenV := binary.BigEndian.Uint16(pkt.Data[4+lenS : 6+lenS])
				v := pkt.Data[6+lenS : 6+lenS+lenV]

				pwd := encodeVerifierAndSalt(s, v)

				db, err := initAuthDB()
				if err != nil {
					log.Print(err)
					return true
				}

				err = modAuthItem(db, string(src.username), pwd)
				if err != nil {
					log.Print(err)
					return true
				}

				db.Close()
			} else {
				log.Print("User " + string(src.username) + " at " + src.Addr().String() + " did not enter sudo mode before attempting to change the password")
			}
			return true
		case ToServerSrpBytesA:
			if !src.sudoMode {
				lenA := binary.BigEndian.Uint16(pkt.Data[2:4])
				A := pkt.Data[4 : 4+lenA]

				db, err := initAuthDB()
				if err != nil {
					log.Print(err)
					return true
				}

				pwd, err := readAuthItem(db, string(src.username))
				if err != nil {
					log.Print(err)
					return true
				}

				db.Close()

				s, v, err := decodeVerifierAndSalt(pwd)
				if err != nil {
					log.Print(err)
					return true
				}

				B, _, K, err := srp.Handshake(A, v)
				if err != nil {
					log.Print(err)
					return true
				}

				src.srp_s = s
				src.srp_A = A
				src.srp_B = B
				src.srp_K = K

				// Send SRP_BYTES_S_B
				data := make([]byte, 6+len(s)+len(B))
				data[0] = uint8(0x00)
				data[1] = uint8(ToClientSrpBytesSB)
				binary.BigEndian.PutUint16(data[2:4], uint16(len(s)))
				copy(data[4:4+len(s)], s)
				binary.BigEndian.PutUint16(data[4+len(s):6+len(s)], uint16(len(B)))
				copy(data[6+len(s):6+len(s)+len(B)], B)

				ack, err := src.Send(Pkt{Data: data})
				if err != nil {
					log.Print(err)
					return true
				}
				<-ack
			}
			return true
		case ToServerSrpBytesM:
			if !src.sudoMode {
				lenM := binary.BigEndian.Uint16(pkt.Data[2:4])
				M := pkt.Data[4 : 4+lenM]

				M2 := srp.CalculateM(src.username, src.srp_s, src.srp_A, src.srp_B, src.srp_K)

				if subtle.ConstantTimeCompare(M, M2) == 1 {
					// Password is correct
					// Enter sudo mode
					src.sudoMode = true

					// Send ACCEPT_SUDO_MODE
					data := []byte{uint8(0x00), uint8(ToClientAcceptSudoMode)}

					ack, err := src.Send(Pkt{Data: data})
					if err != nil {
						log.Print(err)
						return true
					}
					<-ack
				} else {
					// Client supplied wrong password
					log.Print("User " + string(src.username) + " at " + src.Addr().String() + " supplied wrong password for sudo mode")

					// Send DENY_SUDO_MODE
					data := []byte{uint8(0x00), uint8(ToClientDenySudoMode)}

					ack, err := src.Send(Pkt{Data: data})
					if err != nil {
						log.Print(err)
						return true
					}
					<-ack
				}
			}
			return true
		default:
			return false
		}
	}
	return false
}