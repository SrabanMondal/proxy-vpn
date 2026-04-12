package main

import (
	"encoding/hex"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/SrabanMondal/proxy-vpn/internal/client"
	"github.com/SrabanMondal/proxy-vpn/internal/protocol"
	"github.com/SrabanMondal/proxy-vpn/internal/protocol/codec"
	"github.com/SrabanMondal/proxy-vpn/internal/protocol/crypto"
	"github.com/SrabanMondal/proxy-vpn/internal/session"
	"github.com/joho/godotenv"
)

func main() {

	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
	SERVER_ADDR := os.Getenv("SERVER_ADDR")
	CODEC := os.Getenv("CODEC")
	CRYPTO := os.Getenv("CRYPTO")
	HEX_KEY := os.Getenv("KEY")
	CLIENT_ADDR := os.Getenv("CLIENT_ADDR")
	idleTimeout := parseIdleTimeout(os.Getenv("IDLE_TIMEOUT_SECONDS"), 120)

	serverAddr := SERVER_ADDR
	udpConn, err := net.Dial("udp", serverAddr)
	if err != nil {
		log.Fatal("failed to dial server UDP:", err)
	}

	registry := session.NewRegistry()
	err = codec.SetCodec(CODEC)
	if err != nil {
		panic(err)
	}

	key, err := hex.DecodeString(HEX_KEY)
	if err != nil {
		panic(err)
	}
	err = crypto.SetCrypto(CRYPTO, key)
	if err != nil {
		panic(err)
	}

	mux := client.NewMultiplexer(udpConn.(*net.UDPConn), 2000)
	mux.Start()
	defer mux.Stop()

	builder := protocol.NewBuilder()
	parser := protocol.NewParser()

	demux := client.NewDemultiplexer(udpConn.(*net.UDPConn), registry, parser)
	demux.Start()
	defer demux.Close()

	listener, err := net.Listen("tcp", CLIENT_ADDR)
	if err != nil {
		log.Fatal("failed to listen on ", CLIENT_ADDR, " : ", err)
	}
	log.Println("SOCKS5 proxy listening on ", CLIENT_ADDR)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("accept error:", err)
			continue
		}
		go client.HandleBrowserSession(conn, registry, mux, builder, idleTimeout)
	}
}

func parseIdleTimeout(raw string, defaultSeconds int) time.Duration {
	if raw == "" {
		return time.Duration(defaultSeconds) * time.Second
	}

	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return time.Duration(defaultSeconds) * time.Second
	}

	return time.Duration(v) * time.Second
}
