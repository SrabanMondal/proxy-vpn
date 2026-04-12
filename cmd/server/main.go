package main

import (
	"encoding/hex"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/SrabanMondal/proxy-vpn/internal/protocol"
	"github.com/SrabanMondal/proxy-vpn/internal/protocol/codec"
	"github.com/SrabanMondal/proxy-vpn/internal/protocol/crypto"
	"github.com/SrabanMondal/proxy-vpn/internal/server"
	"github.com/SrabanMondal/proxy-vpn/internal/session"
	"github.com/joho/godotenv"
)

func main() {

	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	SERVER_PORT := os.Getenv("SERVER_PORT")
	CODEC := os.Getenv("CODEC")
	CRYPTO := os.Getenv("CRYPTO")
	HEX_KEY := os.Getenv("KEY")
	idleTimeout := parseIdleTimeout(os.Getenv("IDLE_TIMEOUT_SECONDS"), 120)

	udpAddr, err := net.ResolveUDPAddr("udp", ":"+SERVER_PORT)
	if err != nil {
		log.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer udpConn.Close()

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

	mux := server.NewMultiplexer(udpConn, 5000)
	mux.Start()
	defer mux.Stop()

	builder := protocol.NewBuilder()
	parser := protocol.NewParser()

	// limiter := server.NewTokenBucket(10*1024*1024, 1*1024*1024)

	// manager := server.NewSessionManager(registry, mux, builder, limiter)

	demux := server.NewDemultiplexer(udpConn, registry, parser, mux, builder, idleTimeout)
	demux.Start()

	log.Println("VPN server listening on UDP :", SERVER_PORT)

	// Block until shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("shutting down server...")
	demux.Close()
	mux.Stop()
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
