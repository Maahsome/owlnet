package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"periph.io/x/conn/v3/physic"
	"periph.io/x/conn/v3/spi"
	"periph.io/x/conn/v3/spi/spireg"
	"periph.io/x/host/v3"
)

// ---------- MCP23S08 ----------
const (
	regIODIR = 0x00
	regIPOL  = 0x01
	regGPPU  = 0x06
	regIOCON = 0x05
	regGPIO  = 0x09
)

func opcode(addr uint8, read bool) byte {
	op := byte(0x40 | ((addr & 0x3) << 1)) // 0100 A1 A0 R/W
	if read {
		op |= 0x01
	}
	return op
}

type MCP23S08 struct {
	conn spi.Conn
	addr uint8
}

func NewMCP23S08(p spi.PortCloser, addr uint8, hz physic.Frequency, mode spi.Mode) (*MCP23S08, error) {
	c, err := p.Connect(hz, mode, 8)
	if err != nil {
		return nil, err
	}
	m := &MCP23S08{conn: c, addr: addr}
	// Safe init
	_ = m.writeReg(regIOCON, 0x08) // HAEN=1
	_ = m.writeReg(regIPOL, 0x00)  // no inversion
	_ = m.writeReg(regGPPU, 0x00)  // no pull-ups
	_ = m.writeReg(regIODIR, 0xFF) // all inputs
	return m, nil
}

func (m *MCP23S08) writeReg(reg byte, val byte) error {
	tx := []byte{opcode(m.addr, false), reg, val}
	rx := make([]byte, len(tx))
	return m.conn.Tx(tx, rx)
}
func (m *MCP23S08) readReg(reg byte) (byte, error) {
	tx := []byte{opcode(m.addr, true), reg, 0x00}
	rx := make([]byte, len(tx))
	if err := m.conn.Tx(tx, rx); err != nil {
		return 0, err
	}
	return rx[2], nil
}
func (m *MCP23S08) ReadGPIO() (byte, error) { return m.readReg(regGPIO) }

// ---------- Webhook dispatch (stubs you can expand) ----------
type Webhook struct {
	Type string `yaml:"type"` // "slack", "pushcut", ...
	URL  string `yaml:"url"`
}

func sendViaWebhook(w Webhook, msg string) {
	switch strings.ToLower(w.Type) {
	case "slack":
		sendToSlack(w.URL, msg)
	case "pushcut":
		sendToPushcut(w.URL, msg)
	default:
		log.Printf("unknown webhook type %q, skipping", w.Type)
	}
}

func sendToSlack(url, msg string) {
	if url == "" {
		return
	}
	body, _ := json.Marshal(map[string]string{"text": msg})
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("slack send error: %v", err)
		return
	}
	_ = resp.Body.Close()
}

// Pushcut supports inbound webhooks (usually POST JSON or GET with params).
// This is a simple JSON POST; adjust to your Pushcut configuration if needed.
func sendToPushcut(url, msg string) {
	if url == "" {
		return
	}
	body, _ := json.Marshal(map[string]string{"message": msg})
	req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("pushcut send error: %v", err)
		return
	}
	_ = resp.Body.Close()
}

// ---------- Config (YAML) ----------
type ChannelConfig struct {
	Name          string    `yaml:"name"`            // Friendly name
	Bit           int       `yaml:"bit"`             // 0..7
	PairBit       *int      `yaml:"pairbit"`         // optional 0..7
	PairWindowSec int       `yaml:"pair_window_sec"` // window to match pair
	PairMessage   string    `yaml:"pair_message"`    // message when pair completes
	Webhooks      []Webhook `yaml:"webhooks"`        // where to send alerts for this channel
}

type cfg struct {
	DevPath     string          `yaml:"spi_dev"`        // e.g., /dev/spidev0.3
	Addr        uint8           `yaml:"mcp_addr"`       // 0..3
	BusSpeedKHz int             `yaml:"bus_speed_khz"`  // e.g., 100
	DebounceMS  int             `yaml:"debounce_ms"`    // e.g., 150
	Edge        string          `yaml:"edge"`           // "rising" | "falling"
	Invert      bool            `yaml:"invert"`         // invert bits before edge detect
	ChannelCfg  []ChannelConfig `yaml:"channel_config"` // new structure
}

func defaultCfg() cfg {
	return cfg{
		DevPath:     "/dev/spidev0.3",
		Addr:        0,
		BusSpeedKHz: 100,
		DebounceMS:  150,
		Edge:        "rising",
		Invert:      false,
		ChannelCfg:  []ChannelConfig{},
	}
}

func loadCfg() cfg {
	path := os.Getenv("CONFIG_FILE")
	if path == "" {
		path = "./config.yaml"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Printf("⚠️ Could not read config file %s; using defaults (%v)", path, err)
		return defaultCfg()
	}
	var c cfg
	if err := yaml.Unmarshal(raw, &c); err != nil {
		log.Fatalf("parse yaml: %v", err)
	}
	def := defaultCfg()
	if c.DevPath == "" {
		c.DevPath = def.DevPath
	}
	if c.BusSpeedKHz == 0 {
		c.BusSpeedKHz = def.BusSpeedKHz
	}
	if c.DebounceMS == 0 {
		c.DebounceMS = def.DebounceMS
	}
	if c.Edge == "" {
		c.Edge = def.Edge
	}
	return c
}

// ---------- Helpers ----------
type pairPending struct {
	when time.Time
}

// returns the channel config for a bit, or nil if not found
func chanByBit(chs []ChannelConfig, bit int) *ChannelConfig {
	for i := range chs {
		if chs[i].Bit == bit {
			return &chs[i]
		}
	}
	return nil
}

func main() {
	cfg := loadCfg()

	if _, err := host.Init(); err != nil {
		log.Fatalf("periph init: %v", err)
	}

	p, err := spireg.Open(cfg.DevPath)
	if err != nil {
		log.Fatalf("open spi (%s): %v", cfg.DevPath, err)
	}
	defer p.Close()

	busHz := physic.KiloHertz * physic.Frequency(cfg.BusSpeedKHz)
	mcp, err := NewMCP23S08(p, cfg.Addr, busHz, spi.Mode0)
	if err != nil {
		log.Fatalf("mcp init: %v", err)
	}

	log.Printf("Monitoring %s addr=%d @ %s (EDGE=%s INVERT=%v)…",
		cfg.DevPath, cfg.Addr, busHz, cfg.Edge, cfg.Invert)

	var (
		prev          byte
		lastEventTime [8]time.Time
		debounce      = time.Duration(cfg.DebounceMS) * time.Millisecond
		ticker        = time.NewTicker(20 * time.Millisecond)

		// pending map per bit for pair logic
		pending = map[int]pairPending{}
	)
	defer ticker.Stop()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Exiting.")
			return

		case <-ticker.C:
			g, err := mcp.ReadGPIO()
			if err != nil {
				log.Printf("read gpio: %v", err)
				continue
			}

			// Optional inversion
			effective := g
			if cfg.Invert {
				effective = ^g
			}

			var edges byte
			switch strings.ToLower(cfg.Edge) {
			case "falling":
				edges = (effective ^ prev) & prev // 1->0
			default:
				edges = (effective ^ prev) & effective // 0->1
			}

			if edges != 0 {
				now := time.Now()

				// Handle all bits that changed
				for bit := 0; bit < 8; bit++ {
					mask := byte(1 << bit)
					if edges&mask == 0 {
						continue
					}
					if now.Sub(lastEventTime[bit]) < debounce {
						continue
					}
					lastEventTime[bit] = now

					ch := chanByBit(cfg.ChannelCfg, bit)
					if ch == nil {
						// No defined channel for this bit -> skip silently
						continue
					}

					// Pair logic if configured
					if ch.PairBit != nil {
						pairBit := *ch.PairBit
						// prune stale pending for our own bit (optional)
						if pp, ok := pending[bit]; ok {
							// If your design needs expiry here, you can add it; for now, leave as-is.
							_ = pp
						}

						// If pair was already pending and within this channel's window -> send pair message
						if pp, ok := pending[pairBit]; ok {
							window := time.Duration(ch.PairWindowSec) * time.Second
							if window <= 0 {
								window = 60 * time.Second
							}
							if now.Sub(pp.when) <= window {
								msg := ch.PairMessage
								if strings.TrimSpace(msg) == "" {
									// Fallback if not provided
									msg = fmt.Sprintf("%s & Bit%d pair matched", ch.Name, pairBit+1)
								}
								log.Printf("PAIR %s (bit%d<->bit%d) @ %s", ch.Name, bit, pairBit, now.Format(time.RFC3339))
								for _, w := range ch.Webhooks {
									sendViaWebhook(w, msg)
								}
								// consume BOTH sides
								delete(pending, pairBit)
								delete(pending, bit)
								continue
							}
							// pair entry is stale -> replace with this one below
							delete(pending, pairBit)
						}

						// No valid pair yet: start/refresh our pending timer
						pending[bit] = pairPending{when: now}
						continue // do not send single alert for paired channels
					}

					// Not a paired channel: send standard alert with its name
					name := ch.Name
					if name == "" {
						name = fmt.Sprintf("Input %d", bit+1)
					}
					msg := fmt.Sprintf("🚨 Alert: %s @ %s", name, now.Format(time.RFC3339))
					for _, w := range ch.Webhooks {
						sendViaWebhook(w, msg)
					}
					log.Println(msg)
				}
			}

			prev = effective
		}
	}
}
