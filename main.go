package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
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
	c, err := p.Connect(hz, mode, 8) // physic.Frequency accepted directly
	if err != nil {
		return nil, err
	}
	m := &MCP23S08{conn: c, addr: addr}
	// Safe init (board front-end handles conditioning; no pulls/inversion needed)
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

// ---------- Alerts ----------
var (
	slackWebhook = os.Getenv("SLACK_WEBHOOK_URL")
	pushCutWebhook = os.Getenv("PUSHCUT_WEBHOOK_URL")

	twilioSID   = os.Getenv("TWILIO_SID")
	twilioToken = os.Getenv("TWILIO_TOKEN")
	twilioFrom  = os.Getenv("TWILIO_FROM")
	twilioTo    = os.Getenv("TWILIO_TO")
)

func sendPushCut(msg string) {
	if pushCutWebhook == "" {
		return
	}
	body, _ := json.Marshal(map[string]string{"text": msg, "title": "Driveway Alert"})
	req, _ := http.NewRequest("POST", pushCutWebhook, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("pushcut: %v", err)
		return
	}
	_ = resp.Body.Close()
}

func sendSlack(msg string) {
	if slackWebhook == "" {
		return
	}
	body, _ := json.Marshal(map[string]string{"text": msg})
	req, _ := http.NewRequest("POST", slackWebhook, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("slack: %v", err)
		return
	}
	_ = resp.Body.Close()
}

func urlEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' || c == ' ' {
			if c == ' ' {
				b.WriteByte('+')
			} else {
				b.WriteByte(c)
			}
		} else {
			b.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return b.String()
}

func sendSMS(msg string) {
	if twilioSID == "" || twilioToken == "" || twilioFrom == "" || twilioTo == "" {
		return
	}
	url := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", twilioSID)
	data := fmt.Sprintf("From=%s&To=%s&Body=%s", twilioFrom, twilioTo, urlEncode(msg))
	req, _ := http.NewRequest("POST", url, bytes.NewBufferString(data))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(twilioSID, twilioToken)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("twilio: %v", err)
		return
	}
	_ = resp.Body.Close()
}

// ---------- Config (YAML) ----------
type cfg struct {
	DevPath        string   `yaml:"spi_dev"`        // e.g., /dev/spidev0.3
	Addr           uint8    `yaml:"mcp_addr"`       // 0..3
	BusSpeedKHz    int      `yaml:"bus_speed_khz"`  // e.g., 100
	DebounceMS     int      `yaml:"debounce_ms"`    // e.g., 150
	ChannelNames   []string `yaml:"channel_names"`  // 8 names; auto-filled if fewer
	Edge           string   `yaml:"edge"`           // "rising" (0->1) or "falling" (1->0)
	Invert         bool     `yaml:"invert"`         // invert bits before edge detect
	PairWindowSec  int      `yaml:"pair_window_sec"`// window for D3/D4 pairing (default 60)
	EnteringMsg    string   `yaml:"entering_message"`
	LeavingMsg     string   `yaml:"leaving_message"`
}

func defaultCfg() cfg {
	return cfg{
		DevPath:       "/dev/spidev0.3",
		Addr:          0,
		BusSpeedKHz:   100,
		DebounceMS:    150,
		ChannelNames:  []string{"Zone 1 (D1)", "Zone 2 (D2)", "Zone 3 (D3)", "Zone 4 (D4)", "Input 5", "Input 6", "Input 7", "Input 8"},
		Edge:          "rising",
		Invert:        false,
		PairWindowSec: 60,
		EnteringMsg:   "Entering the Driveway",
		LeavingMsg:    "Leaving the Driveway",
	}
}

func loadCfg() cfg {
	path := os.Getenv("CONFIG_FILE")
	if path == "" {
		path = "./config.yaml"
	}
	raw, err := ioutil.ReadFile(path)
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
	if c.PairWindowSec <= 0 {
		c.PairWindowSec = def.PairWindowSec
	}
	if c.EnteringMsg == "" {
		c.EnteringMsg = def.EnteringMsg
	}
	if c.LeavingMsg == "" {
		c.LeavingMsg = def.LeavingMsg
	}
	// Ensure 8 names
	if len(c.ChannelNames) < 8 {
		for i := len(c.ChannelNames); i < 8; i++ {
			c.ChannelNames = append(c.ChannelNames, def.ChannelNames[i])
		}
	}
	return c
}

func main() {
	cfg := loadCfg()

	if _, err := host.Init(); err != nil {
		log.Fatalf("periph init: %v", err)
	}

	sendPushCut("Starting Owlnet")
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

	log.Printf("Monitoring %s addr=%d @ %s (EDGE=%s INVERT=%v, PairWindow=%ds)…",
		cfg.DevPath, cfg.Addr, busHz, cfg.Edge, cfg.Invert, cfg.PairWindowSec)

	var (
		prev          byte
		lastEventTime [8]time.Time
		debounce      = time.Duration(cfg.DebounceMS) * time.Millisecond
		ticker        = time.NewTicker(20 * time.Millisecond)

		// Pairing state for D3 (bit2) & D4 (bit3)
		pendingD3 time.Time
		pendingD4 time.Time
		window    = time.Duration(cfg.PairWindowSec) * time.Second
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

			// Normalize if requested
			effective := g
			if cfg.Invert {
				effective = ^g
			}

			var edges byte
			switch strings.ToLower(cfg.Edge) {
			case "falling":
				edges = (effective ^ prev) & prev // 1 -> 0
			default: // rising
				edges = (effective ^ prev) & effective // 0 -> 1
			}

			if edges != 0 {
				now := time.Now()

				// Handle D3/D4 pairing first (suppress individual alerts for these two)
				const d3bit = 2 // D3 = bit 2
				const d4bit = 3 // D4 = bit 3

				// Prune stale pendings
				if !pendingD3.IsZero() && now.Sub(pendingD3) > window {
					pendingD3 = time.Time{}
				}
				if !pendingD4.IsZero() && now.Sub(pendingD4) > window {
					pendingD4 = time.Time{}
				}

				// D4 fired?
				if edges&(1<<d4bit) != 0 && now.Sub(lastEventTime[d4bit]) >= debounce {
					lastEventTime[d4bit] = now
					if !pendingD3.IsZero() && now.Sub(pendingD3) <= window {
						// D3 was first -> Leaving
						name := cfg.ChannelNames[d4bit]
						otherName := cfg.ChannelNames[d3bit]
						dur := now.Sub(pendingD3)
						msg := fmt.Sprintf("🚨 Sensor Tripped: %s @ %s, %s tripped %.2f ago", name, now.Format(time.RFC3339), otherName, dur.Seconds())
						sendSlack(msg)
						msg = fmt.Sprintf("🚗 %s @ %s", cfg.LeavingMsg, now.Format(time.RFC3339))
						log.Println(msg)
						sendPushCut(msg)
						sendSlack(msg)
						sendSMS(msg)
						// consume both
						pendingD3, pendingD4 = time.Time{}, time.Time{}
					} else {
						// start/refresh pending D4
						name := cfg.ChannelNames[d4bit]
						otherName := cfg.ChannelNames[d3bit]
						dur := now.Sub(pendingD3)
						msg := fmt.Sprintf("🚨 Sensor Tripped: %s @ %s, %s tripped %.2f ago", name, now.Format(time.RFC3339), otherName, dur.Seconds())
						log.Println(msg)
						// sendPushCut(msg)
						sendSlack(msg)
						sendSMS(msg)
						pendingD4 = now
					}
				}

				// D3 fired?
				if edges&(1<<d3bit) != 0 && now.Sub(lastEventTime[d3bit]) >= debounce {
					lastEventTime[d3bit] = now
					if !pendingD4.IsZero() && now.Sub(pendingD4) <= window {
						// D4 was first -> Entering
						name := cfg.ChannelNames[d3bit]
						otherName := cfg.ChannelNames[d4bit]
						dur := now.Sub(pendingD4)
						msg := fmt.Sprintf("🚨 Sensor Tripped: %s @ %s, %s tripped %.2f ago", name, now.Format(time.RFC3339), otherName, dur.Seconds())
						sendSlack(msg)
						msg = fmt.Sprintf("🏠 %s @ %s", cfg.EnteringMsg, now.Format(time.RFC3339))
						log.Println(msg)
						sendPushCut(msg)
						sendSlack(msg)
						sendSMS(msg)
						// consume both
						pendingD3, pendingD4 = time.Time{}, time.Time{}
					} else {
						// start/refresh pending D3
						name := cfg.ChannelNames[d3bit]
						otherName := cfg.ChannelNames[d4bit]
						dur := now.Sub(pendingD4)
						msg := fmt.Sprintf("🚨 Sensor Tripped: %s @ %s, %s tripped %.2f ago", name, now.Format(time.RFC3339), otherName, dur.Seconds())
						log.Println(msg)
						// sendPushCut(msg)
						sendSlack(msg)
						sendSMS(msg)
						pendingD3 = now
					}
				}

				// Handle the rest (all bits except 2 and 3)
				for bit := 0; bit < 8; bit++ {
					if bit == d3bit || bit == d4bit {
						continue // skip; handled by pairing above
					}
					mask := byte(1 << bit)
					if edges&mask == 0 {
						continue
					}
					if now.Sub(lastEventTime[bit]) < debounce {
						continue
					}
					lastEventTime[bit] = now

					name := fmt.Sprintf("Input %d", bit+1)
					if bit >= 0 && bit < len(cfg.ChannelNames) && cfg.ChannelNames[bit] != "" {
						name = cfg.ChannelNames[bit]
					}
					msg := fmt.Sprintf("🚨 Driveway alert: %s @ %s", name, now.Format(time.RFC3339))
					log.Println(msg)
					sendSlack(msg)
					sendSMS(msg)
				}
			}

			prev = effective
		}
	}
}

