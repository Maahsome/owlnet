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
	c, err := p.Connect(hz, mode, 8)
	if err != nil {
		return nil, err
	}
	m := &MCP23S08{conn: c, addr: addr}
	_ = m.writeReg(regIOCON, 0x08) // HAEN=1
	_ = m.writeReg(regIPOL, 0x00)
	_ = m.writeReg(regGPPU, 0x00)
	_ = m.writeReg(regIODIR, 0xFF)
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

// ---------- Webhook dispatch ----------
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

// Simple JSON POST for Pushcut; adjust to your Pushcut setup if needed.
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

// helper: send trip log only to Slack webhooks
func sendTripSlackOnly(webhooks []Webhook, msg string) {
	for _, w := range webhooks {
		if strings.ToLower(w.Type) == "slack" {
			sendToSlack(w.URL, msg)
		}
	}
}

// ---------- Config (YAML) ----------
type ChannelConfig struct {
	Name           string    `yaml:"name"`            // Friendly name
	Bit            int       `yaml:"bit"`             // 0..7
	PairBit        *int      `yaml:"pairbit"`         // optional 0..7
	PairWindowSec  int       `yaml:"pair_window_sec"` // window to match pair
	PairMessage    string    `yaml:"pair_message"`    // message when pair completes
	Webhooks       []Webhook `yaml:"webhooks"`        // destinations
	MinimumAlerts  int       `yaml:"minimum_alerts"`  // N triggers required (0/1 => immediate)
	MinimumTimeSec int       `yaml:"minimum_time"`    // seconds window (0 => immediate)
	CoolingTimeSec int       `yaml:"cooling_time"`    // seconds between webhook sends (0 => none)
}

type cfg struct {
	DevPath     string          `yaml:"spi_dev"`       // e.g., /dev/spidev0.3
	Addr        uint8           `yaml:"mcp_addr"`      // 0..3
	BusSpeedKHz int             `yaml:"bus_speed_khz"` // e.g., 100
	DebounceMS  int             `yaml:"debounce_ms"`   // e.g., 150
	Edge        string          `yaml:"edge"`          // "rising" | "falling"
	Invert      bool            `yaml:"invert"`        // invert bits before edge detect
	ChannelCfg  []ChannelConfig `yaml:"channel_config"`
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
	return c
}

// ---------- Helpers ----------
type pairPending struct {
	when time.Time
}

type triggerHistory struct {
	times map[int][]time.Time // bit -> timestamps
}

func newTriggerHistory() *triggerHistory {
	return &triggerHistory{times: make(map[int][]time.Time)}
}

func (h *triggerHistory) qualifies(bit int, ch ChannelConfig, now time.Time) bool {
	// record first
	h.times[bit] = append(h.times[bit], now)

	// immediate if not configured
	if ch.MinimumAlerts <= 1 || ch.MinimumTimeSec <= 0 {
		h.trimBefore(bit, now.Add(-15*time.Minute))
		return true
	}

	win := time.Duration(ch.MinimumTimeSec) * time.Second
	cutoff := now.Add(-win)
	h.trimBefore(bit, cutoff)

	// Count entries >= cutoff
	n := 0
	for _, t := range h.times[bit] {
		if !t.Before(cutoff) {
			n++
		}
	}
	return n >= ch.MinimumAlerts
}

func (h *triggerHistory) trimBefore(bit int, cutoff time.Time) {
	ts := h.times[bit]
	if len(ts) == 0 {
		return
	}
	i := 0
	for i < len(ts) && ts[i].Before(cutoff) {
		i++
	}
	if i > 0 {
		ts = ts[i:]
	}
	if len(ts) > 1000 {
		ts = ts[len(ts)-1000:]
	}
	h.times[bit] = ts
}

func chanByBit(chs []ChannelConfig, bit int) *ChannelConfig {
	for i := range chs {
		if chs[i].Bit == bit {
			return &chs[i]
		}
	}
	return nil
}

// cooldown guard per channel bit
func passCooldown(last map[int]time.Time, ch ChannelConfig, bit int, now time.Time) bool {
	if ch.CoolingTimeSec <= 0 {
		return true
	}
	lastT, ok := last[bit]
	if !ok {
		return true
	}
	return now.Sub(lastT) >= time.Duration(ch.CoolingTimeSec)*time.Second
}

func markCooldown(last map[int]time.Time, bit int, now time.Time) {
	last[bit] = now
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

		pending    = map[int]pairPending{} // pending per-bit for pair logic
		hist       = newTriggerHistory()   // per-bit trigger history for thresholds
		lastNotify = map[int]time.Time{}   // per-bit cooldown tracking
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
						continue
					}

					// ---- Trip logging for D1..D4 (bits 0..3) ----
					if bit >= 0 && bit <= 3 {
						name := ch.Name
						if name == "" {
							name = fmt.Sprintf("Input %d", bit+1)
						}
						tripMsg := fmt.Sprintf("📟 Trip: %s (bit%d) @ %s", name, bit+1, now.Format(time.RFC3339))
						log.Println(tripMsg)
						// Send trip log only to Slack webhooks for this channel (no thresholds/cooldown here)
						sendTripSlackOnly(ch.Webhooks, tripMsg)
					}

					// ---- Paired channels ----
					if ch.PairBit != nil {
						pairBit := *ch.PairBit

						// See if pairBit is pending and within window
						if pp, ok := pending[pairBit]; ok {
							window := time.Duration(ch.PairWindowSec) * time.Second
							if window <= 0 {
								window = 60 * time.Second
							}
							if now.Sub(pp.when) <= window {
								// Threshold & cooldown for the *current* channel
								if !hist.qualifies(bit, *ch, now) {
									log.Printf("PAIR met but threshold not satisfied for %s (bit%d)", ch.Name, bit)
									delete(pending, pairBit)
									delete(pending, bit)
									continue
								}
								if !passCooldown(lastNotify, *ch, bit, now) {
									log.Printf("Cooling active for %s (bit%d) — skipping send", ch.Name, bit)
									delete(pending, pairBit)
									delete(pending, bit)
									continue
								}

								msg := ch.PairMessage
								if strings.TrimSpace(msg) == "" {
									msg = fmt.Sprintf("%s & bit%d pair matched", ch.Name, pairBit+1)
								}
								log.Printf("PAIR %s (bit%d<->bit%d) @ %s", ch.Name, bit, pairBit, now.Format(time.RFC3339))
								for _, w := range ch.Webhooks {
									sendViaWebhook(w, msg)
								}
								markCooldown(lastNotify, bit, now)
								delete(pending, pairBit)
								delete(pending, bit)
								continue
							}
							// stale pair — drop it and continue to set our pending below
							delete(pending, pairBit)
						}

						// Start/refresh our pending + record for thresholds
						pending[bit] = pairPending{when: now}
						_ = hist.qualifies(bit, *ch, now) // record only
						continue
					}

					// ---- Unpaired channels ----
					if !hist.qualifies(bit, *ch, now) {
						log.Printf("Threshold not yet met for %s (bit%d)", ch.Name, bit)
						continue
					}
					if !passCooldown(lastNotify, *ch, bit, now) {
						log.Printf("Cooling active for %s (bit%d) — skipping send", ch.Name, bit)
						continue
					}

					name := ch.Name
					if name == "" {
						name = fmt.Sprintf("Input %d", bit+1)
					}
					msg := fmt.Sprintf("🚨 Alert: %s @ %s", name, now.Format(time.RFC3339))
					for _, w := range ch.Webhooks {
						sendViaWebhook(w, msg)
					}
					log.Println(msg)
					markCooldown(lastNotify, bit, now)
				}
			}

			prev = effective
		}
	}
}
