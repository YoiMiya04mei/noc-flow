package listener

import (
	"log"
	"net"
	"sync/atomic"

	"github.com/jdp-platform/noc-flow-collector/pkg/model"
	"github.com/jdp-platform/noc-flow-collector/pkg/protocol/ipfix"
	"github.com/jdp-platform/noc-flow-collector/pkg/protocol/netflow5"
	"github.com/jdp-platform/noc-flow-collector/pkg/protocol/netflow9"
	"github.com/jdp-platform/noc-flow-collector/pkg/protocol/sflow5"
	"github.com/jdp-platform/noc-flow-collector/pkg/sink"
)

type UDPListener struct {
	addr        string
	format      string
	siteID      string
	sink        *sink.ClickHouseSink
	metrics     *model.CollectorMetrics
	workerCount int
	bufferChan  chan []byte
	conn        *net.UDPConn
	stopCh      chan struct{}
}

func NewUDPListener(addr, format, siteID string, chSink *sink.ClickHouseSink, metrics *model.CollectorMetrics, workerCount, bufferSize int) *UDPListener {
	return &UDPListener{
		addr:        addr,
		format:      format,
		siteID:      siteID,
		sink:        chSink,
		metrics:     metrics,
		workerCount: workerCount,
		bufferChan:  make(chan []byte, bufferSize),
		stopCh:      make(chan struct{}),
	}
}

func (l *UDPListener) Start() error {
	udpAddr, err := net.ResolveUDPAddr("udp", l.addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	l.conn = conn

	log.Printf("[Collector] Listening for %s on UDP %s (Site: %s)", l.format, l.addr, l.siteID)

	// Launch worker pool
	for w := 0; w < l.workerCount; w++ {
		go l.worker()
	}

	// Packet receive loop
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-l.stopCh:
				return
			default:
				n, remoteAddr, err := l.conn.ReadFrom(buf)
				if err != nil {
					continue
				}
				atomic.AddUint64(&l.metrics.PacketsReceived, 1)

				pktCopy := make([]byte, n)
				copy(pktCopy, buf[:n])

				select {
				case l.bufferChan <- pktCopy:
				default:
					atomic.AddUint64(&l.metrics.DroppedPackets, 1)
				}

				_ = remoteAddr
			}
		}
	}()

	return nil
}

func (l *UDPListener) worker() {
	for pkt := range l.bufferChan {
		var records []model.FlowRecord
		var err error

		switch l.format {
		case "netflow5":
			records, err = netflow5.Parse(pkt, "127.0.0.1", l.siteID)
		case "netflow9":
			records, err = netflow9.Parse(pkt, "127.0.0.1", l.siteID)
		case "ipfix":
			records, err = ipfix.Parse(pkt, "127.0.0.1", l.siteID)
		case "sflow5":
			records, err = sflow5.Parse(pkt, "127.0.0.1", l.siteID)
		}

		if err != nil {
			atomic.AddUint64(&l.metrics.ParseErrors, 1)
			continue
		}

		if len(records) > 0 {
			atomic.AddUint64(&l.metrics.FlowsParsed, uint64(len(records)))
			l.sink.Ingest(records)
		}
	}
}

func (l *UDPListener) Stop() {
	close(l.stopCh)
	if l.conn != nil {
		l.conn.Close()
	}
}
