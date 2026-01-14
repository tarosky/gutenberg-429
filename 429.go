package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/daemon"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/buntdb"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Provided by govvv at compile time
var Version string

type configure struct {
	window                  uint
	maxCount                uint
	ipv4SubnetMask          uint
	denyPrefixes            []netip.Prefix
	gracefulShutdownTimeout uint
	host                    string
	port                    int
	logPath                 string
	errorLogPath            string
	pidFile                 string
}

// Environment holds values needed to execute the entire program.
type environment struct {
	configure
	db  *buntdb.DB
	log *zap.Logger
}

// This implements zapcore.WriteSyncer interface.
type lockedFileWriteSyncer struct {
	m    sync.Mutex
	f    *os.File
	path string
}

func newLockedFileWriteSyncer(path string) *lockedFileWriteSyncer {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error while creating log file: path: %s", err.Error())
		panic(err)
	}

	return &lockedFileWriteSyncer{
		f:    f,
		path: path,
	}
}

func (s *lockedFileWriteSyncer) Write(bs []byte) (int, error) {
	s.m.Lock()
	defer s.m.Unlock()

	return s.f.Write(bs)
}

func (s *lockedFileWriteSyncer) Sync() error {
	s.m.Lock()
	defer s.m.Unlock()

	return s.f.Sync()
}

func (s *lockedFileWriteSyncer) reopen() {
	s.m.Lock()
	defer s.m.Unlock()

	if err := s.f.Close(); err != nil {
		fmt.Fprintf(
			os.Stderr, "error while reopening file: path: %s, err: %s", s.path, err.Error())
	}

	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		fmt.Fprintf(
			os.Stderr, "error while reopening file: path: %s, err: %s", s.path, err.Error())
		panic(err)
	}

	s.f = f
}

func (s *lockedFileWriteSyncer) Close() error {
	s.m.Lock()
	defer s.m.Unlock()

	return s.f.Close()
}

func createLogger(ctx context.Context, logPath, errorLogPath string) *zap.Logger {
	enc := zapcore.NewJSONEncoder(zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        zapcore.OmitKey,
		CallerKey:      zapcore.OmitKey,
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "message",
		StacktraceKey:  zapcore.OmitKey,
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	})

	out := newLockedFileWriteSyncer(logPath)
	errOut := newLockedFileWriteSyncer(errorLogPath)

	sigusr1 := make(chan os.Signal, 1)
	signal.Notify(sigusr1, syscall.SIGUSR1)

	go func() {
		for {
			select {
			case _, ok := <-sigusr1:
				if !ok {
					return
				}
				out.reopen()
				errOut.reopen()
			case <-ctx.Done():
				signal.Stop(sigusr1)
				// closing sigusr1 causes panic (close of closed channel)
				return
			}
		}
	}()

	return zap.New(
		zapcore.NewCore(enc, out, zap.NewAtomicLevelAt(zap.DebugLevel)),
		zap.ErrorOutput(errOut),
		zap.Development(),
		zap.WithCaller(false)).With(zap.String("version", Version))
}

func strsToPrefixes(strs []string) ([]netip.Prefix, error) {
	ps := make([]netip.Prefix, 0, len(strs))
	for _, s := range strs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		ps = append(ps, p.Masked())
	}
	return ps, nil
}

func main() {
	app := cli.NewApp()
	app.Name = "429"

	app.Flags = []cli.Flag{
		&cli.UintFlag{
			Name:    "window",
			Aliases: []string{"w"},
			Value:   30,
		},
		&cli.UintFlag{
			Name:    "max-count",
			Aliases: []string{"c"},
			Value:   30,
		},
		&cli.UintFlag{
			Name:    "ipv4-subnet-mask",
			Aliases: []string{"m"},
			Value:   24,
		},
		&cli.StringSliceFlag{
			Name:    "deny-iprange",
			Aliases: []string{"d"},
			Value:   cli.NewStringSlice(),
		},
		&cli.UintFlag{
			Name:    "graceful-shutdown-timeout",
			Aliases: []string{"g"},
			Value:   5,
		},
		&cli.StringFlag{
			Name:    "host",
			Aliases: []string{"H"},
			Value:   "0.0.0.0",
		},
		&cli.IntFlag{
			Name:    "port",
			Aliases: []string{"p"},
			Value:   8429,
		},
		&cli.StringFlag{
			Name:     "log-path",
			Aliases:  []string{"l"},
			Required: true,
		},
		&cli.StringFlag{
			Name:     "error-log-path",
			Aliases:  []string{"el"},
			Required: true,
		},
		&cli.StringFlag{
			Name:    "pid-file",
			Aliases: []string{"i"},
		},
	}

	app.Action = func(c *cli.Context) error {
		logPath, err := filepath.Abs(c.String("log-path"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to get log-path: %s", err.Error())
			panic(err)
		}

		errorLogPath, err := filepath.Abs(c.String("error-log-path"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to get error-log-path: %s", err.Error())
			panic(err)
		}

		denyPrefixes, err := strsToPrefixes(c.StringSlice("deny-iprange"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse deny-iprange: %s", err.Error())
			panic(err)
		}

		cfg := &configure{
			window:                  c.Uint("window"),
			maxCount:                c.Uint("max-count"),
			ipv4SubnetMask:          c.Uint("ipv4-subnet-mask"),
			denyPrefixes:            denyPrefixes,
			gracefulShutdownTimeout: c.Uint("graceful-shutdown-timeout"),
			host:                    c.String("host"),
			port:                    c.Int("port"),
			logPath:                 logPath,
			errorLogPath:            errorLogPath,
			pidFile:                 c.String("pid-file"),
		}
		log := createLogger(c.Context, cfg.logPath, cfg.errorLogPath)
		defer func() {
			if err := log.Sync(); err != nil {
				fmt.Fprintf(os.Stderr, "failed to sync log on exiting: %s", err.Error())
			}
		}()

		if cfg.pidFile != "" {
			pid := []byte(strconv.Itoa(os.Getpid()))
			if err := os.WriteFile(cfg.pidFile, pid, 0644); err != nil {
				log.Panic(
					"failed to create PID file",
					zap.String("path", cfg.pidFile),
					zap.Error(err))
			}

			defer func() {
				if err := os.Remove(cfg.pidFile); err != nil {
					log.Error(
						"failed to remove PID file",
						zap.String("path", cfg.pidFile),
						zap.Error(err))
				}
			}()
		}

		db, err := buntdb.Open(":memory:")
		if err != nil {
			panic(err)
		}
		db.SetConfig(buntdb.Config{
			AutoShrinkPercentage: 50,
			AutoShrinkMinSize:    500 * 1024,
		})
		defer db.Close()

		gin.SetMode(gin.ReleaseMode)
		e := &environment{
			configure: *cfg,
			db:        db,
			log:       log,
		}
		e.run(c.Context, e.runServer)

		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	sigkill := make(chan os.Signal, 1)
	signal.Notify(sigkill, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-sigkill
		signal.Stop(sigkill)
		close(sigkill)
		cancel()
	}()

	err := app.RunContext(ctx, os.Args)
	if err != nil {
		panic(err)
	}
}

func (e *environment) runServer(ctx context.Context, engine *gin.Engine) {
	srv := &http.Server{
		Addr:    e.host + ":" + strconv.Itoa(e.port),
		Handler: engine,
	}

	go func() {
		listen, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			e.log.Panic("server failed to listen", zap.Error(err))
			return
		}

		_, _ = daemon.SdNotify(false, daemon.SdNotifyReady)
		e.log.Info("server started")

		if err := srv.Serve(listen); err != nil {
			if err != http.ErrServerClosed {
				e.log.Panic("server finished abnormally", zap.Error(err))
			}
		}
	}()

	<-ctx.Done()

	ctx2, cancel := context.WithTimeout(
		context.Background(), time.Duration(e.gracefulShutdownTimeout)*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx2); err != nil {
		e.log.Panic("server forced to shutdown", zap.Error(err))
	}
}

func (e *environment) run(ctx context.Context, runServer func(context.Context, *gin.Engine)) {
	engine := gin.New()
	engine.Use(gin.Recovery())
	engine.GET("/", func(c *gin.Context) {
		e.handleRequest(c, c.Query("ip"), c.Query("path"))
	})

	runServer(ctx, engine)

	e.log.Info("server exited")
}

func (e *environment) respondWithOK(
	c *gin.Context,
	ip netip.Addr,
	masked netip.Prefix,
	path string,
	remaining uint,
) {
	e.log.Debug("response",
		zap.Int("status", http.StatusOK),
		zap.String("ip", ip.String()),
		zap.String("masked", masked.String()),
		zap.String("path", path),
		zap.Uint("remaining", remaining))
	c.String(http.StatusOK, "")
	c.Writer.Flush()
}

func (e *environment) respondWithTooManyRequests(
	c *gin.Context,
	ip netip.Addr,
	masked netip.Prefix,
	path string,
) {
	e.log.Debug("response",
		zap.Int("status", http.StatusTooManyRequests),
		zap.String("ip", ip.String()),
		zap.String("masked", masked.String()),
		zap.String("path", path),
		zap.Uint("remaining", 0))
	c.String(http.StatusTooManyRequests, "")
	c.Writer.Flush()
}

func (e *environment) respondWithForbidden(
	c *gin.Context,
	ip netip.Addr,
	deny netip.Prefix,
	path string,
) {
	e.log.Debug("response",
		zap.Int("status", http.StatusForbidden),
		zap.String("ip", ip.String()),
		zap.String("deny", deny.String()),
		zap.String("path", path))
	c.String(http.StatusForbidden, "")
	c.Writer.Flush()
}

func (e *environment) respondWithBadRequest(c *gin.Context, ipstr, path string) {
	e.log.Debug("response",
		zap.Int("status", http.StatusBadRequest),
		zap.String("ip", ipstr),
		zap.String("path", path))
	c.String(http.StatusBadRequest, "")
	c.Writer.Flush()
}

func (e *environment) respondWithInternalServerError(
	c *gin.Context,
	ip netip.Addr,
	masked netip.Prefix,
	path string,
	err error,
) {
	e.log.Debug("response",
		zap.Int("status", http.StatusInternalServerError),
		zap.String("ip", ip.String()),
		zap.String("masked", masked.String()),
		zap.String("path", path),
		zap.Error(err))
	c.String(http.StatusInternalServerError, "")
	c.Writer.Flush()
}

func (e *environment) maskIP(ip netip.Addr) netip.Prefix {
	if ip.Is4() {
		return netip.PrefixFrom(ip, int(e.ipv4SubnetMask)).Masked()
	}

	return netip.PrefixFrom(ip, ip.BitLen()).Masked()
}

func (e *environment) parseSeries(val string) ([]int64, error) {
	if val == "" {
		return make([]int64, 0, 1), nil
	}

	strs := strings.Split(val, ",")
	series := make([]int64, 0, len(strs)+1)
	for _, v := range strs {
		epoch, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, err
		}
		series = append(series, epoch)
	}

	return series, nil
}

func (e *environment) buildValue(series []int64) string {
	strs := make([]string, 0, len(series))
	for _, ep := range series {
		strs = append(strs, strconv.FormatInt(ep, 10))
	}

	return strings.Join(strs, ",")
}

func (e *environment) slideWindow(now int64, series []int64) []int64 {
	thresh := now - int64(e.window)
	idx := len(series) - 1
	for i, epoch := range series {
		if thresh < epoch {
			idx = i
			break
		}
	}

	return series[idx:]
}

func (e *environment) tooMany(series []int64) bool {
	return int(e.maxCount) < len(series)
}

func (e *environment) trim(series []int64) []int64 {
	outside := len(series) - int(e.maxCount)
	if outside < 0 {
		return series
	}

	return series[outside:]
}

func (e *environment) handleRequest(c *gin.Context, ipstr, path string) {
	ip, err := netip.ParseAddr(ipstr)
	if err != nil {
		e.respondWithBadRequest(c, ipstr, path)
		return
	}

	for _, p := range e.denyPrefixes {
		if p.Contains(ip) {
			e.respondWithForbidden(c, ip, p, path)
			return
		}
	}

	masked := e.maskIP(ip)
	key := masked.String()
	now := time.Now().Unix()
	var tooMany bool
	var remaining uint

	if err := e.db.Update(func(tx *buntdb.Tx) error {
		val, err := tx.Get(key, true)
		if err != nil && err != buntdb.ErrNotFound {
			return err
		}

		series, err := e.parseSeries(val)
		if err != nil {
			return err
		}

		// e.log.Debug("get",
		// 	zap.String("ip", ip.String()),
		// 	zap.String("masked", masked.String()),
		// 	zap.String("path", path),
		// 	zap.Int64s("series", series))

		series = e.slideWindow(now, append(series, now))
		tooMany = e.tooMany(series)
		series = e.trim(series)

		// This should not happen.
		if len(series) == 0 || int(e.maxCount) < len(series) {
			e.log.Fatal("incorrect series",
				zap.String("ip", ip.String()),
				zap.String("masked", masked.String()),
				zap.String("path", path),
				zap.Int64s("series", series))
		}

		remaining = e.maxCount - uint(len(series))

		if !tooMany {
			if _, _, err := tx.Set(key, e.buildValue(series), &buntdb.SetOptions{
				Expires: true,
				TTL:     time.Duration(e.window) * time.Second,
			}); err != nil {
				return err
			}
		}

		// e.log.Debug("set",
		// 	zap.String("ip", ip.String()),
		// 	zap.String("masked", masked.String()),
		// 	zap.String("path", path),
		// 	zap.Int64s("series", series))

		return nil
	}); err != nil {
		e.respondWithInternalServerError(c, ip, masked, path, err)
		return
	}

	if tooMany {
		e.respondWithTooManyRequests(c, ip, masked, path)
	} else {
		e.respondWithOK(c, ip, masked, path, remaining)
	}
}
