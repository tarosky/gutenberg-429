package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

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
	ipv4SubnetMask          net.IPMask
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
		&cli.UintFlag{
			Name:    "graceful-shutdown-timeout",
			Aliases: []string{"g"},
			Value:   5,
		},
		&cli.StringFlag{
			Name:    "host",
			Aliases: []string{"h"},
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

		cfg := &configure{
			window:                  c.Uint("window"),
			maxCount:                c.Uint("max-count"),
			ipv4SubnetMask:          net.CIDRMask(int(c.Uint("ipv4-subnet-mask")), 32),
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
			if err := ioutil.WriteFile(cfg.pidFile, pid, 0644); err != nil {
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
			OnExpiredSync: func(key, value string, tx *buntdb.Tx) error {
				log.Debug("expired", zap.String("masked", key))
				return nil
			},
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

	sigkill := make(chan os.Signal)
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
		e.log.Info("server started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			e.log.Panic("server finished abnormally", zap.Error(err))
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
		e.handleRequest(c, net.ParseIP(c.Query("ip")), c.Query("path"))
	})

	runServer(ctx, engine)

	e.log.Info("server exited")
}

func (e *environment) respondWithOK(c *gin.Context, ip, masked net.IP, path string, left uint) {
	e.log.Debug("response",
		zap.Int("status", 200),
		zap.String("ip", ip.String()),
		zap.String("masked", masked.String()),
		zap.String("path", path),
		zap.Uint("left", left))
	c.String(http.StatusOK, "")
	c.Writer.Flush()
}

func (e *environment) respondWithTooManyRequests(
	c *gin.Context,
	ip, masked net.IP,
	path string,
	left uint,
) {
	e.log.Debug("response",
		zap.Int("status", 429),
		zap.String("ip", ip.String()),
		zap.String("masked", masked.String()),
		zap.String("path", path),
		zap.Uint("left", left))
	c.String(http.StatusTooManyRequests, "")
	c.Writer.Flush()
}

func (e *environment) maskIP(ip net.IP) net.IP {
	masked := ip.Mask(e.ipv4SubnetMask)
	if masked == nil {
		return ip
	}

	return masked
}

func (e *environment) handleRequest(c *gin.Context, ip net.IP, path string) {
	masked := e.maskIP(ip)
	key := masked.String()
	now := time.Now().Unix()

	err := e.db.Update(func(tx *buntdb.Tx) error {
		val, err := tx.Get(key, true)
		if err != nil && err != buntdb.ErrNotFound {
			return err
		}

		if _, _, err := tx.Set(key, val, &buntdb.SetOptions{
			Expires: true,
			TTL:     time.Duration(e.window) * time.Second,
		}); err != nil {
			return err
		}
	})
}
