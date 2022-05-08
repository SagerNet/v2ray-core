package ssh

import (
	"bytes"
	"context"
	"encoding/base64"
	"math/rand"
	"strconv"
	"strings"
	"sync"

	"github.com/sagernet/sing/common/rw"
	core "github.com/v2fly/v2ray-core/v5"
	"github.com/v2fly/v2ray-core/v5/common"
	"github.com/v2fly/v2ray-core/v5/common/buf"
	"github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/common/retry"
	"github.com/v2fly/v2ray-core/v5/common/session"
	"github.com/v2fly/v2ray-core/v5/common/signal"
	"github.com/v2fly/v2ray-core/v5/common/task"
	"github.com/v2fly/v2ray-core/v5/features/policy"
	"github.com/v2fly/v2ray-core/v5/proxy"
	"github.com/v2fly/v2ray-core/v5/transport"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"golang.org/x/crypto/ssh"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		c := &Client{}
		return c, core.RequireFeatures(ctx, func(policyManager policy.Manager) error {
			return c.Init(config.(*Config), policyManager)
		})
	}))
}

var (
	_ proxy.Outbound  = (*Client)(nil)
	_ common.Closable = (*Client)(nil)
)

type Client struct {
	sync.Mutex
	config          *Config
	sessionPolicy   policy.Session
	server          net.Destination
	client          *ssh.Client
	auth            []ssh.AuthMethod
	hostKeyCallback ssh.HostKeyCallback
}

func randomVersion() string {
	version := "SSH-2.0-OpenSSH_"
	if rand.Intn(1) == 0 {
		version += "7." + strconv.Itoa(rand.Intn(10))
	} else {
		version += "8." + strconv.Itoa(rand.Intn(9))
	}
	return version
}

func (c *Client) Init(config *Config, policyManager policy.Manager) error {
	c.config = config
	c.sessionPolicy = policyManager.ForLevel(config.UserLevel)
	c.server = net.Destination{
		Network: net.Network_TCP,
		Address: config.Address.AsAddress(),
		Port:    net.Port(config.Port),
	}
	if config.User == "" {
		config.User = "root"
	}
	if config.HostKeyAlgorithms != nil && len(config.HostKeyAlgorithms) == 0 {
		config.HostKeyAlgorithms = nil
	}
	if config.ClientVersion == "" {
		config.ClientVersion = randomVersion()
	}

	if config.PrivateKey != "" {
		var signer ssh.Signer
		var err error
		if config.Password == "" {
			signer, err = ssh.ParsePrivateKey([]byte(config.PrivateKey))
		} else {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(config.PrivateKey), []byte(config.Password))
		}
		if err != nil {
			return newError("parse private key").Base(err)
		}
		c.auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else if config.Password != "" {
		c.auth = []ssh.AuthMethod{ssh.Password(config.Password)}
	}

	var keys []ssh.PublicKey
	if config.PublicKey != "" {
		for _, str := range strings.Split(config.PublicKey, "\n") {
			str = strings.TrimSpace(str)
			if str == "" {
				continue
			}
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(str))
			if err != nil {
				if err != nil {
					return newError(err, "parse public key").Base(err)
				}
			}
			keys = append(keys, key)
		}
	}
	if keys != nil {
		c.hostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			for _, pk := range keys {
				if bytes.Equal(key.Marshal(), pk.Marshal()) {
					return nil
				}
			}
			return newError("ssh host key mismatch, server send ", key.Type(), " ", base64.StdEncoding.EncodeToString(key.Marshal()))
		}
	} else {
		c.hostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			newError("please save server public key for verifying").AtWarning().WriteToLog()
			newError(key.Type(), " ", base64.StdEncoding.EncodeToString(key.Marshal())).AtWarning().WriteToLog()
			return nil
		}
	}
	return nil
}

func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified")
	}
	destination := outbound.Target
	network := destination.Network
	if network != net.Network_TCP {
		return newError("only TCP is supported in SSH proxy")
	}

	sc := c.client
	if sc == nil {
		c.Lock()
		sc = c.client
		if c.client == nil {
			client, err := c.connect(ctx, dialer)
			if err != nil {
				c.Unlock()
				return err
			}
			connElem := net.AddConnection(client)
			go func() {
				err = client.Wait()
				if err != nil {
					newError("ssh client closed").Base(err).AtDebug().WriteToLog()
				}
				c.Lock()
				c.client = nil
				c.Unlock()
				net.RemoveConnection(connElem)
			}()
			sc = client
		}
		c.Unlock()
	}

	conn, err := sc.Dial("tcp", destination.NetAddr())
	if err != nil {
		return newError("failed to open ssh proxy connection").Base(err)
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, c.sessionPolicy.Timeouts.ConnectionIdle)

	if err := task.Run(ctx, func() error {
		defer timer.SetTimeout(c.sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, buf.NewWriter(conn), buf.UpdateActivity(timer))
	}, func() error {
		defer timer.SetTimeout(c.sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(buf.NewReader(conn), link.Writer, buf.UpdateActivity(timer))
	}); err != nil {
		return newError("connection ends").Base(err)
	}

	return nil
}

func (c *Client) ProcessConn(ctx context.Context, conn net.Conn, dialer internet.Dialer) error {
	outbound := session.OutboundFromContext(ctx)
	if outbound == nil || !outbound.Target.IsValid() {
		return newError("target not specified")
	}
	destination := outbound.Target
	network := destination.Network
	if network != net.Network_TCP {
		return newError("only TCP is supported in SSH proxy")
	}

	sc := c.client
	if sc == nil {
		c.Lock()
		sc = c.client
		if c.client == nil {
			client, err := c.connect(ctx, dialer)
			if err != nil {
				c.Unlock()
				return err
			}
			connElem := net.AddConnection(client)
			go func() {
				err = client.Wait()
				if err != nil {
					newError("ssh client closed").Base(err).AtDebug().WriteToLog()
				}
				c.Lock()
				c.client = nil
				c.Unlock()
				net.RemoveConnection(connElem)
			}()
			sc = client
		}
		c.Unlock()
	}

	outboundConn, err := sc.Dial("tcp", destination.NetAddr())
	if err != nil {
		return newError("failed to open ssh proxy connection").Base(err)
	}

	return rw.CopyConn(ctx, conn, outboundConn)
}

func (c *Client) connect(ctx context.Context, dialer internet.Dialer) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User:              c.config.User,
		Auth:              c.auth,
		ClientVersion:     c.config.ClientVersion,
		HostKeyAlgorithms: c.config.HostKeyAlgorithms,
		HostKeyCallback:   c.hostKeyCallback,
		BannerCallback: func(message string) error {
			for _, line := range strings.Split(message, "\n") {
				newError("| ", line).AtDebug().WriteToLog(session.ExportIDToError(ctx))
			}
			return nil
		},
	}

	newError("open connection to ", c.server).AtDebug().WriteToLog(session.ExportIDToError(ctx))

	var conn internet.Connection
	err := retry.ExponentialBackoff(2, 100).On(func() error {
		rawConn, err := dialer.Dial(ctx, c.server)
		if err != nil {
			return err
		}
		conn = rawConn
		return nil
	})
	if err != nil {
		return nil, newError("failed to connect to ssh server").AtWarning().Base(err)
	}

	clientConn, chans, reqs, err := ssh.NewClientConn(conn, c.server.Address.String(), config)
	if err != nil {
		return nil, newError("failed to create ssh connection").Base(err)
	}

	client := ssh.NewClient(clientConn, chans, reqs)
	c.client = client
	return client, nil
}

func (c *Client) Close() error {
	sc := c.client
	if sc != nil {
		return sc.Close()
	}
	return nil
}
