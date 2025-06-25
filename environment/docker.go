package environment

import (
	"context"
	"strconv"
	"sync"

	"emperror.dev/errors"
	"github.com/apex/log"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"

	"github.com/pelican-dev/wings/config"
	"github.com/pelican-dev/wings/internal/cgroup"
)

var (
	_conce  sync.Once
	_client *client.Client
)

// Docker returns a docker client to be used throughout the codebase. Once a
// client has been created it will be returned for all subsequent calls to this
// function.
func Docker() (*client.Client, error) {
	var err error
	_conce.Do(func() {
		_client, err = client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	})
	return _client, errors.Wrap(err, "environment/docker: could not create client")
}

// ConfigureDocker configures the required network for the docker environment.
func ConfigureDocker(ctx context.Context) error {
	// Check cgroup compatibility first
	if err := checkCgroupCompatibility(); err != nil {
		return err
	}

	// Ensure the required docker network exists on the system.
	cli, err := Docker()
	if err != nil {
		return err
	}

	nw := config.Get().Docker.Network
	resource, err := cli.NetworkInspect(ctx, nw.Name, network.InspectOptions{})
	if err != nil {
		if !client.IsErrNotFound(err) {
			return err
		}

		log.Info("creating missing pelican0 interface, this could take a few seconds...")
		if err := createDockerNetwork(ctx, cli); err != nil {
			return err
		}
	}

	config.Update(func(c *config.Configuration) {
		c.Docker.Network.Driver = resource.Driver
		switch c.Docker.Network.Driver {
		case "host":
			c.Docker.Network.Interface = "127.0.0.1"
			c.Docker.Network.ISPN = false
		case "overlay":
			fallthrough
		case "weavemesh":
			c.Docker.Network.Interface = ""
			c.Docker.Network.ISPN = true
		default:
			c.Docker.Network.ISPN = false
		}
	})
	return nil
}

// Creates a new network on the machine if one does not exist already.
func createDockerNetwork(ctx context.Context, cli *client.Client) error {
	nw := config.Get().Docker.Network
	enableIPv6 := nw.IPv6 // get the value from the config file, todo add some logic to the IPAM interaface for that.
	_, err := cli.NetworkCreate(ctx, nw.Name, network.CreateOptions{
		Driver:     nw.Driver,
		EnableIPv6: &enableIPv6,
		Internal:   nw.IsInternal,
		IPAM: &network.IPAM{
			Config: []network.IPAMConfig{{
				Subnet:  nw.Interfaces.V4.Subnet,
				Gateway: nw.Interfaces.V4.Gateway,
			}, {
				Subnet:  nw.Interfaces.V6.Subnet,
				Gateway: nw.Interfaces.V6.Gateway,
			}},
		},
		Options: map[string]string{
			"encryption": "false",
			"com.docker.network.bridge.default_bridge":       "false",
			"com.docker.network.bridge.enable_icc":           strconv.FormatBool(nw.EnableICC),
			"com.docker.network.bridge.enable_ip_masquerade": "true",
			"com.docker.network.bridge.host_binding_ipv4":    "0.0.0.0",
			"com.docker.network.bridge.name":                 "pelican0",
			"com.docker.network.driver.mtu":                  strconv.FormatInt(nw.NetworkMTU, 10),
		},
	})
	if err != nil {
		return err
	}
	if nw.Driver != "host" && nw.Driver != "overlay" && nw.Driver != "weavemesh" {
		config.Update(func(c *config.Configuration) {
			c.Docker.Network.Interface = c.Docker.Network.Interfaces.V4.Gateway
		})
	}
	return nil
}

// checkCgroupCompatibility performs comprehensive cgroup compatibility checks
func checkCgroupCompatibility() error {
	cgroupInfo := cgroup.GetCgroupInfo()
	version := cgroup.DetectCgroupVersion()

	log.WithField("cgroup_version", version.String()).Info("detected cgroup version")

	switch version {
	case cgroup.CgroupV1:
		log.Debug("using cgroup v1 - checking controller availability")
		if controllers, ok := cgroupInfo["controllers"].([]string); ok {
			log.WithField("controllers", controllers).Debug("available cgroup v1 controllers")

			// Check for essential controllers
			required := []string{"memory", "cpu", "cpuacct", "blkio", "devices"}
			for _, req := range required {
				found := false
				for _, avail := range controllers {
					if avail == req {
						found = true
						break
					}
				}
				if !found {
					log.WithField("controller", req).Warn("required cgroup v1 controller not available")
				}
			}
		}

	case cgroup.CgroupV2:
		log.Debug("using cgroup v2 - checking unified hierarchy")

		if !cgroup.CheckCgroupV2MemoryAccounting() {
			log.Warn("cgroup v2 memory controller not available - memory limits may not work correctly")
			log.Warn("to enable memory accounting, add 'systemd.unified_cgroup_hierarchy=1 cgroup_enable=memory' to kernel parameters")
		}

		if controllers, ok := cgroupInfo["controllers"].([]string); ok {
			log.WithField("controllers", controllers).Debug("available cgroup v2 controllers")
		}

	case cgroup.CgroupUnknown:
		return errors.New("unable to detect cgroup version - container resource limits may not work")
	}

	// Check write permissions
	if !cgroup.CheckCgroupWritePermissions() {
		log.Warn("insufficient permissions to write to cgroup filesystem - some resource limits may not work")
	}

	return nil
}
