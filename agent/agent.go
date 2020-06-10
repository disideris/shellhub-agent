package main

import (
	"crypto/rsa"
	"os"
        "bytes"
        "os/exec"
        "strings"

	"github.com/shellhub-io/shellhub/agent/pkg/keygen"
	"github.com/shellhub-io/shellhub/agent/pkg/sysinfo"
	"github.com/shellhub-io/shellhub/pkg/models"
	"github.com/sirupsen/logrus"
)

type Agent struct {
	opts     *ConfigOptions
	pubKey   *rsa.PublicKey
	Identity *models.DeviceIdentity
	Info     *models.DeviceInfo
}

func NewAgent() (*Agent, error) {
	identity, err := getDeviceIdentity()
	if err != nil {
		return nil, err
	}

	info, err := getDeviceInfo()
	if err != nil {
		return nil, err
	}

	return &Agent{Identity: identity, Info: info}, nil
}

func (a *Agent) generatePrivateKey() error {
	if _, err := os.Stat(a.opts.PrivateKey); os.IsNotExist(err) {
		logrus.Info("Private key not found. Generating...")
		err := keygen.GeneratePrivateKey(a.opts.PrivateKey)
		if err != nil {
			return err
		}
	}

	return nil
}

func (a *Agent) readPublicKey() error {
	key, err := keygen.ReadPublicKey(a.opts.PrivateKey)
	a.pubKey = key
	return err
}

func getDeviceIdentity() (*models.DeviceIdentity, error) {
	//d := &models.DeviceIdentity{}

	//iface, err := sysinfo.PrimaryInterface()
	//if err != nil {
	//	return nil, err
	//}

	//d.MAC = iface.HardwareAddr.String()

        c1 := exec.Command("cat", "/proc/cpuinfo")
        c2 := exec.Command("grep", "Serial")

        r, w := io.Pipe() 
        c1.Stdout = w
        c2.Stdin = r

        var b2 bytes.Buffer
        c2.Stdout = &b2

        c1.Start()
        c2.Start()
        c1.Wait()
        w.Close()
        c2.Wait()

        s := b2.String()

        s2 := strings.Split(s, ":")
        s3 := strings.Split(s2[1], " ")
        d.MAC = s3[1]

	return d, nil
}

func getDeviceInfo() (*models.DeviceInfo, error) {
	osrelease, err := sysinfo.GetOSRelease()
	if err != nil {
		return nil, err
	}

	return &models.DeviceInfo{ID: osrelease.ID, PrettyName: osrelease.Name}, nil
}
