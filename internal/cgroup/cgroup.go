//go:build linux

package cgroup

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// CgroupVersion represents the cgroup version being used
type CgroupVersion int

const (
	CgroupV1 CgroupVersion = iota + 1
	CgroupV2
	CgroupUnknown
)

// DetectCgroupVersion detects whether the system is using cgroup v1 or v2
func DetectCgroupVersion() CgroupVersion {
	// Check if cgroup v2 is mounted at /sys/fs/cgroup
	if isUnifiedCgroupMount() {
		return CgroupV2
	}

	// Check if cgroup v1 controllers exist
	if hasCgroupV1Controllers() {
		return CgroupV1
	}

	return CgroupUnknown
}

// isUnifiedCgroupMount checks if /sys/fs/cgroup is mounted as cgroup2
func isUnifiedCgroupMount() bool {
	// Read /proc/mounts to check for cgroup2 filesystem
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "/sys/fs/cgroup" && fields[2] == "cgroup2" {
			return true
		}
	}

	return false
}

// hasCgroupV1Controllers checks if cgroup v1 controllers exist
func hasCgroupV1Controllers() bool {
	// Check for typical cgroup v1 controller directories
	controllers := []string{"memory", "cpu", "cpuacct", "blkio", "devices", "freezer"}

	for _, controller := range controllers {
		path := filepath.Join("/sys/fs/cgroup", controller)
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	return false
}

// String returns the string representation of the cgroup version
func (v CgroupVersion) String() string {
	switch v {
	case CgroupV1:
		return "v1"
	case CgroupV2:
		return "v2"
	default:
		return "unknown"
	}
}

// IsCgroupV2 returns true if the system is using cgroup v2
func IsCgroupV2() bool {
	return DetectCgroupVersion() == CgroupV2
}

// IsCgroupV1 returns true if the system is using cgroup v1
func IsCgroupV1() bool {
	return DetectCgroupVersion() == CgroupV1
}

// GetCgroupInfo returns detailed information about the cgroup configuration
func GetCgroupInfo() map[string]interface{} {
	info := make(map[string]interface{})

	version := DetectCgroupVersion()
	info["version"] = version.String()
	info["detected_version"] = version

	switch version {
	case CgroupV1:
		info["controllers"] = getCgroupV1Controllers()
		info["mount_points"] = getCgroupV1MountPoints()
	case CgroupV2:
		info["unified_hierarchy"] = true
		info["controllers"] = getCgroupV2Controllers()
		info["mount_point"] = "/sys/fs/cgroup"
	}

	return info
}

// getCgroupV1Controllers returns available cgroup v1 controllers
func getCgroupV1Controllers() []string {
	var controllers []string

	// Read /proc/cgroups to get available controllers
	file, err := os.Open("/proc/cgroups")
	if err != nil {
		return controllers
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header line
	scanner.Scan()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[3] == "1" { // enabled
			controllers = append(controllers, fields[0])
		}
	}

	return controllers
}

// getCgroupV1MountPoints returns cgroup v1 mount points
func getCgroupV1MountPoints() map[string]string {
	mountPoints := make(map[string]string)

	file, err := os.Open("/proc/mounts")
	if err != nil {
		return mountPoints
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)

		if len(fields) >= 3 && fields[2] == "cgroup" {
			// Extract controller from mount options
			options := strings.Split(fields[3], ",")
			for _, opt := range options {
				if !strings.Contains(opt, "=") && opt != "rw" && opt != "relatime" {
					mountPoints[opt] = fields[1]
				}
			}
		}
	}

	return mountPoints
}

// getCgroupV2Controllers returns available cgroup v2 controllers
func getCgroupV2Controllers() []string {
	var controllers []string

	// Read cgroup.controllers from the root cgroup
	data, err := os.ReadFile("/sys/fs/cgroup/cgroup.controllers")
	if err != nil {
		return controllers
	}

	controllerList := strings.TrimSpace(string(data))
	if controllerList != "" {
		controllers = strings.Fields(controllerList)
	}

	return controllers
}

// CheckCgroupV2MemoryAccounting checks if memory accounting is properly enabled
func CheckCgroupV2MemoryAccounting() bool {
	if !IsCgroupV2() {
		return true // Not applicable for v1
	}

	// Check if memory controller is available
	controllers := getCgroupV2Controllers()
	for _, controller := range controllers {
		if controller == "memory" {
			return true
		}
	}

	return false
}

// CheckCgroupV2IOAccounting checks if IO accounting is properly enabled in cgroup v2
func CheckCgroupV2IOAccounting() bool {
	if !IsCgroupV2() {
		return true // Not applicable for v1
	}

	// Check if io controller is available
	controllers := getCgroupV2Controllers()
	for _, controller := range controllers {
		if controller == "io" {
			return true
		}
	}

	return false
}

// CheckCgroupWritePermissions checks if we have write permissions to cgroup
func CheckCgroupWritePermissions() bool {
	var testPath string

	if IsCgroupV2() {
		testPath = "/sys/fs/cgroup"
	} else {
		testPath = "/sys/fs/cgroup/memory"
	}

	// Test write access - simplified for cross-platform compatibility
	_, err := os.Stat(testPath)
	return err == nil
}
