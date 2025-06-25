//go:build !linux

package cgroup

// CgroupVersion represents the cgroup version being used
type CgroupVersion int

const (
	CgroupV1 CgroupVersion = iota + 1
	CgroupV2
	CgroupUnknown
)

// DetectCgroupVersion detects whether the system is using cgroup v1 or v2
// On non-Linux systems, always returns CgroupUnknown
func DetectCgroupVersion() CgroupVersion {
	return CgroupUnknown
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
// On non-Linux systems, always returns false
func IsCgroupV2() bool {
	return false
}

// IsCgroupV1 returns true if the system is using cgroup v1
// On non-Linux systems, always returns false
func IsCgroupV1() bool {
	return false
}

// GetCgroupInfo returns detailed information about the cgroup configuration
// On non-Linux systems, returns minimal information
func GetCgroupInfo() map[string]interface{} {
	info := make(map[string]interface{})
	info["version"] = "unknown"
	info["detected_version"] = CgroupUnknown
	info["platform"] = "non-linux"
	return info
}

// CheckCgroupV2MemoryAccounting checks if memory accounting is properly enabled
// On non-Linux systems, always returns false
func CheckCgroupV2MemoryAccounting() bool {
	return false
}

// CheckCgroupWritePermissions checks if we have write permissions to cgroup
// On non-Linux systems, always returns false
func CheckCgroupWritePermissions() bool {
	return false
}
