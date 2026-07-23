package proofstrap

import (
	"fmt"
	"sort"
	"strings"
)

// HostFacts is raw review provenance. Package and service behaviors select
// themselves from live evidence; OS identity never dispatches behavior.
type HostFacts struct {
	ID      string   `json:"id"`
	Version string   `json:"version,omitempty"`
	Like    []string `json:"like,omitempty"`
	PID1    string   `json:"pid1"`
}

type hostInspection struct {
	facts    HostFacts
	factsOut []Fact
	blockers []Blocker
}

func observeHost(runner Runner) hostInspection {
	inspection := hostInspection{}
	contents, err := runner.ReadFile("/etc/os-release")
	if err != nil {
		inspection.blockers = append(inspection.blockers, Blocker{Subject: "file:/etc/os-release", Detail: err.Error()})
	} else {
		values := parseOSReleaseValues(string(contents))
		inspection.facts.ID = normalizeOSID(values["ID"])
		inspection.facts.Version = strings.TrimSpace(values["VERSION_ID"])
		inspection.facts.Like = normalizeIDLike(values["ID_LIKE"])
		if inspection.facts.ID == "" {
			inspection.blockers = append(inspection.blockers, Blocker{Subject: "host:identity", Detail: "os-release ID is empty"})
		} else {
			inspection.factsOut = append(inspection.factsOut, Fact{Subject: "host:identity", Detail: fmt.Sprintf("id=%s version=%s id_like=%s", inspection.facts.ID, inspection.facts.Version, strings.Join(inspection.facts.Like, ","))})
		}
	}

	contents, err = runner.ReadFile("/proc/1/comm")
	if err != nil {
		inspection.blockers = append(inspection.blockers, Blocker{Subject: "service-manager", Detail: err.Error()})
		return inspection
	}
	inspection.facts.PID1 = strings.TrimSpace(string(contents))
	if inspection.facts.PID1 == "" {
		inspection.blockers = append(inspection.blockers, Blocker{Subject: "service-manager", Detail: "PID 1 name is empty"})
	}
	return inspection
}

func normalizeIDLike(value string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, token := range strings.Fields(value) {
		token = normalizeOSID(token)
		if token != "" && !seen[token] {
			seen[token] = true
			result = append(result, token)
		}
	}
	sort.Strings(result)
	return result
}

func parseOSReleaseValues(contents string) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(contents, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		values[parts[0]] = strings.Trim(strings.TrimSpace(parts[1]), "\"")
	}
	return values
}

func normalizeOSID(id string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(id), "_", "-"))
}
