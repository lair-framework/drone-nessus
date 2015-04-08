package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/lair-framework/go-lair-drone"
	"github.com/lair-framework/go-nessus"
)

const (
	TOOL     = "Nessus"
	OSWEIGHT = 75
)

const usage = `
	Usage: nessus.go <project_id> <file>
`

type hostMap struct {
	Hosts         map[string]bool
	Vulnerability *lairdrone.Vulnerability
}

func buildProject(nessus *nessus.NessusData, projectId string) (*lairdrone.Project, error) {
	cvePattern := regexp.MustCompile(`(CVE-|CAN-)`)
	falseUdpPattern := regexp.MustCompile(`.*\?$`)
	noteId := 1

	project := &lairdrone.Project{}
	project.Tool = TOOL
	project.ProjectId = projectId

	vulnHostMap := make(map[string]hostMap)
	for _, reportHost := range nessus.Report.ReportHosts {
		tempIp := reportHost.Name
		host := &lairdrone.Host{}
		for _, tag := range reportHost.HostProperties.Tags {
			switch {
			case tag.Name == "operating-system":
				os := &lairdrone.OS{
					Tool:        TOOL,
					Weight:      OSWEIGHT,
					Fingerprint: tag.Data,
				}
				host.OperatingSystem = append(host.OperatingSystem, *os)
			case tag.Name == "host-ip":
				host.StringAddr = tag.Data
			case tag.Name == "mac-address":
				host.MACAddr = tag.Data
			case tag.Name == "host-fqdn":
				host.Hostnames = append(host.Hostnames, tag.Data)
			case tag.Name == "netbios-name":
				host.Hostnames = append(host.Hostnames, tag.Data)
			}
		}

		portsProcessed := make(map[string]lairdrone.Port)
		for _, item := range reportHost.ReportItems {
			pluginId := item.PluginID
			pluginFamily := item.PluginFamily
			severity := item.Severity
			title := item.PluginName
			port := item.Port
			protocol := item.Protocol
			service := item.SvcName
			evidence := item.PluginOutput

			// Check for false positive UDP...ignore it if found.
			if protocol == "udp" && falseUdpPattern.MatchString(service) {
				continue
			}

			portKey := fmt.Sprintf("%d:%s", port, protocol)
			if _, ok := portsProcessed[portKey]; !ok {
				// Haven't seen this port. Create it.
				p := &lairdrone.Port{
					PortNum:  port,
					Protocol: protocol,
					Service:  service,
				}
				portsProcessed[portKey] = *p
			}

			if evidence != "" && severity >= 1 && pluginFamily != "Port scanners" && pluginFamily != "Service detection" {
				// Format and add evidence
				note := &lairdrone.Note{
					Title:          fmt.Sprintf("%s (ID%d)", title, noteId),
					Content:        "",
					LastModifiedBy: TOOL,
				}
				e := strings.Trim(evidence, " \t")
				for _, line := range strings.Split(e, "\n") {
					line = strings.Trim(line, " \t")
					if line != "" {
						note.Content += "    " + line + "\n"
					}
				}
				p := portsProcessed[portKey]
				p.Notes = append(p.Notes, *note)
				portsProcessed[portKey] = p
				noteId += 1
			}

			if pluginId == "19506" {
				command := &lairdrone.Command{
					Tool:    TOOL,
					Command: item.PluginOutput,
				}
				if project.Commands == nil || len(project.Commands) == 0 {
					project.Commands = append(project.Commands, *command)
				}
				continue
			}

			if _, ok := vulnHostMap[pluginId]; !ok {
				// Vulnerability has not yet been seen for this host. Add it.
				v := &lairdrone.Vulnerability{}

				v.Title = title
				v.Description = item.Description
				v.Solution = item.Solution
				v.Evidence = evidence
				v.Flag = item.ExploitAvailable
				if item.ExploitAvailable {
					exploitDetail := item.ExploitFrameworkMetasploit
					if exploitDetail {
						note := &lairdrone.Note{
							Title:          "Metasploit Exploit",
							Content:        "Exploit exists. Details unknown.",
							LastModifiedBy: TOOL,
						}
						if item.MetasploitName != "" {
							note.Content = item.MetasploitName
						}
						v.Notes = append(v.Notes, *note)
					}

					exploitDetail = item.ExploitFrameworkCanvas
					if exploitDetail {
						note := &lairdrone.Note{
							Title:          "Canvas Exploit",
							Content:        "Exploit exists. Details unknown.",
							LastModifiedBy: TOOL,
						}
						if item.CanvasPackage != "" {
							note.Content = item.CanvasPackage
						}
						v.Notes = append(v.Notes, *note)
					}

					exploitDetail = item.ExploitFrameworkCore
					if exploitDetail {
						note := &lairdrone.Note{
							Title:          "Core Impact Exploit",
							Content:        "Exploit exists. Details unknown.",
							LastModifiedBy: TOOL,
						}
						if item.CoreName != "" {
							note.Content = item.CoreName
						}
						v.Notes = append(v.Notes, *note)
					}
				}

				v.CVSS = item.CVSSBaseScore
				if v.CVSS == 0 && item.RiskFactor != "" && item.RiskFactor != "Low" {
					switch {
					case item.RiskFactor == "Medium":
						v.CVSS = 5.0
					case item.RiskFactor == "High":
						v.CVSS = 7.5
					case item.RiskFactor == "Critical":
						v.CVSS = 10
					}
				}

				if v.CVSS == 0 {
					// Ignore informational findings
					continue
				}

				// Set the CVEs
				for _, cve := range item.CVE {
					c := cvePattern.ReplaceAllString(cve, "")
					v.CVEs = append(v.CVEs, c)
				}

				// Set the plugin and identified by information
				plugin := &lairdrone.PluginId{Tool: TOOL, Id: pluginId}
				v.PluginIds = append(v.PluginIds, *plugin)
				v.IdentifiedBy = append(v.IdentifiedBy, *plugin)

				vulnHostMap[pluginId] = hostMap{Hosts: make(map[string]bool), Vulnerability: v}

			}

			if hm, ok := vulnHostMap[pluginId]; ok {
				hostStr := fmt.Sprintf("%s:%d:%s", host.StringAddr, port, protocol)
				hm.Hosts[hostStr] = true
			}
		}

		if host.StringAddr == "" {
			host.StringAddr = tempIp
		}

		// Add ports to host and host to project
		for _, p := range portsProcessed {
			host.Ports = append(host.Ports, p)
		}
		project.Hosts = append(project.Hosts, *host)
	}

	for _, hm := range vulnHostMap {
		for key, _ := range hm.Hosts {
			tokens := strings.Split(key, ":")
			portNum, err := strconv.Atoi(tokens[1])
			if err != nil {
				return nil, err
			}
			hostKey := &lairdrone.HostKey{
				StringAddr: tokens[0],
				PortNum:    portNum,
				Protocol:   tokens[2],
			}
			hm.Vulnerability.Hosts = append(hm.Vulnerability.Hosts, *hostKey)
		}
		project.Vulnerabilities = append(project.Vulnerabilities, *hm.Vulnerability)
	}

	if len(project.Commands) == 0 {
		c := &lairdrone.Command{Tool: TOOL, Command: "Nessus scan - command unknown"}
		project.Commands = append(project.Commands, *c)
	}

	return project, nil
}

func main() {

	// Parse command line args
	flag.Usage = func() { fmt.Print(usage) }
	flag.Parse()
	if len(flag.Args()) != 2 {
		log.Fatal("You need to supply the Lair project ID and file you wish to import")
	}
	pid := flag.Arg(0)
	f := flag.Arg(1)

	// Parse and setup to target drone server info
	dest := os.Getenv("LAIR_DRONE_SERVER")
	if dest == "" {
		log.Fatal("Missing LAIR_DRONE_SERVER environment variable.")
	}
	u, err := url.Parse(dest)
	if err != nil {
		log.Fatal(err)
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	if user == "" || pass == "" {
		log.Fatal("Missing username and/or password")
	}
	target := &lairdrone.LairTarget{User: user, Password: pass, Host: u.Host}

	// Read the raw data file and parse
	buf, err := ioutil.ReadFile(f)
	if err != nil {
		log.Fatal(err)
	}
	nessusData, err := nessus.Parse(buf)
	if err != nil {
		log.Fatal(err)
	}

	// Convert the Nessus structs to a go-lair-drone project
	project, err := buildProject(nessusData, pid)
	if err != nil {
		log.Fatal(err)
	}

	// Import the project into Lair
	res, err := lairdrone.ImportProject(target, project)
	if err != nil {
		log.Fatal("Unable to import project: ", err)
	}
	defer res.Body.Close()

	// Inspect the reponse
	droneRes := &lairdrone.DroneResponse{}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	if err := json.Unmarshal(body, droneRes); err != nil {
		log.Fatal(err)
	}
	if droneRes.Status == "Error" {
		log.Fatal("Import failed : ", droneRes.Message)
	}

}
