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

	"github.com/lair-framework/api-server/client"
	"github.com/lair-framework/go-lair"
	"github.com/lair-framework/go-nessus"
)

const (
	version  = "2.0.0"
	tool     = "nessus"
	osWeight = 75
	usage    = `
Parses a nessus XML file into a lair project.

Usage:
  drone-nessus <id> <filename>
  export LAIR_ID=<id>; drone-nessus <filename>
Options:
  -v              show version and exit
  -h              show usage and exit
  -k              allow insecure SSL connections
  -force-ports    disable data protection in the API server for excessive ports
  -tags           a comma separated list of tags to add to every host that is imported
`
)

type hostMap struct {
	Hosts         map[string]bool
	Vulnerability *lair.Issue
}

func buildProject(nessus *nessus.NessusData, projectID string, tags []string) (*lair.Project, error) {
	cvePattern := regexp.MustCompile(`(CVE-|CAN-)`)
	falseUDPPattern := regexp.MustCompile(`.*\?$`)
	noteID := 1

	project := &lair.Project{}
	project.Tool = tool
	project.ID = projectID

	vulnHostMap := make(map[string]hostMap)
	for _, reportHost := range nessus.Report.ReportHosts {
		tempIP := reportHost.Name
		host := &lair.Host{
			Tags: tags,
		}
		for _, tag := range reportHost.HostProperties.Tags {
			switch {
			case tag.Name == "operating-system":
				os := &lair.OS{
					Tool:        tool,
					Weight:      osWeight,
					Fingerprint: tag.Data,
				}
				host.OS = *os
			case tag.Name == "host-ip":
				host.IPv4 = tag.Data
			case tag.Name == "mac-address":
				host.MAC = tag.Data
			case tag.Name == "host-fqdn":
				host.Hostnames = append(host.Hostnames, tag.Data)
			case tag.Name == "netbios-name":
				host.Hostnames = append(host.Hostnames, tag.Data)
			}
		}

		portsProcessed := make(map[string]lair.Service)
		for _, item := range reportHost.ReportItems {
			pluginID := item.PluginID
			pluginFamily := item.PluginFamily
			severity := item.Severity
			title := item.PluginName
			port := item.Port
			protocol := item.Protocol
			service := item.SvcName
			evidence := item.PluginOutput

			// Check for false positive UDP...ignore it if found.
			if protocol == "udp" && falseUDPPattern.MatchString(service) {
				continue
			}

			portKey := fmt.Sprintf("%d:%s", port, protocol)
			if _, ok := portsProcessed[portKey]; !ok {
				// Haven't seen this port. Create it.
				p := &lair.Service{
					Port:     port,
					Protocol: protocol,
					Service:  service,
				}
				portsProcessed[portKey] = *p
			}

			if evidence != "" && severity >= 1 && pluginFamily != "Port scanners" && pluginFamily != "Service detection" {
				// Format and add evidence
				note := &lair.Note{
					Title:          fmt.Sprintf("%s (ID%d)", title, noteID),
					Content:        "",
					LastModifiedBy: tool,
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
				noteID++
			}

			if pluginID == "19506" {
				command := &lair.Command{
					Tool:    tool,
					Command: item.PluginOutput,
				}
				if project.Commands == nil || len(project.Commands) == 0 {
					project.Commands = append(project.Commands, *command)
				}
				continue
			}

			if _, ok := vulnHostMap[pluginID]; !ok {
				// Vulnerability has not yet been seen for this host. Add it.
				v := &lair.Issue{}

				v.Title = title
				v.Description = item.Description
				v.Solution = item.Solution
				v.Evidence = evidence
				v.IsFlagged = item.ExploitAvailable
				if item.ExploitAvailable {
					exploitDetail := item.ExploitFrameworkMetasploit
					if exploitDetail {
						note := &lair.Note{
							Title:          "Metasploit Exploit",
							Content:        "Exploit exists. Details unknown.",
							LastModifiedBy: tool,
						}
						if item.MetasploitName != "" {
							note.Content = item.MetasploitName
						}
						v.Notes = append(v.Notes, *note)
					}

					exploitDetail = item.ExploitFrameworkCanvas
					if exploitDetail {
						note := &lair.Note{
							Title:          "Canvas Exploit",
							Content:        "Exploit exists. Details unknown.",
							LastModifiedBy: tool,
						}
						if item.CanvasPackage != "" {
							note.Content = item.CanvasPackage
						}
						v.Notes = append(v.Notes, *note)
					}

					exploitDetail = item.ExploitFrameworkCore
					if exploitDetail {
						note := &lair.Note{
							Title:          "Core Impact Exploit",
							Content:        "Exploit exists. Details unknown.",
							LastModifiedBy: tool,
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
				plugin := &lair.PluginID{Tool: tool, ID: pluginID}
				v.PluginIDs = append(v.PluginIDs, *plugin)
				v.IdentifiedBy = append(v.IdentifiedBy, lair.IdentifiedBy{Tool: tool})

				vulnHostMap[pluginID] = hostMap{Hosts: make(map[string]bool), Vulnerability: v}

			}

			if hm, ok := vulnHostMap[pluginID]; ok {
				hostStr := fmt.Sprintf("%s:%d:%s", host.IPv4, port, protocol)
				hm.Hosts[hostStr] = true
			}
		}

		if host.IPv4 == "" {
			host.IPv4 = tempIP
		}

		// Add ports to host and host to project
		for _, p := range portsProcessed {
			host.Services = append(host.Services, p)
		}
		project.Hosts = append(project.Hosts, *host)
	}

	for _, hm := range vulnHostMap {
		for key := range hm.Hosts {
			tokens := strings.Split(key, ":")
			portNum, err := strconv.Atoi(tokens[1])
			if err != nil {
				return nil, err
			}
			hostKey := &lair.IssueHost{
				IPv4:     tokens[0],
				Port:     portNum,
				Protocol: tokens[2],
			}
			hm.Vulnerability.Hosts = append(hm.Vulnerability.Hosts, *hostKey)
		}
		project.Issues = append(project.Issues, *hm.Vulnerability)
	}

	if len(project.Commands) == 0 {
		c := &lair.Command{Tool: tool, Command: "Nessus scan - command unknown"}
		project.Commands = append(project.Commands, *c)
	}

	return project, nil
}

func main() {
	showVersion := flag.Bool("v", false, "")
	insecureSSL := flag.Bool("k", false, "")
	forcePorts := flag.Bool("force-ports", false, "")
	tags := flag.String("tags", "", "")
	flag.Usage = func() {
		fmt.Println(usage)
	}
	flag.Parse()
	if *showVersion {
		log.Println(version)
		os.Exit(0)
	}
	lairURL := os.Getenv("LAIR_API_SERVER")
	if lairURL == "" {
		log.Fatal("Fatal: Missing LAIR_API_SERVER environment variable")
	}
	lairPID := os.Getenv("LAIR_ID")
	var filename string
	switch len(flag.Args()) {
	case 2:
		lairPID = flag.Arg(0)
		filename = flag.Arg(1)
	case 1:
		filename = flag.Arg(0)
	default:
		log.Fatal("Fatal: Missing required argument")
	}

	u, err := url.Parse(lairURL)
	if err != nil {
		log.Fatalf("Fatal: Error parsing LAIR_API_SERVER URL. Error %s", err.Error())
	}
	if u.User == nil {
		log.Fatal("Fatal: Missing username and/or password")
	}
	user := u.User.Username()
	pass, _ := u.User.Password()
	if user == "" || pass == "" {
		log.Fatal("Fatal: Missing username and/or password")
	}
	c, err := client.New(&client.COptions{
		User:               user,
		Password:           pass,
		Host:               u.Host,
		Scheme:             u.Scheme,
		InsecureSkipVerify: *insecureSSL,
	})

	if err != nil {
		log.Fatalf("Fatal: Error setting up client: Error %s", err.Error())
	}

	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Fatal: Could not open file. Error %s", err.Error())
	}
	nessusData, err := nessus.Parse(buf)
	if err != nil {
		log.Fatalf("Fatal: Error parsing nessus data. Error %s", err.Error())
	}
	hostTags := []string{}
	if *tags != "" {
		hostTags = strings.Split(*tags, ",")
	}
	project, err := buildProject(nessusData, lairPID, hostTags)
	if err != nil {
		log.Fatalf("Fatal: Error building project. Error %s", err.Error())
	}

	res, err := c.ImportProject(&client.DOptions{ForcePorts: *forcePorts}, project)
	if err != nil {
		log.Fatalf("Fatal: Unable to import project. Error %s", err)
	}
	defer res.Body.Close()
	droneRes := &client.Response{}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("Fatal: Error %s", err.Error())
	}
	if err := json.Unmarshal(body, droneRes); err != nil {
		log.Fatalf("Fatal: Could not unmarshal JSON. Error %s", err.Error())
	}
	if droneRes.Status == "Error" {
		log.Fatalf("Fatal: Import failed. Error %s", droneRes.Message)
	}
	log.Println("Success: Operation completed successfully")
}
