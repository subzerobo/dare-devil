package main

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/yl2chen/cidranger"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"time"

	"bufio"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/ip2location/ip2location-go"
	"github.com/joho/godotenv"
)

type IPEntry struct {
	list_index int
	value      string
}

type Msg struct {
	IP       string `json:"ip"`
	IPStatus string `json:"reputation"`
	Data     MyIP2L `json:"ip2location"`
	Duration string `json:"execution_time"`
	OK       bool   `json:"ok"`
}

type Error struct {
	OK bool `json:"ok"`
}

type MyIP2L struct {
	Country_short      string  `json:",omitempty"`
	Country_long       string  `json:",omitempty"`
	Region             string  `json:",omitempty"`
	City               string  `json:",omitempty"`
	Isp                string  `json:",omitempty"`
	Latitude           float32 `json:",omitempty"`
	Longitude          float32 `json:",omitempty"`
	Domain             string  `json:",omitempty"`
	Zipcode            string  `json:",omitempty"`
	Timezone           string  `json:",omitempty"`
	Netspeed           string  `json:",omitempty"`
	Iddcode            string  `json:",omitempty"`
	Areacode           string  `json:",omitempty"`
	Weatherstationcode string  `json:",omitempty"`
	Weatherstationname string  `json:",omitempty"`
	Mcc                string  `json:",omitempty"`
	Mnc                string  `json:",omitempty"`
	Mobilebrand        string  `json:",omitempty"`
	Elevation          float32 `json:",omitempty"`
	Usagetype          string  `json:",omitempty"`
}

var IPMap = map[string]IPEntry{}

var ranger cidranger.Ranger
var ourRanger cidranger.Ranger

var firehol_lists = [...]string{
	"firehol_level1.netset",
	"firehol_level2.netset",
	"firehol_level3.netset",
	"firehol_level4.netset",
	"firehol_abusers_1d.netset",
	"firehol_abusers_30d.netset",
	"firehol_webserver.netset",
	"firehol_webclient.netset",
	"firehol_proxies.netset",
	"firehol_anonymous.netset",
}

// Loads IP2Location binary file
func loadIp2Location() {
	fmt.Println("Loading IP2Location Bin File")
	logrus.Info("Loading IP2Location Bin File");
	start := time.Now()
	ip2location.Open("./ip2location/IP-COUNTRY-REGION-CITY-ISP.BIN")
	elapsed := time.Since(start)
	logrus.Info(fmt.Sprintf("IP2Country Loaded in %s \n", elapsed))
}

// Loads the IP Whitelists
func loadWhiteList() {
	// add our CIDR ranger

	start := time.Now();
	total := 0

	logrus.Info("Reading Whitelist to memory \n")
	filename := "whitelist/whitelist.ipset"

	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err = f.Close(); err != nil {
			log.Fatal(err)
		}
	}()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		if !strings.HasPrefix(line, "#") {
			_, network, _ := net.ParseCIDR(line)
			ourRanger.Insert(cidranger.NewBasicRangerEntry(*network))
			total++
		}
	}
	err = s.Err()
	if err != nil {
		log.Fatal(err)
	}
	elapsed := time.Since(start);
	logrus.Info(fmt.Sprintf("Total %d WhiteList Records added to memory in %s \n", total, elapsed))
}

// Loads Firehole data files to memory
func loadFireHoleData() {

	start := time.Now();
	total := 0
	for i := 0; i < len(firehol_lists); i++ {
		logrus.Info(fmt.Sprintf("Reading %dth element of Firehol List [%s] to memory \n", i+1, firehol_lists[i]))
		filename := "firehol/" + firehol_lists[i]

		f, err := os.Open(filename)
		if err != nil {
			log.Fatal(err)
		}
		defer func() {
			if err = f.Close(); err != nil {
				log.Fatal(err)
			}
		}()
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := s.Text()
			if !strings.HasPrefix(line, "#") {
				isCIDRValue := strings.Contains(line, "/")
				if (isCIDRValue) {
					_, network, _ := net.ParseCIDR(line)
					ranger.Insert(cidranger.NewBasicRangerEntry(*network))
				} else {
					n := IPEntry{list_index: i, value: line}
					IPMap[line] = n;
				}
				total++
			}
		}
		err = s.Err()
		if err != nil {
			log.Fatal(err)
		}
	}

	elapsed := time.Since(start);
	logrus.Info(fmt.Sprintf("Total %d Block Records added to memory in %s \n", total, elapsed))
}

// Displays Welcome text in CLI
func welcomeText() {
	b, err := ioutil.ReadFile("ascii.txt")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
}

// Check if IP is black listed + execution time
func isIPBlackList(ip string) (bool, time.Duration) {
	start := time.Now();

	// Test our ips
	isUs, err2 := ranger.Contains(net.ParseIP(ip))
	if err2 != nil {
		log.Fatal("Error Parsing IP")
	}
	if isUs {
		elapsed := time.Since(start);
		return false, elapsed
	}

	contains, err := ranger.Contains(net.ParseIP(ip))
	if err != nil {
		log.Fatal("Error Parsing IP")
	}
	if contains {
		elapsed := time.Since(start);
		return true, elapsed
	}
	_, hasKey := IPMap[ip]
	if (hasKey) {
		elapsed := time.Since(start);
		return true, elapsed
	}
	elapsed := time.Since(start);
	return false, elapsed
}

// Cleanup Data
func cleanIP2LocationData(results ip2location.IP2Locationrecord) MyIP2L {
	myIP2L := MyIP2L{}

	if (results.Country_short != "This parameter is unavailable for selected data file. Please upgrade the data file.") {
		myIP2L.Country_short = results.Country_short
	}
	if (results.Country_long != "This parameter is unavailable for selected data file. Please upgrade the data file.") {
		myIP2L.Country_long = results.Country_long
	}
	if (results.Isp != "This parameter is unavailable for selected data file. Please upgrade the data file.") {
		myIP2L.Isp = results.Isp
	}
	if (results.Region != "This parameter is unavailable for selected data file. Please upgrade the data file.") {
		myIP2L.Region = results.Region
	}
	if (results.City != "This parameter is unavailable for selected data file. Please upgrade the data file.") {
		myIP2L.City = results.City
	}
	if (results.Domain != "This parameter is unavailable for selected data file. Please upgrade the data file.") {
		myIP2L.Domain = results.Domain
	}
	if (results.Zipcode != "This parameter is unavailable for selected data file. Please upgrade the data file.") {
		myIP2L.Zipcode = results.Zipcode
	}
	if (results.Timezone != "This parameter is unavailable for selected data file. Please upgrade the data file.") {
		myIP2L.Timezone = results.Timezone
	}
	if (results.Netspeed != "This parameter is unavailable for selected data file. Please upgrade the data file.") {
		myIP2L.Netspeed = results.Netspeed
	}
	if (results.Iddcode != "This parameter is unavailable for selected data file. Please upgrade the data file.") {
		myIP2L.Iddcode = results.Iddcode
	}
	if (results.Weatherstationcode != "This parameter is unavailable for selected data file. Please upgrade the data file.") {
		myIP2L.Weatherstationcode = results.Weatherstationcode
	}
	if (results.Weatherstationname != "This parameter is unavailable for selected data file. Please upgrade the data file.") {
		myIP2L.Weatherstationname = results.Weatherstationname
	}
	if (results.Mcc != "This parameter is unavailable for selected data file. Please upgrade the data file.") {
		myIP2L.Mcc = results.Mcc
	}
	if (results.Mnc != "This parameter is unavailable for selected data file. Please upgrade the data file.") {
		myIP2L.Mnc = results.Mnc
	}
	if (results.Mobilebrand != "This parameter is unavailable for selected data file. Please upgrade the data file.") {
		myIP2L.Mobilebrand = results.Mobilebrand
	}
	if (results.Usagetype != "This parameter is unavailable for selected data file. Please upgrade the data file.") {
		myIP2L.Usagetype = results.Usagetype
	}
	return myIP2L
}

// Provide data for the IP
func getIP2LocationData(ip string) Msg {
	start := time.Now()

	results := ip2location.Get_all(ip)
	status, _ := isIPBlackList(ip)

	elapsed := time.Since(start)

	msg := Msg{}

	status_str := "good"
	if (status) {
		status_str = "bad"
	}

	myIP2L := cleanIP2LocationData(results)

	msg.Data = myIP2L
	msg.IP = ip
	msg.IPStatus = status_str
	msg.Duration = elapsed.String()

	return msg
}

// Validate IP Address
func validIP4(ipAddress string) bool {
	ipAddress = strings.Trim(ipAddress, " ")

	re, _ := regexp.Compile(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`)
	if re.MatchString(ipAddress) {
		return true
	}
	return false
}

// Main Program
func main() {

	welcomeText()

	ranger = cidranger.NewPCTrieRanger();
	ourRanger = cidranger.NewPCTrieRanger();
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	loadIp2Location()

	loadFireHoleData()

	loadWhiteList()

	mod := os.Getenv("GIN_MODE")
	port:= os.Getenv("GIN_PORT")

	fmt.Println("Staring Gin WebServer")
	fmt.Println("Gin Mode : ", mod)
	gin.SetMode(mod)

	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		origin :=""
		xff:= c.Request.Header.Get("X-Forwarded-For")
		if xff !="" {
			origin = xff
		}else{
			origin = c.Request.RemoteAddr
		}
		i := strings.Index(origin, ":")
		ipAddress := origin
		// Cleanup ip address
		if i > -1 {
			ipAddress = origin[:i]
		}
		// replace ::1 with 127.0.0.1
		if ipAddress == "[::1]" {
			ipAddress = "127.0.0.1"
		}
		if (c.Request.Header.Get("Accept") == "application/json") {
			if ipValid := validIP4(ipAddress); ipValid {
				msg := getIP2LocationData(ipAddress)
				msg.OK = true
				c.JSON(200, msg)
			} else {
				msg := Error{}
				msg.OK = false
				c.JSON(400, msg)
			}

		} else {
			//log.Printf("debug: header origin ip: %v", origin)
			c.String(200, ipAddress)
		}

	})

	r.GET("/:ip", func(c *gin.Context) {
		ip := c.Param("ip")
		if ipValid := validIP4(ip); ipValid {
			msg := getIP2LocationData(ip)
			msg.OK = true
			c.JSON(200, msg)
		} else {
			msg := Error{}
			msg.OK = false
			c.JSON(400, msg)
		}

	})

	r.Run(port) // listen and serve on 0.0.0.0:8080
}
