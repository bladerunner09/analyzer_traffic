#include <stdlib.h>
#include <string.h>
#include <iomanip>
#include <algorithm>
#include "PcapLiveDeviceList.h"
#include "PcapFilter.h"
#include "PcapFileDevice.h"
#include "HttpStatsCollector.h"
#include "TablePrinter.h"
#include "SystemUtils.h"
#include "PcapPlusPlusVersion.h"
#include <getopt.h>
#include <iostream>
#include <sstream>


#define EXIT_WITH_ERROR(reason) do { \
	printUsage(); \
	std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl; \
	exit(1); \
	} while(0)


#define PRINT_STAT_LINE(description, counter, measurement) \
		std::cout \
			<< std::left << std::setw(40) << (std::string(description) + ":") \
			<< std::right << std::setw(15) << std::fixed << std::showpoint << std::setprecision(3) << counter \
			<< " [" << measurement << "]" << std::endl;


#define DEFAULT_CALC_RATES_PERIOD_SEC 2


static struct option HttpAnalyzerOptions[] =
{
	{"interface",  required_argument, nullptr, 'i'},
	{"dst-port",  required_argument, nullptr, 'p'},
	{"input-file",  required_argument, nullptr, 'f'},
	{"output-file", required_argument, nullptr, 'o'},
	{"rate-calc-period", required_argument, nullptr, 'r'},
	{"disable-rates-print", no_argument, nullptr, 'd'},
	{"list-interfaces", no_argument, nullptr, 'l'},
	{"help", no_argument, nullptr, 'h'},
	{"version", no_argument, nullptr, 'v'},
	{nullptr, 0, nullptr, 0}
};


struct HttpPacketArrivedData
{
	HttpStatsCollector* statsCollector;
	pcpp::PcapFileWriterDevice* pcapWriter;
};


/**
 * Print application usage
 */
void printUsage()
{
	std::cout << std::endl
		<< "Usage: PCAP file mode:" << std::endl
		<< "----------------------" << std::endl
		<< pcpp::AppName::get() << " [-vh] -f input_file" << std::endl
		<< std::endl
		<< "Options:" << std::endl
		<< std::endl
		<< "    -f             : The input pcap/pcapng file to analyze. Required argument for this mode" << std::endl
		<< "    -v             : Displays the current version and exists" << std::endl
		<< "    -h             : Displays this help message and exits" << std::endl
		<< std::endl
		<< "Usage: Live traffic mode:" << std::endl
		<< "-------------------------" << std::endl
		<< pcpp::AppName::get() << " [-hvld] [-o output_file] [-r calc_period] [-p dst_port] -i interface" << std::endl
		<< std::endl
		<< "Options:" << std::endl
		<< std::endl
		<< "    -i interface   : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address" << std::endl
		<< "    -p dst_port    : Use the specified port (optional parameter, the default is 80)" << std::endl
		<< "    -o output_file : Save all captured HTTP packets to a pcap file. Notice this may cause performance degradation" << std::endl
		<< "    -r calc_period : The period in seconds to calculate rates. If not provided default is 2 seconds" << std::endl
		<< "    -d             : Disable periodic rates calculation" << std::endl
		<< "    -h             : Displays this help message and exits" << std::endl
		<< std::endl;
}


/**
 * packet capture callback - called whenever a packet arrives
 */
void httpPacketArrive(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
	// parse the packet
	pcpp::Packet parsedPacket(packet);

	HttpPacketArrivedData* data  = (HttpPacketArrivedData*)cookie;

	// give the packet to the collector
	data->statsCollector->collectStats(&parsedPacket);

	// if needed - write the packet to the output pcap file
	if (data->pcapWriter != nullptr)
	{
		data->pcapWriter->writePacket(*packet);
	}
}


/**
 * Print the summary traffic.
 */
void printSummaryTraffic(HttpStatsCollector& collector)
{
	for (auto it = collector.getRequestStats().outDataLenghtPerHost.begin(); it != collector.getRequestStats().outDataLenghtPerHost.end(); it++) {
		std::cout << it->first << ": " << collector.getRequestStats().outPacketsNumPerHost[it->first] + collector.getResponseStats().inPacketsNumPerHost[it->first]
		<< " packets (" << collector.getRequestStats().outPacketsNumPerHost[it->first] << " OUT / " << collector.getResponseStats().inPacketsNumPerHost[it->first] << " IN) "
		<< "Traffic: " <<  collector.getRequestStats().outDataLenghtPerHost[it->first] + collector.getResponseStats().inDataLenghtPerHost[it->first] << "B ("
		<< collector.getRequestStats().outDataLenghtPerHost[it->first] << "B OUT / " << collector.getResponseStats().inDataLenghtPerHost[it->first] << "B IN)";

		std::cout << std::endl;
	}

	std::cout << std::endl;
}


/**
 * The callback to be called when application is terminated by ctrl-c. Stops the endless while loop
 */
void onApplicationInterrupted(void* cookie)
{
	bool* shouldStop = (bool*)cookie;
	*shouldStop = true;
}


/**
 * activate HTTP analysis from pcap file
 */
void analyzeHttpFromPcapFile(const std::string& pcapFileName, uint16_t dstPort)
{
	// open input file (pcap or pcapng file)
	pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(pcapFileName);

	if (!reader->open())
		EXIT_WITH_ERROR("Could not open input pcap file");

	// set a port  filter on the reader device to process only HTTP packets
	pcpp::PortFilter httpPortFilter(dstPort, pcpp::SRC_OR_DST);
	if (!reader->setFilter(httpPortFilter))
		EXIT_WITH_ERROR("Could not set up filter on file");

	// read the input file packet by packet and give it to the HttpStatsCollector for collecting stats
	HttpStatsCollector collector(dstPort);
	pcpp::RawPacket rawPacket;
	while(reader->getNextPacket(rawPacket))
	{
		pcpp::Packet parsedPacket(&rawPacket);
		collector.collectStats(&parsedPacket);
	}

	// close input file
	reader->close();

	// free reader memory
	delete reader;
}


/**
 * activate HTTP analysis from live traffic
 */
void analyzeHttpFromLiveTraffic(pcpp::PcapLiveDevice* dev, bool printRatesPeriodically, int printRatePeriod, const std::string& savePacketsToFileName, uint16_t dstPort)
{
	// open the device
	if (!dev->open())
		EXIT_WITH_ERROR("Could not open the device");

	pcpp::PortFilter httpPortFilter(dstPort, pcpp::SRC_OR_DST);
	if (!dev->setFilter(httpPortFilter))
		EXIT_WITH_ERROR("Could not set up filter on device");

	// if needed to save the captured packets to file - open a writer device
	pcpp::PcapFileWriterDevice* pcapWriter = nullptr;
	if (savePacketsToFileName != "")
	{
		pcapWriter = new pcpp::PcapFileWriterDevice(savePacketsToFileName);
		if (!pcapWriter->open())
		{
			EXIT_WITH_ERROR("Could not open pcap file for writing");
		}
	}

	// start capturing packets and collecting stats
	HttpPacketArrivedData data;
	HttpStatsCollector collector(dstPort);
	data.statsCollector = &collector;
	data.pcapWriter = pcapWriter;
	dev->startCapture(httpPacketArrive, &data);


	// register the on app close event to print summary stats on app termination
	bool shouldStop = false;
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &shouldStop);

	while(!shouldStop)
	{
		pcpp::multiPlatformSleep(printRatePeriod);

		// calculate rates
		if (printRatesPeriodically)
		{
			printSummaryTraffic(collector);
		}
	}

	// stop capturing and close the live device
	dev->stopCapture();
	dev->close();

	// close and free the writer device
	if (pcapWriter != nullptr)
	{
		pcapWriter->close();
		delete pcapWriter;
	}
}

/**
 * main method of this utility
 */
int main(int argc, char* argv[])
{
	pcpp::AppName::init(argc, argv);

	std::string interfaceNameOrIP = "";
	std::string port = "80";
	bool printRatesPeriodically = true;
	int printRatePeriod = DEFAULT_CALC_RATES_PERIOD_SEC;
	std::string savePacketsToFileName = "";

	std::string readPacketsFromPcapFileName = "";


	int optionIndex = 0;
	int opt = 0;

	while((opt = getopt_long(argc, argv, "i:p:f:o:r:hvld", HttpAnalyzerOptions, &optionIndex)) != -1)
	{
		switch (opt)
		{
			case 0:
				break;
			case 'i':
				interfaceNameOrIP = optarg;
				break;
			case 'p':
				port = optarg;
				break;
			case 'f':
				readPacketsFromPcapFileName = optarg;
				break;
			case 'o':
				savePacketsToFileName = optarg;
				break;
			case 'r':
				printRatePeriod = atoi(optarg);
				break;
			case 'd':
				printRatesPeriodically = false;
				break;
			case 'h':
				printUsage();
				exit(0);
				break;
			default:
				printUsage();
				exit(-1);
		}
	}

	// if no interface nor input pcap file were provided - exit with error
	if (readPacketsFromPcapFileName == "" && interfaceNameOrIP == "")
		EXIT_WITH_ERROR("Neither interface nor input pcap file were provided");

	// get the port
	int nPort = atoi(port.c_str());
	if (nPort <= 0 || nPort > 65535)
		EXIT_WITH_ERROR("Please input a number between 0 to 65535");

	// analyze in pcap file mode
	if (readPacketsFromPcapFileName != "")
	{
		analyzeHttpFromPcapFile(readPacketsFromPcapFileName, nPort);
	}
	else // analyze in live traffic mode
	{
		pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(interfaceNameOrIP);
		if (dev == nullptr)
			EXIT_WITH_ERROR("Couldn't find interface by provided IP address or name");

		// start capturing and analyzing traffic
		analyzeHttpFromLiveTraffic(dev, printRatesPeriodically, printRatePeriod, savePacketsToFileName, nPort);
	}
}