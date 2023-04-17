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

#define DEFAULT_CALC_RATES_PERIOD_SEC 5


static struct option HttpAnalyzerOptions[] =
{
	{"interface",  required_argument, nullptr, 'i'},
	{"dst-port",  required_argument, nullptr, 'p'},
	{"rate-calc-period", required_argument, nullptr, 'r'},
	{"help", no_argument, nullptr, 'h'},
	{nullptr, 0, nullptr, 0}
};


struct HttpPacketArrivedData
{
	HttpStatsCollector* statsCollector;
};


/**
 * Print application usage
 */
void printUsage()
{
	std::cout << std::endl
		<< "Usage: Live traffic mode:" << std::endl
		<< "-------------------------" << std::endl
		<< pcpp::AppName::get() << " [-h] [-r calc_period] [-p dst_port] [-i interface]" << std::endl
		<< std::endl
		<< "Options:" << std::endl
		<< std::endl
		<< "    -i interface   : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address" << std::endl
		<< "    -p dst_port    : Use the specified port (optional parameter, the default is 80)" << std::endl
		<< "    -r calc_period : The period in seconds to calculate rates. If not provided default is 2 seconds" << std::endl
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
 * activate HTTP analysis from live traffic
 */
void analyzeHttpFromLiveTraffic(pcpp::PcapLiveDevice* dev, int printRatePeriod, uint16_t dstPort)
{
	// open the device
	if (!dev->open())
		EXIT_WITH_ERROR("Could not open the device");

	pcpp::PortFilter httpPortFilter(dstPort, pcpp::SRC_OR_DST);
	if (!dev->setFilter(httpPortFilter))
		EXIT_WITH_ERROR("Could not set up filter on device");

	// start capturing packets and collecting stats
	HttpPacketArrivedData data;
	HttpStatsCollector collector(dstPort);
	data.statsCollector = &collector;
	dev->startCapture(httpPacketArrive, &data);


	// register the on app close event to print summary stats on app termination
	bool shouldStop = false;
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &shouldStop);

	while(!shouldStop)
	{
		pcpp::multiPlatformSleep(printRatePeriod);

		printSummaryTraffic(collector);
	}

	// stop capturing and close the live device
	dev->stopCapture();
	dev->close();
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

	int optionIndex = 0;
	int opt = 0;

	while((opt = getopt_long(argc, argv, "i:p:r:h", HttpAnalyzerOptions, &optionIndex)) != -1)
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
			case 'r':
				printRatePeriod = atoi(optarg);
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

	// if no interface - exit with error
	if (interfaceNameOrIP == "")
		EXIT_WITH_ERROR("Neither interface nor input pcap file were provided");

	// get the port
	int nPort = atoi(port.c_str());
	if (nPort <= 0 || nPort > 65535)
		EXIT_WITH_ERROR("Please input a number between 0 to 65535");

	// analyze in live traffic mode

	pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(interfaceNameOrIP);
	if (dev == nullptr)
		EXIT_WITH_ERROR("Couldn't find interface by provided IP address or name");

	// start capturing and analyzing traffic
	analyzeHttpFromLiveTraffic(dev, printRatePeriod, nPort);

}