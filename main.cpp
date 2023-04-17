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
#include <glog/logging.h>

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


void printUsage()
{
	std::cout << std::endl
		<< "Traffic analyzer:" << std::endl
		<< "-------------------------" << std::endl
		<< pcpp::AppName::get() << " [-h] [-r calc_period] [-p dst_port] [-i interface]" << std::endl
		<< std::endl
		<< "Options:" << std::endl
		<< std::endl
		<< "    -i interface   : Use the specified interface. Can be interface name (e.g eth0) or interface IPv4 address" << std::endl
		<< "    -p dst_port    : Use the specified port (optional parameter, the default is 80)" << std::endl
		<< "    -r calc_period : The period in seconds to calculate rates. If not provided default is 5 seconds" << std::endl
		<< "    -h             : Displays this help message and exits" << std::endl
		<< std::endl;
}


void httpPacketArrive(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
	pcpp::Packet parsedPacket(packet);

	HttpPacketArrivedData* data  = (HttpPacketArrivedData*)cookie;

	data->statsCollector->collectStats(&parsedPacket);
}


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


void onApplicationInterrupted(void* cookie)
{
	bool* shouldStop = (bool*)cookie;
	*shouldStop = true;
}


void analyzeHttpFromLiveTraffic(pcpp::PcapLiveDevice* dev, int printRatePeriod, uint16_t dstPort)
{
	if (!dev->open())
		LOG(FATAL) << "Could not open the device";

	pcpp::PortFilter httpPortFilter(dstPort, pcpp::SRC_OR_DST);
	if (!dev->setFilter(httpPortFilter))
		LOG(FATAL) << "Could not set up filter on device";

	HttpPacketArrivedData data;
	HttpStatsCollector collector(dstPort);
	data.statsCollector = &collector;
	dev->startCapture(httpPacketArrive, &data);


	bool shouldStop = false;
	pcpp::ApplicationEventHandler::getInstance().onApplicationInterrupted(onApplicationInterrupted, &shouldStop);

	if (shouldStop == true)
		LOG(DFATAL) << "Shoud be at least one try";

	while(!shouldStop)
	{
		pcpp::multiPlatformSleep(printRatePeriod);

		printSummaryTraffic(collector);
	}

	dev->stopCapture();
	dev->close();

	LOG(INFO) << "End of execution";
}

int main(int argc, char* argv[])
{
	FLAGS_log_dir = "./";

	google::InitGoogleLogging(argv[0]);

	pcpp::AppName::init(argc, argv);

	std::string interfaceNameOrIP = "";
	std::string port = "80";
	bool printRatesPeriodically = true;
	int printRatePeriod = DEFAULT_CALC_RATES_PERIOD_SEC;

	int optionIndex = 0;
	int opt = 0;

	LOG(INFO) << "Start of execution";

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
				LOG(ERROR) << "Unknown opt: " << opt;
				exit(-1);
		}
	}

	if (interfaceNameOrIP == "")
		LOG(FATAL) << "Neither interface nor input pcap file were provided";

	int nPort = atoi(port.c_str());
	if (nPort <= 0 || nPort > 65535)
		LOG(FATAL) << "Please input a number between 0 to 65535";

	if (nPort == 443)
		LOG(WARNING) << "Can't track HTTPS traffic";	

	pcpp::PcapLiveDevice* dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(interfaceNameOrIP);
	if (dev == nullptr)
		LOG(FATAL) << "Couldn't find interface by provided IP address or name";

	analyzeHttpFromLiveTraffic(dev, printRatePeriod, nPort);

	google::ShutdownGoogleLogging();
}