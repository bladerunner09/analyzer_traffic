#pragma once

#include <map>
#include <sstream>
#include "HttpLayer.h"
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "PayloadLayer.h"
#include "PacketUtils.h"
#include "SystemUtils.h"


struct HttpRequestStats
{
	std::map<std::string, int> outDataLenghtPerHost;
	std::map<std::string, int> outPacketsNumPerHost;
};


struct HttpResponseStats
{
	std::map<std::string, int> inDataLenghtPerHost;
	std::map<std::string, int> inPacketsNumPerHost;
};


class HttpStatsCollector
{
public:

	explicit HttpStatsCollector(uint16_t dstPort)
	{
		m_DstPort = dstPort;
	}

	void collectStats(pcpp::Packet* httpPacket)
	{
		if (!httpPacket->isPacketOfType(pcpp::TCP))
			return;

		pcpp::TcpLayer* tcpLayer = httpPacket->getLayerOfType<pcpp::TcpLayer>();
		if (!(tcpLayer->getDstPort() == m_DstPort || tcpLayer->getSrcPort() == m_DstPort))
			return;

		int dataSize = 0;

		uint32_t hashVal = collectHttpTrafficStats(httpPacket, &dataSize);

		if (httpPacket->isPacketOfType(pcpp::HTTPRequest))
		{
			pcpp::HttpRequestLayer* req = httpPacket->getLayerOfType<pcpp::HttpRequestLayer>();
			collectRequestStats(req, dataSize);
		}
		else if (httpPacket->isPacketOfType(pcpp::HTTPResponse))
		{
			pcpp::HttpResponseLayer* res = httpPacket->getLayerOfType<pcpp::HttpResponseLayer>();
			collectResponseStats(res, dataSize);
		}
	}

	HttpRequestStats& getRequestStats() { return m_RequestStats; }
	HttpResponseStats& getResponseStats() { return m_ResponseStats; }

private:

	std::string lastRequestHost = "";

	uint32_t collectHttpTrafficStats(pcpp::Packet* httpPacket, int* dataSize)
	{
		pcpp::TcpLayer* tcpLayer = httpPacket->getLayerOfType<pcpp::TcpLayer>();

		*dataSize = tcpLayer->getLayerPayloadSize();

		uint32_t hashVal = pcpp::hash5Tuple(httpPacket);

		return hashVal;
	}


	void collectRequestStats(pcpp::HttpRequestLayer* req, int dataSize)
	{
		pcpp::HeaderField* hostField = req->getFieldByName(PCPP_HTTP_HOST_FIELD);

		m_RequestStats.outDataLenghtPerHost[hostField->getFieldValue()] += dataSize;
		m_RequestStats.outPacketsNumPerHost[hostField->getFieldValue()]++;

		lastRequestHost = hostField->getFieldValue();
	}


	void collectResponseStats(pcpp::HttpResponseLayer* res, int dataSize)
	{
		m_ResponseStats.inDataLenghtPerHost[lastRequestHost] += dataSize;
		m_ResponseStats.inPacketsNumPerHost[lastRequestHost]++;
	}

	HttpRequestStats m_RequestStats;
	HttpRequestStats m_PrevRequestStats;
	HttpResponseStats m_ResponseStats;
	HttpResponseStats m_PrevResponseStats;

	uint16_t m_DstPort;
};