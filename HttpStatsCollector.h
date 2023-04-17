#pragma once

#include <map>
#include <sstream>
#include "HttpLayer.h"
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "PayloadLayer.h"
#include "PacketUtils.h"
#include "SystemUtils.h"


/**
 * A struct for collecting stats on all HTTP requests
 */
struct HttpRequestStats
{
	std::map<std::string, int> outDataLenghtPerHost;
	std::map<std::string, int> outPacketsNumPerHost;
};


/**
 * A struct for collecting stats on all HTTP responses
 */
struct HttpResponseStats
{
	std::map<std::string, int> inDataLenghtPerHost;
	std::map<std::string, int> inPacketsNumPerHost;
};


/**
 * The HTTP stats collector. Should be called for every packet arriving and also periodically to calculate rates
 */
class HttpStatsCollector
{
public:

	/**
	 * C'tor - clear all structures
	 */
	explicit HttpStatsCollector(uint16_t dstPort)
	{
		m_DstPort = dstPort;
	}

	/**
	 * Collect stats for a single packet
	 */
	void collectStats(pcpp::Packet* httpPacket)
	{
		// verify packet is TCP
		if (!httpPacket->isPacketOfType(pcpp::TCP))
			return;

		// verify packet is port 80
		pcpp::TcpLayer* tcpLayer = httpPacket->getLayerOfType<pcpp::TcpLayer>();
		if (!(tcpLayer->getDstPort() == m_DstPort || tcpLayer->getSrcPort() == m_DstPort))
			return;

		int dataSize = 0;

		// collect general HTTP traffic stats on this packet
		uint32_t hashVal = collectHttpTrafficStats(httpPacket, &dataSize);

		// if packet is an HTTP request - collect HTTP request stats on this packet
		if (httpPacket->isPacketOfType(pcpp::HTTPRequest))
		{
			pcpp::HttpRequestLayer* req = httpPacket->getLayerOfType<pcpp::HttpRequestLayer>();
			collectRequestStats(req, dataSize);
		}
		// if packet is an HTTP response - collect HTTP response stats on this packet
		else if (httpPacket->isPacketOfType(pcpp::HTTPResponse))
		{
			pcpp::HttpResponseLayer* res = httpPacket->getLayerOfType<pcpp::HttpResponseLayer>();
			collectResponseStats(res, dataSize);
		}
	}

	/**
	 * Get HTTP request stats
	 */
	HttpRequestStats& getRequestStats() { return m_RequestStats; }

	/**
	 * Get HTTP response stats
	 */
	HttpResponseStats& getResponseStats() { return m_ResponseStats; }

private:

	std::string lastRequestHost = "";

	/**
	 * Collect stats relevant for every HTTP packet (request, response or any other)
	 * This method calculates and returns the flow key for this packet
	 */
	uint32_t collectHttpTrafficStats(pcpp::Packet* httpPacket, int* dataSize)
	{
		pcpp::TcpLayer* tcpLayer = httpPacket->getLayerOfType<pcpp::TcpLayer>();

		*dataSize = tcpLayer->getLayerPayloadSize();

		// calculate a hash key for this flow to be used in the flow table
		uint32_t hashVal = pcpp::hash5Tuple(httpPacket);

		return hashVal;
	}


	/**
	 * Collect stats relevant for HTTP request messages
	 */
	void collectRequestStats(pcpp::HttpRequestLayer* req, int dataSize)
	{
		// extract hostname and add to hostname count map
		pcpp::HeaderField* hostField = req->getFieldByName(PCPP_HTTP_HOST_FIELD);

		m_RequestStats.outDataLenghtPerHost[hostField->getFieldValue()] += dataSize;
		m_RequestStats.outPacketsNumPerHost[hostField->getFieldValue()]++;

		lastRequestHost = hostField->getFieldValue();
	}


	/**
	 * Collect stats relevant for HTTP response messages
	 */
	void collectResponseStats(pcpp::HttpResponseLayer* res, int dataSize)
	{
		// extract content-type and add to content-type map
		pcpp::HeaderField* contentTypeField = res->getFieldByName(PCPP_HTTP_CONTENT_TYPE_FIELD);
		if (contentTypeField != NULL)
		{
			std::string contentType = contentTypeField->getFieldValue();

			// sometimes content-type contains also the charset it uses.
			// for example: "application/javascript; charset=UTF-8"
			// remove charset as it's not relevant for these stats
			size_t charsetPos = contentType.find(";");
			if (charsetPos != std::string::npos)
				contentType.resize(charsetPos);
		}

		// collect status code - create one string from status code and status description (for example: 200 OK)
		std::ostringstream stream;
		stream << res->getFirstLine()->getStatusCodeAsInt();
		std::string statusCode = stream.str() + " " + res->getFirstLine()->getStatusCodeString();

		m_ResponseStats.inDataLenghtPerHost[lastRequestHost] += dataSize;
		m_ResponseStats.inPacketsNumPerHost[lastRequestHost]++;
	}

	HttpRequestStats m_RequestStats;
	HttpRequestStats m_PrevRequestStats;
	HttpResponseStats m_ResponseStats;
	HttpResponseStats m_PrevResponseStats;

	uint16_t m_DstPort;
};