/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#ifndef _HARVESTER_AVRO_H
#define _HARVESTER_AVRO_H

#include <sys/time.h>
#include <stdint.h>
#include <wifi_hal.h>
#include <pthread.h>
#include <pthread.h>

#ifndef UNIT_TEST_DOCKER_SUPPORT
    #define STATIC                    static
#else
    #define STATIC
#endif

#include <stdbool.h>

#define MAC_STR_LEN 18

typedef struct _harvester_associated_dev_t {
    unsigned char cli_MACAddress[6];
    char cli_IPAddress[64];
    char cli_OperatingStandard[64];
    char cli_OperatingChannelBandwidth[64];
    char cli_InterferenceSources[64];
    uint32_t cli_LastDataDownlinkRate;
    uint32_t cli_LastDataUplinkRate;
    int32_t cli_SignalStrength;
    uint64_t cli_BytesReceived;
    uint64_t cli_BytesSent;
    uint64_t cli_PacketsReceived;
    uint64_t cli_PacketsSent;
    int32_t cli_RSSI;
    int32_t cli_MinRSSI;
    int32_t cli_MaxRSSI;
    uint32_t cli_Disassociations;
    uint32_t cli_AuthenticationFailures;
    uint32_t cli_Associations; // In case needed
    bool cli_AuthenticationState;
    bool cli_Active;
    uint32_t cli_Retransmissions;
    int32_t cli_SNR;
    uint64_t cli_DataFramesSentAck;
    uint64_t cli_DataFramesSentNoAck;
    uint32_t cli_Errors;
    // MLO fields
    char mld_mac[MAC_STR_LEN];
    bool mld_enable;
    char vap_index[32];
    char frequency_band[8];
} harvester_associated_dev_t;

struct associateddevicedata
{
struct timeval timestamp;
char* sSidName;
char* bssid;
char* radioOperatingFrequencyBand; //Possible value 2.4Ghz and 5.0 Ghz
ULONG radioChannel;  // Possible Value between 1-11
ULONG numAssocDevices;
harvester_associated_dev_t* devicedata;

struct associateddevicedata *next;
};


struct neighboringapdata
{
struct timeval timestamp;
char* radioName;
char* radioOperatingFrequencyBand; //Possible value 2.4Ghz and 5.0 Ghz
ULONG radioChannel;  // Possible Value between 1-11
ULONG numNeibouringAP;
wifi_neighbor_ap2_t* napdata;

struct neighboringapdata *next;
};


struct radiotrafficdata
{
struct timeval timestamp;
char* radioBssid;
BOOL  enabled;
char* radioOperatingFrequencyBand; //Possible value 2.4Ghz and 5.0 Ghz
ULONG radioChannel;  // Possible Value between 1-11
char* radiOperatingChannelBandwidth;
wifi_radioTrafficStats2_t* rtdata;
};

extern void harvester_report_associateddevices(struct associateddevicedata *head, char* ServiceType);
extern void harvester_report_neighboringap(struct neighboringapdata *head);
extern void harvester_report_radiotraffic(struct radiotrafficdata *head);

#endif /* !_HARVESTER_AVRO_H */
