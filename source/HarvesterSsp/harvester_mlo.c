/*
 * If not stated otherwise in this file or this component's Licenses.txt file
 * the following copyright and licenses apply:
 *
 * Copyright 2025 RDK Management
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "harvester_mlo.h"
#include <rbus/rbus.h>
#include "harvester_rbus_api.h"
#include "../../include/ccsp_harvesterLog_wrapper.h"
#include "safec_lib_common.h"
#include <cJSON.h>

/* Global variable for MLO RFC enable status */
static bool g_MLORfcEnabled = false;

/**
 * @brief Get MLO RFC enable status
 */
bool get_HarvesterMLORfcEnable(void)
{
    return g_MLORfcEnabled;
}

/**
 * @brief Set MLO RFC enable status and persist to PSM
 */
int set_HarvesterMLORfcEnable(bool bValue)
{
    // Updare global mlo rfc variable
    g_MLORfcEnabled = bValue;

    // Update PSM DB Value
    rbusError_t retPsmSet = RBUS_ERROR_SUCCESS;
    char *buf = NULL;

    buf = bValue ? strdup("true") : strdup("false");
    if (buf == NULL)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, %s: strdup failed\n", __FUNCTION__));
        return 1;
    }

    retPsmSet = rbus_StoreValueIntoPsmDB(HARVESTER_MLO_RFC_PARAM, buf);
    if (retPsmSet != RBUS_ERROR_SUCCESS)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, %s: PSM set failed ret %d for parameter %s and value %s\n", __FUNCTION__, retPsmSet, HARVESTER_MLO_RFC_PARAM, buf));
        free(buf);
        return 1;
    }

    CcspHarvesterTrace(("RDK_LOG_INFO, %s: PSM set success for parameter %s and value %s\n", __FUNCTION__, HARVESTER_MLO_RFC_PARAM, buf));
    free(buf);
    return 0;
}

/**
 * @brief RBUS Get handler for MLO RFC parameter
 */
static rbusError_t harvesterMLO_RfcGetHandler(rbusHandle_t handle, rbusProperty_t property, rbusGetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;

    const char *propertyName;
    propertyName = rbusProperty_GetName(property);
    if (propertyName == NULL)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, %s: Unable to handle get request for property\n", __FUNCTION__));
        return RBUS_ERROR_INVALID_INPUT;
    }

    CcspHarvesterTrace(("RDK_LOG_DEBUG, %s: Property Name is %s\n", __FUNCTION__, propertyName));

    if (strcmp(propertyName, HARVESTER_MLO_RFC_PARAM) != 0)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, %s: Unexpected parameter %s\n", __FUNCTION__, propertyName));
        return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
    }

    rbusError_t retPsmGet = RBUS_ERROR_SUCCESS;
    rbusValue_t value;
    rbusValue_Init(&value);
    char *tmpchar = NULL;

    /* Get value from PSM DB */
    retPsmGet = rbus_GetValueFromPsmDB(HARVESTER_MLO_RFC_PARAM, &tmpchar);
    if (retPsmGet == RBUS_ERROR_SUCCESS)
    {
      if (tmpchar != NULL)
      {
          if ((strcmp(tmpchar, "true") == 0) || (strcmp(tmpchar, "TRUE") == 0))
          {
            g_MLORfcEnabled = true;
          }
          else
          {
            g_MLORfcEnabled = false;
          }
          free(tmpchar);
      }
      CcspHarvesterTrace(("RDK_LOG_DEBUG, %s: MLO RFC value from PSM = %d\n", __FUNCTION__, g_MLORfcEnabled));
    }
    else
    {
      CcspHarvesterTrace(("RDK_LOG_WARN, %s: PSM get failed ret %d, using cached value %d\n",__FUNCTION__, retPsmGet, g_MLORfcEnabled));
    }

    rbusValue_SetBoolean(value, g_MLORfcEnabled);
    rbusProperty_SetValue(property, value);
    rbusValue_Release(value);

    CcspHarvesterTrace(("RDK_LOG_INFO, %s: Mlo Rfc value fetched is %s\n", __FUNCTION__, g_MLORfcEnabled ? "true" : "false"));
    return RBUS_ERROR_SUCCESS;
}

/**
 * @brief RBUS Set handler for MLO RFC parameter
 */
static rbusError_t harvesterMLO_RfcSetHandler(rbusHandle_t handle, rbusProperty_t prop, rbusSetHandlerOptions_t* opts)
{
    (void)handle;
    (void)opts;
    const char *propertyName;
    propertyName = rbusProperty_GetName(prop);
    if (propertyName == NULL)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, %s: Unable to handle get request for property\n", __FUNCTION__));
        return RBUS_ERROR_INVALID_INPUT;
    }

    CcspHarvesterTrace(("RDK_LOG_DEBUG, %s: Property Name is %s\n", __FUNCTION__, propertyName));

    if (strcmp(propertyName, HARVESTER_MLO_RFC_PARAM) != 0)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, %s: Unexpected parameter %s\n", __FUNCTION__, propertyName));
        return RBUS_ERROR_ELEMENT_DOES_NOT_EXIST;
    }
    
    rbusValue_t paramValue_t = NULL;
    rbusValueType_t type;

    paramValue_t = rbusProperty_GetValue(prop);
    if (paramValue_t == NULL)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, %s: value is NULL\n", __FUNCTION__));
        return RBUS_ERROR_INVALID_INPUT;
    }

    type = rbusValue_GetType(paramValue_t);
    if (type != RBUS_BOOLEAN)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, %s: Unexpected value type %d\n", __FUNCTION__, type));
        return RBUS_ERROR_INVALID_INPUT;
    }

    bool paramVal = rbusValue_GetBoolean(paramValue_t);
    CcspHarvesterTrace(("RDK_LOG_INFO, %s: Setting MLO RFC to %s\n", __FUNCTION__, paramVal ? "true" : "false"));

    if (set_HarvesterMLORfcEnable(paramVal) != 0) {
        CcspHarvesterTrace(("RDK_LOG_ERROR, %s: set_HarvesterMLORfcEnable failed\n", __FUNCTION__));
        return RBUS_ERROR_BUS_ERROR;
    }

    CcspHarvesterTrace(("RDK_LOG_INFO, %s: MLO RFC set successfully to %s\n", 
                        __FUNCTION__, paramVal ? "true" : "false"));
    return RBUS_ERROR_SUCCESS;
}

/**
 * @brief Initialize and register MLO RFC RBUS data elements
 */
int regHarvesterDataModel()
{
    rbusError_t ret = RBUS_ERROR_SUCCESS;
    rbusHandle_t handle = get_rbus_handle();


    if (handle == NULL)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, %s: rbus handle is NULL\n", __FUNCTION__));
        return -1;
    }

    CcspHarvesterTrace(("RDK_LOG_INFO, %s: Registering MLO RFC parameter %s\n", __FUNCTION__, HARVESTER_MLO_RFC_PARAM));

    rbusDataElement_t dataElements[1] = {
      {HARVESTER_MLO_RFC_PARAM, RBUS_ELEMENT_TYPE_PROPERTY, {harvesterMLO_RfcGetHandler, harvesterMLO_RfcSetHandler, NULL, NULL, NULL, NULL}}
    };

    ret = rbus_regDataElements(handle, 1, dataElements);

    if (ret != RBUS_ERROR_SUCCESS)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, %s: rbus_regDataElements failed with error %d\n", __FUNCTION__, ret));
        return -1;
    }
    return 0;
}

/**
 * @brief Unregister MLO RFC RBUS data elements
 */
void harvesterMLO_RfcUninit(void)
{
    rbusHandle_t handle = get_rbus_handle();

    if (handle == NULL) {
        CcspHarvesterTrace(("RDK_LOG_ERROR, %s: rbus handle is NULL\n", __FUNCTION__));
        return;
    }

    CcspHarvesterTrace(("RDK_LOG_INFO, %s: Unregistering MLO RFC parameter\n", __FUNCTION__));

    rbusDataElement_t dataElements[1] = {
        {HARVESTER_MLO_RFC_PARAM, RBUS_ELEMENT_TYPE_PROPERTY, {harvesterMLO_RfcGetHandler, harvesterMLO_RfcSetHandler, NULL, NULL, NULL, NULL}}
    };

    rbus_unregDataElements(handle, 1, dataElements);
    CcspHarvesterTrace(("RDK_LOG_INFO, %s: MLO RFC unregistration done\n", __FUNCTION__));
}

/**
 * @brief Parse MLO format JSON into structures
 */
/**
 * @brief Parse MLO format JSON into structures
 */
int mlo_parseAssociatedDeviceDiagnostics(void *jsonVal, harvester_associated_dev_t **associated_dev, uint32_t *assocDevCount, char **vapIndex)
{
    cJSON *json = (cJSON *)jsonVal;
    cJSON *outerArr = NULL;
    cJSON *item = NULL;
    cJSON *vapItem = NULL;
    cJSON *clientsArr = NULL;
    cJSON *client = NULL;
    cJSON *linksArr = NULL;
    cJSON *link = NULL;
    cJSON *jsonItem = NULL;
    harvester_associated_dev_t *dev = NULL;
    int i = 0, j = 0, k = 0, m = 0;
    uint32_t totalLinks = 0;
    errno_t rc = -1;

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s: Entered\n", __FUNCTION__));

    if (json == NULL || associated_dev == NULL || assocDevCount == NULL || vapIndex == NULL)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, try_parse: NULL parameter\n"));
        return 1;
    }

    *associated_dev = NULL;
    *assocDevCount = 0;
    *vapIndex = NULL;

    outerArr = cJSON_GetObjectItem(json, "AssociatedClientsDiagnostics");
    if (outerArr == NULL)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s: no associated mlo devices clients are connected\n", __FUNCTION__));
        return 1;
    }
    
    int outerArrSize = cJSON_GetArraySize(outerArr);
    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s: Found AssociatedClientsDiagnostics size %d\n", __FUNCTION__, outerArrSize));

    /* First Pass: Count Total Links to allocate memory */
    for(m = 0; m < outerArrSize; m++)
    {
        item = cJSON_GetArrayItem(outerArr, m);
        if (item == NULL) continue;
        
        clientsArr = cJSON_GetObjectItem(item, "AssociatedClientDiagnostics");
        if (clientsArr != NULL)
        {
            int numClients = cJSON_GetArraySize(clientsArr);
            for(i = 0; i < numClients; i++)
            {
                client = cJSON_GetArrayItem(clientsArr, i);
                if(client != NULL)
                {
                     // Check if Links array exists
                     linksArr = cJSON_GetObjectItem(client, "Links");
                     if (linksArr != NULL)
                     {
                         totalLinks += cJSON_GetArraySize(linksArr);
                     }
                     else
                     {
                         // Fallback: If no Links array, maybe it's just a legacy-style MLD entry? 
                         // But schema implies MLD -> Links. If missing, assume 0 or 1? 
                         // Assuming MLO enabled structure always has Links.
                         // If singular, we might handle it, but for now expect Links array.
                         CcspHarvesterTrace(("RDK_LOG_WARN, %s: MLD Client %d has no Links array\n", __FUNCTION__, i));
                     }
                }
            }
        }
    }

    CcspHarvesterConsoleTrace(("RDK_LOG_DEBUG, %s: Total Links found: %u\n", __FUNCTION__, totalLinks));

    if (totalLinks == 0)
    {
        return 0;
    }

    /* Allocate Memory */
    dev = (harvester_associated_dev_t *)calloc(totalLinks, sizeof(harvester_associated_dev_t));
    if (dev == NULL)
    {
        CcspHarvesterTrace(("RDK_LOG_ERROR, Harvester %s: Memory allocation failed for %d devices\n", __FUNCTION__, totalLinks));
        return 1;
    }

    /* Second Pass: Populate Data */
    uint32_t current_idx = 0;
    for(m = 0; m < outerArrSize; m++)
    {
        item = cJSON_GetArrayItem(outerArr, m);
        if (item == NULL) continue;

        char *currentVapIndex = NULL;
        vapItem = cJSON_GetObjectItem(item, "VapIndex");
        if (vapItem != NULL && vapItem->valuestring != NULL)
        {
             currentVapIndex = vapItem->valuestring;
             // Set the first found VapIndex as the output for compatibility, if not set
             if (*vapIndex == NULL) *vapIndex = strdup(currentVapIndex);
        }

        clientsArr = cJSON_GetObjectItem(item, "AssociatedClientDiagnostics");
        if (clientsArr == NULL) continue;

        int numClients = cJSON_GetArraySize(clientsArr);
        for(i = 0; i < numClients; i++)
        {
            client = cJSON_GetArrayItem(clientsArr, i);
            if(client == NULL) continue;

            // Extract MLD common fields
            char mldMac[32] = {0};
            bool mldEnable = false;

            jsonItem = cJSON_GetObjectItem(client, "MLDMAC");
            if (jsonItem != NULL && jsonItem->valuestring != NULL)
            {
                strncpy(mldMac, jsonItem->valuestring, sizeof(mldMac)-1);
            }

            jsonItem = cJSON_GetObjectItem(client, "MLDEnable");
            if (jsonItem != NULL)
            {
               // Handle bool or string/int 0/1
               if(cJSON_IsBool(jsonItem)) mldEnable = cJSON_IsTrue(jsonItem);
               else if(cJSON_IsString(jsonItem)) mldEnable = (atoi(jsonItem->valuestring) == 1);
               else if(cJSON_IsNumber(jsonItem)) mldEnable = (jsonItem->valueint == 1);
            }

            linksArr = cJSON_GetObjectItem(client, "AssociatedClientDiagnostics"); // The JSON Request implies inner array is also named this? 
            // Wait, looking at USER_REQUEST:
            // "AssociatedClientsDiagnostics": [ { "VapIndex":..., "AssociatedClientDiagnostics": [ { "MAC":..., "Links": [ ... ] } ] } ]
            // Correction: The User Request example shows:
            // "AssociatedClientDiagnostics": [
            //    { "MAC": "...", "MLDMAC": "...", ... "Band": "2G", ... }, 
            //    { "MAC": "...", "MLDMAC": "...", ... "Band": "5G", ... }
            // ]
            // It seems "AssociatedClientDiagnostics" inside "AssociatedClientsDiagnostics" IS THE LIST OF LINKS directly?
            // The JSON structure in the USER EXAMPLE (Step 0) is:
            // { "Version": "1.1", "AssociatedClientsDiagnostics": [ { "VapIndex": "...", "AssociatedClientDiagnostics": [ { "MAC": "...", "Band": "2G", "MLDMAC": "...", ... }, { "MAC": "...", "Band": "5G", ... } ] } ] }
            //
            // **CRITICAL OBSERVATION**: In the user's example, the inner array "AssociatedClientDiagnostics" contains objects that HAVE "MAC", "Band", "MLDMAC", etc.
            // This means the JSON is ALREADY FLATTENED (or relatively flat). It lists Links directly, where each Link has MLDMAC property.
            // There is NO "Links" array nested inside.
            //
            // My previous parsing logic assumed MLD -> Links array. 
            // The new JSON format (Step 0) shows Links are direct children of the VAP object's list.
            //
            // I must adapt to this.
            
            // Re-evaluating based on Step 0 JSON:
            // Loop Outer (VAPs)
            //   Loop Inner "AssociatedClientDiagnostics" (Links)
            //     Parse "MAC" -> cli_MACAddress
            //     Parse "MLDMAC" -> mld_mac
            //     Parse "Band" -> frequency_band
            //     Etc.

            // So I need to correct my loop logic. 
            // linksArr IS clientsArr in this context if the JSON is flat list of links.
            // But wait, "AssociatedClientDiagnostics" [ { ... } ]. Is { ... } a Link or a Client?
            // It has "MAC" and "Band". And "MLDMAC".
            // It looks like a Link-level object that carries MLD context.
            // So YES, it is flat.

            // Let's implement based on Step 0 structure.
            
            // Extract Link Data directly from 'client' (which in this case is a link entry)
            harvester_associated_dev_t *dst = &dev[current_idx];
            
            // MLD Context
            if (currentVapIndex)
            {
                rc = strcpy_s(dst->vap_index, sizeof(dst->vap_index), currentVapIndex);
                ERR_CHK(rc);
            }

            jsonItem = cJSON_GetObjectItem(client, "MLDMAC");
             if (jsonItem != NULL && jsonItem->valuestring != NULL)
            {
                rc = strcpy_s(dst->mld_mac, sizeof(dst->mld_mac), jsonItem->valuestring);
                ERR_CHK(rc);
            }
            
            jsonItem = cJSON_GetObjectItem(client, "MLDEnable");
            if (jsonItem != NULL)
            {
               if(cJSON_IsBool(jsonItem)) dst->mld_enable = cJSON_IsTrue(jsonItem);
               else if(cJSON_IsString(jsonItem)) dst->mld_enable = (atoi(jsonItem->valuestring) == 1);
               else if(cJSON_IsNumber(jsonItem)) dst->mld_enable = (jsonItem->valueint == 1);
            }

            // Link Data
            jsonItem = cJSON_GetObjectItem(client, "MAC");
            if (jsonItem != NULL && jsonItem->valuestring != NULL) {
                sscanf(jsonItem->valuestring, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
                       &dst->cli_MACAddress[0], &dst->cli_MACAddress[1],
                       &dst->cli_MACAddress[2], &dst->cli_MACAddress[3],
                       &dst->cli_MACAddress[4], &dst->cli_MACAddress[5]);
            }

            jsonItem = cJSON_GetObjectItem(client, "Band");
            if (jsonItem != NULL && jsonItem->valuestring != NULL)
            {
                rc = strcpy_s(dst->frequency_band, sizeof(dst->frequency_band), jsonItem->valuestring);
                ERR_CHK(rc);
            }
            
            // Other Metrics
            jsonItem = cJSON_GetObjectItem(client, "RSSI");
            if (jsonItem) dst->cli_RSSI = atoi(jsonItem->valuestring);
            
            jsonItem = cJSON_GetObjectItem(client, "SignalStrength");
            if (jsonItem) dst->cli_SignalStrength = atoi(jsonItem->valuestring);
            
            jsonItem = cJSON_GetObjectItem(client, "SNR");
            if (jsonItem) dst->cli_SNR = atoi(jsonItem->valuestring);
            
            jsonItem = cJSON_GetObjectItem(client, "BytesSent");
            if (jsonItem) dst->cli_BytesSent = strtoull(jsonItem->valuestring, NULL, 10);
            
            jsonItem = cJSON_GetObjectItem(client, "BytesReceived");
            if (jsonItem) dst->cli_BytesReceived = strtoull(jsonItem->valuestring, NULL, 10);

            jsonItem = cJSON_GetObjectItem(client, "PacketsSent");
            if (jsonItem) dst->cli_PacketsSent = strtoull(jsonItem->valuestring, NULL, 10);

            jsonItem = cJSON_GetObjectItem(client, "PacketsRecieved");
            if (jsonItem) dst->cli_PacketsReceived = strtoull(jsonItem->valuestring, NULL, 10);

            jsonItem = cJSON_GetObjectItem(client, "Errors");
            if (jsonItem) dst->cli_Errors = atoi(jsonItem->valuestring);

            jsonItem = cJSON_GetObjectItem(client, "RetransCount"); // Not standard in wifi_associated_dev_t but was in MLO struct. 
                                                                    // Check if base has it. Hal dev_t sometimes has X_COMCAST_ stuff.
                                                                    // Assuming base has only standard fields. 
                                                                    // Previous code in harvester_associated_devices.c debug prints showed:
                                                                    // cli_Retransmissions.
            jsonItem = cJSON_GetObjectItem(client, "Retransmissions");
            if (jsonItem) dst->cli_Retransmissions = atoi(jsonItem->valuestring);
            
            jsonItem = cJSON_GetObjectItem(client, "AuthenticationFailures");
            if (jsonItem) dst->cli_AuthenticationFailures = atoi(jsonItem->valuestring);

            jsonItem = cJSON_GetObjectItem(client, "AuthenticationState");
             if (jsonItem) dst->cli_AuthenticationState = (atoi(jsonItem->valuestring) == 1);
            
            jsonItem = cJSON_GetObjectItem(client, "Active");
             if (jsonItem) dst->cli_Active = (atoi(jsonItem->valuestring) == 1);
            
            jsonItem = cJSON_GetObjectItem(client, "Disassociations");
            if (jsonItem) dst->cli_Disassociations = atoi(jsonItem->valuestring);

            jsonItem = cJSON_GetObjectItem(client, "OperatingStandard");
            if (jsonItem && jsonItem->valuestring) {
                rc = strcpy_s(dst->cli_OperatingStandard, sizeof(dst->cli_OperatingStandard), jsonItem->valuestring);
                ERR_CHK(rc);
            }
            
            jsonItem = cJSON_GetObjectItem(client, "OperatingChannelBandwidth");
            if (jsonItem && jsonItem->valuestring) {
                rc = strcpy_s(dst->cli_OperatingChannelBandwidth, sizeof(dst->cli_OperatingChannelBandwidth), jsonItem->valuestring);
                ERR_CHK(rc);
            }

             jsonItem = cJSON_GetObjectItem(client, "InterferenceSources");
            if (jsonItem && jsonItem->valuestring) {
                rc = strcpy_s(dst->cli_InterferenceSources, sizeof(dst->cli_InterferenceSources), jsonItem->valuestring);
                ERR_CHK(rc);
            }

            jsonItem = cJSON_GetObjectItem(client, "DataFramesSentNoAck");
            if (jsonItem) dst->cli_DataFramesSentNoAck = strtoull(jsonItem->valuestring, NULL, 10);
            
            jsonItem = cJSON_GetObjectItem(client, "DataFramesSentAck"); // "Acknowledgements" in JSON? 
            // User JSON has "Acknowledgements": "170000".
             jsonItem = cJSON_GetObjectItem(client, "Acknowledgements");
            if (jsonItem) dst->cli_DataFramesSentAck = strtoull(jsonItem->valuestring, NULL, 10);

            current_idx++;
        }
    }
    
    *associated_dev = dev;
    *assocDevCount = totalLinks;
    
    CcspHarvesterTrace(("RDK_LOG_INFO, mlo_parseAssociatedDeviceDiagnostics: Successfully Parsed %u MLO Links\n", totalLinks));
}
