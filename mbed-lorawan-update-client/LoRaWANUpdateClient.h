/*
* PackageLicenseDeclared: Apache-2.0
* Copyright (c) 2018 ARM Limited
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef _LORAWAN_UPDATE_CLIENT_H_
#define _LORAWAN_UPDATE_CLIENT_H_

#include "mbed.h"
#include "mbed_delta_update.h"
#include "mbed_stats.h"
#include "BDFile.h"
#include "FragmentationSha256.h"
#include "FragmentationEcdsaVerify.h"
#include "FragmentationBlockDeviceWrapper.h"
#include "arm_uc_metadata_header_v2.h"
#include "update_params.h"
#include "update_types.h"
#include "tiny-aes.h"   // @todo: replace by Mbed TLS / hw crypto?

#include "mbed_trace.h"
#define TRACE_GROUP "LWUC"

#ifndef NB_FRAG_GROUPS
#define NB_FRAG_GROUPS          1
#endif // NB_FRAG_GROUPS

#ifndef NB_MC_GROUPS
#define NB_MC_GROUPS          1
#endif // NB_MC_GROUPS

#ifndef LW_UC_SHA256_BUFFER_SIZE
#define LW_UC_SHA256_BUFFER_SIZE       128
#endif // LW_UC_SHA256_BUFFER_SIZE

#ifndef LW_UC_JANPATCH_BUFFER_SIZE
#define LW_UC_JANPATCH_BUFFER_SIZE     528
#endif // LW_UC_JANPATCH_BUFFER_SIZE

enum LW_UC_STATUS {
    LW_UC_OK = 0,
    LW_UC_INVALID_PACKET_LENGTH = 1,
    LW_UC_UNKNOWN_COMMAND = 2,
    LW_UC_FRAG_SESSION_NOT_ACTIVE = 3,
    LW_UC_PROCESS_FRAME_FAILED = 4,
    LW_UC_BD_READ_ERROR = 5,
    LW_UC_BD_WRITE_ERROR = 6,
    LW_UC_SIGNATURE_MANUFACTURER_UUID_MISMATCH = 7,
    LW_UC_SIGNATURE_DEVICECLASS_UUID_MISMATCH = 8,
    LW_UC_SIGNATURE_ECDSA_FAILED = 9,
    LW_UC_OUT_OF_MEMORY = 10,
    LW_UC_CREATE_BOOTLOADER_HEADER_FAILED = 11,
    LW_UC_INVALID_SLOT = 12,
    LW_UC_DIFF_SIZE_MISMATCH = 13,
    LW_UC_DIFF_INCORRECT_SLOT2_HASH = 14,
    LW_UC_DIFF_DELTA_UPDATE_FAILED = 15
};

enum LW_UC_EVENT {
    LW_UC_EVENT_FIRMWARE_READY = 0,
    LW_UC_EVENT_FRAGSESSION_COMPLETE = 1
};

class LoRaWANUpdateClient {
public:
    /**
     * Initialize a new LoRaWANUpdateClient
     *
     * @param bd A block device
     * @param appKey Application Key, used to derive session keys from multicast keys
     * @param send_fn A send function, invoked when we want to relay data back to the network
     */
    LoRaWANUpdateClient(BlockDevice *bd, const uint8_t appKey[16], Callback<void(uint8_t, uint8_t*, size_t)> send_fn)
        : _bd(bd), _send_fn(send_fn), _event_cb(NULL)
    {
        memcpy(_appKey, appKey, 16);

        for (size_t ix = 0; ix < NB_FRAG_GROUPS; ix++) {
            frag_sessions[ix].active = false;
            frag_sessions[ix].session = NULL;
        }

        for (size_t ix = 0; ix < NB_MC_GROUPS; ix++) {
            mc_groups[ix].active = false;
        }
    }

    /**
     * Sets the event callback (will let you know when firmware is complete and ready to flash)
     * @param fn Callback function
     */
    void setEventCallback(Callback<void(LW_UC_EVENT)> fn) {
        _event_cb = fn;
    }

    /**
     * Handle packets that came in on the fragmentation port (e.g. 201)
     */
    LW_UC_STATUS handleFragmentationCommand(uint8_t *buffer, size_t length) {
        if (length == 0) return LW_UC_INVALID_PACKET_LENGTH;

        switch (buffer[0]) {
            case FRAG_SESSION_SETUP_REQ:
                return handleFragmentationSetupReq(buffer + 1, length - 1);

            case DATA_FRAGMENT:
                return handleDataFragment(buffer + 1, length - 1);

            case FRAG_SESSION_DELETE_REQ:
                return handleFragmentationDeleteReq(buffer + 1, length - 1);

            case FRAG_SESSION_STATUS_REQ:
                return handleFragmentationStatusReq(buffer + 1, length - 1);

            case PACKAGE_VERSION_REQ:
                return handleFragmentationPackageVersionReq(buffer + 1, length - 1);

            default:
               return LW_UC_UNKNOWN_COMMAND;
        }
    }

    /**
     * Handle packets that came in on the multicast control port (e.g. 200)
     */
    LW_UC_STATUS handleMulticastControlCommand(uint8_t *buffer, size_t length) {
        if (length == 0) return LW_UC_INVALID_PACKET_LENGTH;

        switch (buffer[0]) {
            case MC_GROUP_SETUP_REQ:
                return handleMulticastSetupReq(buffer + 1, length - 1);

            case MC_GROUP_DELETE_REQ:
                return handleMulticastDeleteReq(buffer + 1, length - 1);

            case MC_GROUP_STATUS_REQ:
                return handleMulticastStatusReq(buffer + 1, length - 1);

            case PACKAGE_VERSION_REQ:
                return handleMulticastPackageVersionReq(buffer + 1, length - 1);

            default:
               return LW_UC_UNKNOWN_COMMAND;
        }
    }

private:

    /**
     * Used by the AS to request the package version implemented by the end-device
     */
    LW_UC_STATUS handleMulticastPackageVersionReq(uint8_t *buffer, size_t length) {
        if (length != 0) {
            return LW_UC_INVALID_PACKET_LENGTH;
        }

        // The identifier of the fragmentation transport package is 2. The version of this package is version 1.
        uint8_t response[PACKAGE_VERSION_ANS_LENGTH] = { PACKAGE_VERSION_ANS, 2, 1 };
        send(MCCONTROL_PORT, response, PACKAGE_VERSION_ANS_LENGTH);

        return LW_UC_OK;
    }

    /**
     * This command is used to create or modify the parameters of a multicast group.
     */
    LW_UC_STATUS handleMulticastSetupReq(uint8_t *buffer, size_t length) {
        if (length != MC_GROUP_SETUP_REQ_LENGTH) {
            // @todo, I assume we need to send a FRAG_SESSION_SETUP_ANS at this point... But not listed in the spec.
            return LW_UC_INVALID_PACKET_LENGTH;
        }

        uint8_t mcIx = buffer[0] & 0b11;

        tr_debug("handleMulticastSetupReq mcIx=%u", mcIx);

        if (mcIx > NB_MC_GROUPS - 1) {
            tr_debug("handleMulticastSetupReq: mcIx out of bounds");
            return sendMulticastSetupAns(true, mcIx);
        }

        // @todo: so the spec allows us to modify a group
        // but what if we're currently in class C mode - how should we change the parameters?

        mc_groups[mcIx].mcAddr = (buffer[4] << 24) + (buffer[3] << 16) + (buffer[2] << 8) + buffer[1];
        memcpy(mc_groups[mcIx].mcKey_Encrypted, buffer + 5, 16);
        mc_groups[mcIx].minFcFCount = (buffer[24] << 24) + (buffer[23] << 16) + (buffer[22] << 8) + buffer[21];
        mc_groups[mcIx].maxFcFCount = (buffer[28] << 24) + (buffer[27] << 16) + (buffer[26] << 8) + buffer[25];

        // Derived from the AppKey.  LoRaWAN 1.1+ end-devices SHALL use this scheme.
        // McRootKey = aes128_encrypt(AppKey, 0x20 | pad16)
        const uint8_t mc_root_key_input[16] = { 0x20, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
        uint8_t mc_root_key_output[16] = {};
        AES_ECB_encrypt(mc_root_key_input, _appKey, mc_root_key_output, 16);

        // McKEKey = aes128_encrypt(McRootKey, 0x00 | pad16)
        const uint8_t mc_e_key_input[16] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
        uint8_t mc_e_key_output[16];
        AES_ECB_encrypt(mc_e_key_input, mc_root_key_output, mc_e_key_output, 16);

        // McKey = aes128_encrypt(McKEKey, McKey_encrypted)
        uint8_t mc_key[16];
        AES_ECB_encrypt(mc_groups[mcIx].mcKey_Encrypted, mc_e_key_output, mc_key, 16);

        // The McAppSKey and the McNetSKey are then derived from the group’s McKey as follow:
        // McAppSKey = aes128_encrypt(McKey, 0x01 | McAddr | pad16)
        // McNetSKey = aes128_encrypt(McKey, 0x02 | McAddr | pad16)
        const uint8_t nwk_input[16] = { 0x01, buffer[1], buffer[2], buffer[3], buffer[4], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
        const uint8_t app_input[16] = { 0x02, buffer[1], buffer[2], buffer[3], buffer[4], 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

        AES_ECB_encrypt(nwk_input, mc_key, mc_groups[mcIx].nwkSKey, 16);
        AES_ECB_encrypt(app_input, mc_key, mc_groups[mcIx].appSKey, 16);

        mc_groups[mcIx].active = true;

        tr_debug("\tmcAddr:         0x%08x", mc_groups[mcIx].mcAddr);
        tr_debug("\tNwkSKey:");
        printf("\t         ");
        for (size_t ix = 0; ix < 16; ix++) {
            printf("%02x ", mc_groups[mcIx].nwkSKey[ix]);
        }
        printf("\n");
        tr_debug("\tAppSKey:");
        printf("\t         ");
        for (size_t ix = 0; ix < 16; ix++) {
            printf("%02x ", mc_groups[mcIx].appSKey[ix]);
        }
        printf("\n");
        tr_debug("\tminFcFCount:    %u", mc_groups[mcIx].minFcFCount);
        tr_debug("\tmaxFcFCount:    %u", mc_groups[mcIx].maxFcFCount);

        return sendMulticastSetupAns(false, mcIx);
    }

    /**
     * Send FRAG_SESSION_ANS to network server with bits set depending on the error indicator
     */
    LW_UC_STATUS sendMulticastSetupAns(bool error, uint8_t mcIx) {
        uint8_t resp = mcIx;
        resp += error ? 0b100 : 0;

        uint8_t buffer[MC_GROUP_SETUP_ANS_LENGTH] = { MC_GROUP_SETUP_ANS, resp };
        send(MCCONTROL_PORT, buffer, MC_GROUP_SETUP_ANS_LENGTH);

        return LW_UC_OK;
    }

    /**
     * This message is used to delete a multicast group from an end-device.
     */
    LW_UC_STATUS handleMulticastDeleteReq(uint8_t *buffer, size_t length) {
        if (length != MC_GROUP_DELETE_REQ_LENGTH) {
            return LW_UC_INVALID_PACKET_LENGTH;
        }

        uint8_t mcIx = buffer[0] & 0b11;

        tr_debug("handleMulticastDeleteReq mcIx=%u", mcIx);

        uint8_t response[MC_GROUP_DELETE_ANS_LENGTH] = { MC_GROUP_DELETE_ANS, mcIx };

        if (mcIx > NB_MC_GROUPS - 1 || !mc_groups[mcIx].active) {
            // set error flag
            response[1] += 0b100;
        }

        mc_groups[mcIx].active = false;

        // clear potentially sensitive details
        mc_groups[mcIx].mcAddr = 0x0;
        memset(mc_groups[mcIx].mcKey_Encrypted, 0, 16);
        memset(mc_groups[mcIx].nwkSKey, 0, 16);
        memset(mc_groups[mcIx].appSKey, 0, 16);
        mc_groups[mcIx].minFcFCount = 0;
        mc_groups[mcIx].maxFcFCount = 0;

        send(MCCONTROL_PORT, response, MC_GROUP_DELETE_ANS_LENGTH);

        return LW_UC_OK;
    }

    /**
     * Get the status of the active multicast groups
     */
    LW_UC_STATUS handleMulticastStatusReq(uint8_t *buffer, size_t length) {
        if (length != MC_GROUP_STATUS_REQ_LENGTH) {
            return LW_UC_INVALID_PACKET_LENGTH;
        }

        // @todo... if a MC group is not active what am I supposed to send? the spec is not clear.
        // I guess we need to discard it because we cannot give status on a non-existing group.

        // max length of the response is 1 byte status + 5 bytes per group...
        uint8_t response[2 + (NB_MC_GROUPS * 5)];

        uint8_t reqGroupMask = buffer[0] & 0b1111;

        uint8_t ansGroupMask = 0;
        uint8_t totalGroups = 0;

        // iterate over the response
        uint8_t *resp_ptr = response + 2;

        for (size_t ix = 0; ix < NB_MC_GROUPS; ix++) {
            bool requested = (reqGroupMask >> ix) & 0b1;

            if (requested && mc_groups[ix].active) {
                totalGroups++;
                ansGroupMask += (1 << ix);

                resp_ptr[0] = ix;
                resp_ptr[1] = mc_groups[ix].mcAddr & 0xff;
                resp_ptr[2] = mc_groups[ix].mcAddr >> 8 & 0xff;
                resp_ptr[3] = mc_groups[ix].mcAddr >> 16 & 0xff;
                resp_ptr[4] = mc_groups[ix].mcAddr >> 24 & 0xff;

                resp_ptr += 5;
            }
        }

        // add the total groups to the mask
        ansGroupMask += (totalGroups << 4);

        response[0] = MC_GROUP_STATUS_ANS;
        response[1] = ansGroupMask;

        // if we didn't use the full response, just cut it off here
        send(MCCONTROL_PORT, response, 2 + (totalGroups * 5));

        return LW_UC_OK;
    }

    /**
     * Start a new fragmentation session
     */
    LW_UC_STATUS handleFragmentationSetupReq(uint8_t *buffer, size_t length) {
        if (length != FRAG_SESSION_SETUP_REQ_LENGTH) {
            // @todo, I assume we need to send a FRAG_SESSION_SETUP_ANS at this point... But not listed in the spec.
            return LW_UC_INVALID_PACKET_LENGTH;
        }

        uint8_t fragIx = (buffer[0] >> 4) & 0b11;

        tr_debug("handleFragmentationSetup fragIx=%u", fragIx);

        if (fragIx > NB_FRAG_GROUPS - 1) {
            tr_debug("handleFragmentationSetup: FSAE_IndexNotSupported");
            sendFragSessionAns(FSAE_IndexNotSupported);
            return LW_UC_OK;
        }

        if (frag_sessions[fragIx].active) {
            if (frag_sessions[fragIx].session) {
                // clear memory associated with the session - this should clear out the full context...
                delete frag_sessions[fragIx].session;
            }
        }

        frag_sessions[fragIx].mcGroupBitMask = buffer[0] & 0b1111;
        frag_sessions[fragIx].nbFrag = (buffer[2] << 8) + buffer[1];
        frag_sessions[fragIx].fragSize = buffer[3];
        frag_sessions[fragIx].fragAlgo = (buffer[4] >> 3) & 0b111;
        frag_sessions[fragIx].blockAckDelay = buffer[4] & 0b111;
        frag_sessions[fragIx].padding = buffer[5];
        frag_sessions[fragIx].descriptor = (buffer[9] << 24) + (buffer[8] << 16) + (buffer[7] << 8) + buffer[6];

        tr_debug("FragmentationSessionSetupReq");
        tr_debug("\tIndex:            %u", fragIx);
        tr_debug("\tMcGroupBitMask:   %u", frag_sessions[fragIx].mcGroupBitMask);
        tr_debug("\tNbFrag:           %u", frag_sessions[fragIx].nbFrag);
        tr_debug("\tFragSize:         %u", frag_sessions[fragIx].fragSize);
        tr_debug("\tFragAlgo:         %u", frag_sessions[fragIx].fragAlgo);
        tr_debug("\tBlockAckDelay:    %u", frag_sessions[fragIx].blockAckDelay);
        tr_debug("\tPadding:          %u", frag_sessions[fragIx].padding);
        tr_debug("\tDescriptor:       %u", frag_sessions[fragIx].descriptor);

        // create a fragmentation session which can handle all this...
        FragmentationSessionOpts_t opts;
        opts.NumberOfFragments = frag_sessions[fragIx].nbFrag;
        opts.FragmentSize = frag_sessions[fragIx].fragSize;
        opts.Padding = frag_sessions[fragIx].padding;
        opts.RedundancyPackets = MBED_CONF_LORAWAN_UPDATE_CLIENT_MAX_REDUNDANCY - 1;

        // @todo, make this dependent on the frag index...
        opts.FlashOffset = MBED_CONF_LORAWAN_UPDATE_CLIENT_SLOT0_FW_ADDRESS;

        frag_sessions[fragIx].sessionOptions = opts;

        FragmentationSession *session = new FragmentationSession(&_bd, opts);
        FragResult init_res = session->initialize();
        if (init_res != FRAG_OK) {
            tr_error("Failed to initialize fragmentation session (out of memory?)");
            delete session;

            sendFragSessionAns(FSAE_NotEnoughMemory);
            return LW_UC_OK;
        }

        frag_sessions[fragIx].session = session;
        frag_sessions[fragIx].active = true;

        sendFragSessionAns(FSAE_None);
        return LW_UC_OK;
    }

    /**
     * Send FRAG_SESSION_ANS to network server with bits set depending on the error indicator
     */
    void sendFragSessionAns(FragmenationSessionAnswerErrors error) {
        uint8_t response = 0b0000;

        switch (error) {
            case FSAE_WrongDescriptor: response = 0b1000; break;
            case FSAE_IndexNotSupported: response = 0b0100; break;
            case FSAE_NotEnoughMemory: response = 0b0010; break;
            case FSAE_EncodingUnsupported: response = 0b0001; break;
            case FSAE_None: response = 0b0000; break;
        }

        uint8_t buffer[2];
        buffer[0] = FRAG_SESSION_SETUP_ANS;
        buffer[1] = response;
        send(FRAGSESSION_PORT, buffer, 2);
    }

    /**
     * Delete a fragmentation session
     */
    LW_UC_STATUS handleFragmentationDeleteReq(uint8_t *buffer, size_t length) {
        if (length != FRAG_SESSION_DELETE_REQ_LENGTH) {
            return LW_UC_INVALID_PACKET_LENGTH;
        }

        uint8_t fragIx = buffer[0] & 0b11;

        tr_debug("handleFragmentationDeleteReq ix=%u", fragIx);

        uint8_t response[FRAG_SESSION_DELETE_ANS_LENGTH] = { FRAG_SESSION_DELETE_ANS, fragIx };

        // fragIndex out of bounds, or not active
        if (fragIx > NB_FRAG_GROUPS - 1 || frag_sessions[fragIx].active == false) {
            tr_debug("session is out of bounds or not active");

            // set bit 3 of the response high
            response[1] += 0b100;
        }

        send(FRAGSESSION_PORT, response, FRAG_SESSION_DELETE_ANS_LENGTH);

        return LW_UC_OK;
    }

    /**
     * Get the status of a fragmentation session
     */
    LW_UC_STATUS handleFragmentationStatusReq(uint8_t *buffer, size_t length) {
        if (length != FRAG_SESSION_STATUS_REQ_LENGTH) {
            return LW_UC_INVALID_PACKET_LENGTH;
        }

        uint8_t fragIx = (buffer[0] >> 1) & 0b11;

        if (fragIx > NB_FRAG_GROUPS - 1) {
            // this is not handled in the specs... ignore?
            return LW_UC_OK;
        }

        tr_debug("handleFragmentationStatusReq ix=%u", fragIx);

        // The “participants” bit signals if all the fragmentation receivers should answer or only the ones still missing fragments.
        // 0 = Only the receivers still missing fragments MUST answer the request
        // 1 = All receivers MUST answer, even those who already successfully reconstructed the data block
        uint8_t participants = buffer[0] & 0b1;

        if (participants == 0) {
            // no active session? OK, done
            if (!frag_sessions[fragIx].active || frag_sessions[fragIx].session == NULL) {
                return LW_UC_OK;
            }
        }

        // otherwise we need to send an update...
        // @todo problem is that we don't have the info anymore after we reconstructed
        if (!frag_sessions[fragIx].active || frag_sessions[fragIx].session == NULL) {
            // @todo: this is wrong because I don't have the info...
            return LW_UC_OK;
        }

        uint16_t nbReceived = frag_sessions[fragIx].session->get_received_frame_count();
        // upper 2 bits are for the fragIndex
        nbReceived += (fragIx << 14);

        uint8_t response[FRAG_SESSION_STATUS_ANS_LENGTH] = {
            FRAG_SESSION_STATUS_ANS,
            nbReceived >> 8 & 0xff,
            nbReceived & 0xff,
            static_cast<uint8_t>(frag_sessions[fragIx].session->get_lost_frame_count()),
            0 /* whether we're out of memory... i don't think this is possible, because we limit this at compile time */
        };

        // @todo: delay not implemented
        // (As described in the “FragSessionStatusReq” command, the receivers MUST respond with a pseudo-random delay as specified by the BlockAckDelay field of the FragSessionSetupReq command.)
        send(FRAGSESSION_PORT, response, FRAG_SESSION_STATUS_ANS_LENGTH);

        return LW_UC_OK;
    }

    /**
     * Used by the AS to request the package version implemented by the end-device
     */
    LW_UC_STATUS handleFragmentationPackageVersionReq(uint8_t *buffer, size_t length) {
        if (length != 0) {
            return LW_UC_INVALID_PACKET_LENGTH;
        }

        // The identifier of the fragmentation transport package is 3. The version of this package is version 1.
        uint8_t response[PACKAGE_VERSION_ANS_LENGTH] = { PACKAGE_VERSION_ANS, 3, 1 };
        send(FRAGSESSION_PORT, response, PACKAGE_VERSION_ANS_LENGTH);

        return LW_UC_OK;
    }

    /**
     * Handle a data fragment packet
     * @param buffer
     * @param length
     */
    LW_UC_STATUS handleDataFragment(uint8_t *buffer, size_t length) {
        // top 2 bits are the fragSessionIx, other 16 bits are the pkgIndex
        uint16_t indexAndN = (buffer[1] << 8) + buffer[0];

        uint8_t fragIx = indexAndN >> 14;
        uint16_t frameCounter = indexAndN & 16383;

        if (!frag_sessions[fragIx].active) return LW_UC_FRAG_SESSION_NOT_ACTIVE;
        if (!frag_sessions[fragIx].session) return LW_UC_FRAG_SESSION_NOT_ACTIVE;

        FragResult result = frag_sessions[fragIx].session->process_frame(frameCounter, buffer + 2, length - 2);

        if (result == FRAG_OK) {
            return LW_UC_OK;
        }

        if (result == FRAG_COMPLETE) {
            tr_debug("FragSession complete");
            if (_event_cb) {
                _event_cb(LW_UC_EVENT_FRAGSESSION_COMPLETE);
            }

            // clear the session to re-claim memory
            if (frag_sessions[fragIx].session) {
                delete frag_sessions[fragIx].session;
            }

            // make the session inactive
            frag_sessions[fragIx].active = false;

            // Options contain info on where the manifest is placed
            FragmentationSessionOpts_t opts = frag_sessions[fragIx].sessionOptions;

            // the signature is the last FOTA_SIGNATURE_LENGTH bytes of the package
            size_t signatureOffset = opts.FlashOffset + ((opts.NumberOfFragments * opts.FragmentSize) - opts.Padding) - FOTA_SIGNATURE_LENGTH;

            // Manifest to read in
            UpdateSignature_t header;
            if (_bd.read(&header, signatureOffset, FOTA_SIGNATURE_LENGTH) != BD_ERROR_OK) {
                return LW_UC_BD_READ_ERROR;
            }

            // So... now it depends on whether this is a delta update or not...
            uint8_t* diff_info = (uint8_t*)&(header.diff_info);

            tr_debug("Diff info: is_diff=%d, size_of_old_fw=%d", diff_info[0], (diff_info[1] << 16) + (diff_info[2] << 8) + diff_info[3]);

            if (diff_info[0] == 0) { // Not a diff...
                // last FOTA_SIGNATURE_LENGTH bytes should be ignored because the signature is not part of the firmware
                size_t fwSize = (opts.NumberOfFragments * opts.FragmentSize) - opts.Padding - FOTA_SIGNATURE_LENGTH;
                LW_UC_STATUS authStatus = verifyAuthenticityAndWriteBootloader(
                    MBED_CONF_LORAWAN_UPDATE_CLIENT_SLOT0_HEADER_ADDRESS,
                    &header,
                    opts.FlashOffset,
                    fwSize);

                if (authStatus != LW_UC_OK) return authStatus;

                if (_event_cb) {
                    _event_cb(LW_UC_EVENT_FIRMWARE_READY);
                }

                return LW_UC_OK;
            }
            else {
                uint32_t slot1Size;
                LW_UC_STATUS deltaStatus = applySlot0Slot2DeltaUpdate(
                    (opts.NumberOfFragments * opts.FragmentSize) - opts.Padding - FOTA_SIGNATURE_LENGTH,
                    (diff_info[1] << 16) + (diff_info[2] << 8) + diff_info[3],
                    &slot1Size
                );

                if (deltaStatus != LW_UC_OK) return deltaStatus;

                LW_UC_STATUS authStatus = verifyAuthenticityAndWriteBootloader(
                    MBED_CONF_LORAWAN_UPDATE_CLIENT_SLOT1_HEADER_ADDRESS,
                    &header,
                    MBED_CONF_LORAWAN_UPDATE_CLIENT_SLOT1_FW_ADDRESS,
                    slot1Size);

                if (authStatus != LW_UC_OK) return authStatus;

                if (_event_cb) {
                    _event_cb(LW_UC_EVENT_FIRMWARE_READY);
                }

                return LW_UC_OK;
            }
        }

        tr_warn("process_frame failed (%d)", result);
        return LW_UC_PROCESS_FRAME_FAILED;
    }

    /**
     * Verify the authenticity (SHA hash and ECDSA hash) of a firmware package,
     * and after passing verification write the bootloader header
     *
     * @param addr Address of firmware slot (MBED_CONF_LORAWAN_UPDATE_CLIENT_SLOT0_HEADER_ADDRESS or MBED_CONF_LORAWAN_UPDATE_CLIENT_SLOT1_HEADER_ADDRESS)
     * @param header Firmware manifest
     * @param flashOffset Offset in flash of the firmware
     * @param flashLength Length in flash of the firmware
     */
    LW_UC_STATUS verifyAuthenticityAndWriteBootloader(uint32_t addr, UpdateSignature_t *header, size_t flashOffset, size_t flashLength) {

        if (!compare_buffers(header->manufacturer_uuid, UPDATE_CERT_MANUFACTURER_UUID, 16)) {
            return LW_UC_SIGNATURE_MANUFACTURER_UUID_MISMATCH;
        }

        if (!compare_buffers(header->device_class_uuid, UPDATE_CERT_DEVICE_CLASS_UUID, 16)) {
            return LW_UC_SIGNATURE_DEVICECLASS_UUID_MISMATCH;
        }

        // Calculate the SHA256 hash of the file, and then verify whether the signature was signed with a trusted private key
        unsigned char sha_out_buffer[32];
        // Internal buffer for reading from BD
        uint8_t sha_buffer[LW_UC_SHA256_BUFFER_SIZE];

        // SHA256 requires a large buffer, alloc on heap instead of stack
        FragmentationSha256* sha256 = new FragmentationSha256(&_bd, sha_buffer, sizeof(sha_buffer));

        sha256->calculate(flashOffset, flashLength, sha_out_buffer);

        delete sha256;

        tr_debug("New firmware SHA256 hash is: ");
        for (size_t ix = 0; ix < 32; ix++) {
            printf("%02x", sha_out_buffer[ix]);
        }
        printf("\n");

        // now check that the signature is correct...
        {
            tr_debug("Expected ECDSA signature is: ");
            for (size_t ix = 0; ix < header->signature_length; ix++) {
                printf("%02x", header->signature[ix]);
            }
            printf("\n");
            tr_debug("Verifying signature...");

            // ECDSA requires a large buffer, alloc on heap instead of stack
            FragmentationEcdsaVerify* ecdsa = new FragmentationEcdsaVerify(UPDATE_CERT_PUBKEY, UPDATE_CERT_LENGTH);
            bool valid = ecdsa->verify(sha_out_buffer, header->signature, header->signature_length);
            if (!valid) {
                tr_warn("New firmware signature verification failed");
                return LW_UC_SIGNATURE_ECDSA_FAILED;
            }
            else {
                tr_debug("New firmware signature verification passed");
            }

            delete ecdsa;
        }

        return writeBootloaderHeader(addr, flashLength, sha_out_buffer);
    }

    /**
     * Write the bootloader header so the firmware can be flashed
     *
     * @param addr Beginning of the firmware slot (e.g. MBED_CONF_LORAWAN_UPDATE_CLIENT_SLOT0_HEADER_ADDRESS)
     * @param fwSize Size of the firmware in bytes
     * @param sha_hash SHA256 hash of the firmware
     *
     * @returns LW_UC_OK if all went well, or non-0 status when something went wrong
     */
    LW_UC_STATUS writeBootloaderHeader(uint32_t addr, size_t fwSize, unsigned char sha_hash[32]) {
        if (addr != MBED_CONF_LORAWAN_UPDATE_CLIENT_SLOT0_HEADER_ADDRESS && addr != MBED_CONF_LORAWAN_UPDATE_CLIENT_SLOT1_HEADER_ADDRESS) {
            return LW_UC_INVALID_SLOT;
        }

        arm_uc_firmware_details_t details;

        // @todo: replace by real version?
        details.version = static_cast<uint64_t>(MBED_BUILD_TIMESTAMP) + 1; // should be timestamp that the fw was built, this is to get around this
        details.size = fwSize;
        memcpy(details.hash, sha_hash, 32); // SHA256 hash of the firmware
        memset(details.campaign, 0, ARM_UC_GUID_SIZE); // todo, add campaign info
        details.signatureSize = 0; // not sure what this is used for

        uint8_t *fw_header_buff = (uint8_t*)malloc(ARM_UC_EXTERNAL_HEADER_SIZE_V2);
        if (!fw_header_buff) {
            tr_error("Could not allocate %d bytes for header", ARM_UC_EXTERNAL_HEADER_SIZE_V2);
            return LW_UC_OUT_OF_MEMORY;
        }

        arm_uc_buffer_t buff = { ARM_UC_EXTERNAL_HEADER_SIZE_V2, ARM_UC_EXTERNAL_HEADER_SIZE_V2, fw_header_buff };

        arm_uc_error_t err = arm_uc_create_external_header_v2(&details, &buff);

        if (err.error != ERR_NONE) {
            tr_error("Failed to create external header (%d)", err.error);
            return LW_UC_CREATE_BOOTLOADER_HEADER_FAILED;
        }

        int r = _bd.program(buff.ptr, addr, buff.size);
        if (r != BD_ERROR_OK) {
            tr_error("Failed to program firmware header: %d bytes at address 0x%x", buff.size, addr);
            return LW_UC_BD_WRITE_ERROR;
        }

        tr_debug("Stored the update parameters in flash on 0x%x. Reset the board to apply update.", addr);

        return LW_UC_OK;
    }

    /**
     * Apply a delta update between slot 2 (source file) and slot 0 (diff file) and place in slot 1
     *
     * @param sizeOfFwInSlot0 Size of the diff image that we just received
     * @param sizeOfFwInSlot2 Expected size of firmware in slot 2 (will do sanity check)
     * @param sizeOfFwInSlot1 Out parameter which will be set to the size of the new firmware in slot 1
     */
    LW_UC_STATUS applySlot0Slot2DeltaUpdate(size_t sizeOfFwInSlot0, size_t sizeOfFwInSlot2, uint32_t *sizeOfFwInSlot1) {
        // read details about the current firmware, it's in the slot2 header
        arm_uc_firmware_details_t curr_details;
        int bd_status = _bd.read(&curr_details, MBED_CONF_LORAWAN_UPDATE_CLIENT_SLOT2_HEADER_ADDRESS, sizeof(arm_uc_firmware_details_t));
        if (bd_status != BD_ERROR_OK) {
            return LW_UC_BD_READ_ERROR;
        }

        // so... sanity check, do we have the same size in both places
        if (sizeOfFwInSlot2 != curr_details.size) {
            tr_warn("Diff size mismatch, expecting %u but got %llu", sizeOfFwInSlot2, curr_details.size);
            return LW_UC_DIFF_SIZE_MISMATCH;
        }

        // calculate sha256 hash for current fw & diff file (for debug purposes)
        {
            unsigned char sha_out_buffer[32];
            uint8_t sha_buffer[LW_UC_SHA256_BUFFER_SIZE];
            FragmentationSha256* sha256 = new FragmentationSha256(&_bd, sha_buffer, sizeof(sha_buffer));

            tr_debug("Firmware hash in slot 2 (current firmware): ");
            sha256->calculate(MBED_CONF_LORAWAN_UPDATE_CLIENT_SLOT2_FW_ADDRESS, sizeOfFwInSlot2, sha_out_buffer);
            print_buffer(sha_out_buffer, 32, false);
            printf("\n");

            tr_debug("Firmware hash in slot 2 (expected): ");
            print_buffer(curr_details.hash, 32, false);
            printf("\n");

            if (!compare_buffers(curr_details.hash, sha_out_buffer, 32)) {
                tr_info("Firmware in slot 2 hash incorrect hash");
                return LW_UC_DIFF_INCORRECT_SLOT2_HASH;
            }

            tr_debug("Firmware hash in slot 0 (diff file): ");
            sha256->calculate(MBED_CONF_LORAWAN_UPDATE_CLIENT_SLOT0_FW_ADDRESS, sizeOfFwInSlot0, sha_out_buffer);
            print_buffer(sha_out_buffer, 32, false);
            printf("\n");

            delete sha256;
        }

        // now run the diff...
        BDFILE source(&_bd, MBED_CONF_LORAWAN_UPDATE_CLIENT_SLOT2_FW_ADDRESS, sizeOfFwInSlot2);
        BDFILE diff(&_bd, MBED_CONF_LORAWAN_UPDATE_CLIENT_SLOT0_FW_ADDRESS, sizeOfFwInSlot0);
        BDFILE target(&_bd, MBED_CONF_LORAWAN_UPDATE_CLIENT_SLOT1_FW_ADDRESS, 0);

        int v = apply_delta_update(&_bd, LW_UC_JANPATCH_BUFFER_SIZE, &source, &diff, &target);

        if (v != MBED_DELTA_UPDATE_OK) {
            tr_warn("apply_delta_update failed %d", v);
            return LW_UC_DIFF_DELTA_UPDATE_FAILED;
        }

        tr_debug("Patched firmware length is %ld", target.ftell());

        *sizeOfFwInSlot1 = target.ftell();

        return LW_UC_OK;
    }

    /**
     * Relay message back to network server - to be provided by the caller of this client
     */
    void send(uint8_t port, uint8_t *data, size_t length) {
        _send_fn(port, data, length);
    }

    /**
     * Compare whether two buffers contain the same content
     */
    bool compare_buffers(uint8_t* buff1, const uint8_t* buff2, size_t size) {
        for (size_t ix = 0; ix < size; ix++) {
            if (buff1[ix] != buff2[ix]) return false;
        }
        return true;
    }

    /**
     * Helper function to print memory usage statistics
     */
    void print_heap_stats(uint8_t prefix = 0) {
        mbed_stats_heap_t heap_stats;
        mbed_stats_heap_get(&heap_stats);

        if (prefix != 0) {
            printf("%d ", prefix);
        }
        tr_info("Heap stats: %d / %d (max=%d)", heap_stats.current_size, heap_stats.reserved_size, heap_stats.max_size);
    }

    /**
     * Print the content of a buffer
     * @params buff Buffer
     * @params size Size of buffer
     * @params withSpace Whether to separate bytes by spaces
     */
    void print_buffer(void* buff, size_t size, bool withSpace = true) {
        for (size_t ix = 0; ix < size; ix++) {
            printf("%02x", ((uint8_t*)buff)[ix]);
            if (withSpace) {
                printf(" ");
            }
        }
    }

    // store fragmentation groups here...
    FragmentationSessionParams_t frag_sessions[NB_FRAG_GROUPS];
    MulticastGroupParams_t mc_groups[NB_MC_GROUPS];

    // external storage
    FragmentationBlockDeviceWrapper _bd;
    uint8_t _appKey[16];
    Callback<void(uint8_t, uint8_t*, size_t)> _send_fn;
    Callback<void(LW_UC_EVENT)> _event_cb;
};

#endif // _LORAWAN_UPDATE_CLIENT_H_
