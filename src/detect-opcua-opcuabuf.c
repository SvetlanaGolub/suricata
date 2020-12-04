/* Copyright (C) 2015-2018 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 * TODO: Update the \author in this file and detect-opcua-opcuabuf.h.
 * TODO: Update description in the \file section below.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Set up of the "opcua_opcuabuf" keyword to allow content
 * inspections on the decoded opcua application layer buffers.
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "app-layer-opcua.h"
#include "detect-opcua-opcuabuf.h"

static int DetectOPCUAopcuabufSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t flow_flags,
        void *txv, const int list_id);
#ifdef UNITTESTS
static void DetectOPCUAopcuabufRegisterTests(void);
#endif
static int g_opcua_opcuabuf_id = 0;

void DetectOPCUAopcuabufRegister(void)
{
    sigmatch_table[DETECT_AL_OPCUA_OPCUABUF].name = "opcua_opcuabuf";
    sigmatch_table[DETECT_AL_OPCUA_OPCUABUF].desc =
        "OPCUA content modififier to match on the opcua buffers";
    sigmatch_table[DETECT_AL_OPCUA_OPCUABUF].Setup = DetectOPCUAopcuabufSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_OPCUA_OPCUABUF].RegisterTests =
        DetectOPCUAopcuabufRegisterTests;
#endif

    sigmatch_table[DETECT_AL_OPCUA_OPCUABUF].flags |= SIGMATCH_NOOPT;

    /* register inspect engines - these are called per signature */
    DetectAppLayerInspectEngineRegister2("opcua_opcuabuf",
            ALPROTO_OPCUA, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetData);
    DetectAppLayerInspectEngineRegister2("opcua_opcuabuf",
            ALPROTO_OPCUA, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetData);

    /* register mpm engines - these are called in the prefilter stage */
    DetectAppLayerMpmRegister2("opcua_opcuabuf", SIG_FLAG_TOSERVER, 0,
            PrefilterGenericMpmRegister, GetData,
            ALPROTO_OPCUA, 0);
    DetectAppLayerMpmRegister2("opcua_opcuabuf", SIG_FLAG_TOCLIENT, 0,
            PrefilterGenericMpmRegister, GetData,
            ALPROTO_OPCUA, 0);


    g_opcua_opcuabuf_id = DetectBufferTypeGetByName("opcua_opcuabuf");

    SCLogNotice("OPCUA application layer detect registered.");
}

static int DetectOPCUAopcuabufSetup(DetectEngineCtx *de_ctx, Signature *s,
    const char *str)
{
    /* store list id. Content, pcre, etc will be added to the list at this
     * id. */
    s->init_data->list = g_opcua_opcuabuf_id;

    /* set the app proto for this signature. This means it will only be
     * evaluated against flows that are ALPROTO_OPCUA */
    if (DetectSignatureSetAppProto(s, ALPROTO_OPCUA) != 0)
        return -1;

    return 0;
}

/** \internal
 *  \brief get the data to inspect from the transaction.
 *  This function gets the data, sets up the InspectionBuffer object
 *  and applies transformations (if any).
 *
 *  \retval buffer or NULL in case of error
 */
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t flow_flags,
        void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const OPCUATransaction  *tx = (OPCUATransaction *)txv;
        const uint8_t *data = NULL;
        uint32_t data_len = 0;

        if (flow_flags & STREAM_TOSERVER) {
            data = tx->request_buffer;
            data_len = tx->request_buffer_len;
        } else if (flow_flags & STREAM_TOCLIENT) {
            data = tx->response_buffer;
            data_len = tx->response_buffer_len;
        } else {
            return NULL; /* no buffer */
        }

        InspectionBufferSetup(buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

#ifdef UNITTESTS
#include "tests/detect-opcua-opcuabuf.c"
#endif
