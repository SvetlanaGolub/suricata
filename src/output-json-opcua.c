/* Copyright (C) 2015-2020 Open Information Security Foundation
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
 * TODO: Update \author in this file and in output-json-opcua.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Implement JSON/eve logging app-layer OPCUA.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "app-layer-opcua.h"
#include "output-json-opcua.h"

typedef struct LogOPCUAFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t    flags;
} LogOPCUAFileCtx;

typedef struct LogOPCUALogThread_ {
    LogFileCtx *file_ctx;
    LogOPCUAFileCtx *opcualog_ctx;
    MemBuffer          *buffer;
} LogOPCUALogThread;

static int JsonOPCUALogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    OPCUATransaction *opcuatx = tx;
    LogOPCUALogThread *thread = thread_data;

    SCLogNotice("Logging opcua transaction %"PRIu64".", opcuatx->tx_id);

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_PACKET, "opcua", NULL);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(js, "opcua");

    /* Log the request buffer. */
    if (opcuatx->request_buffer != NULL) {
        jb_set_string_from_bytes(js, "request", opcuatx->request_buffer,
                opcuatx->request_buffer_len);
    }

    /* Log the response buffer. */
    if (opcuatx->response_buffer != NULL) {
        jb_set_string_from_bytes(js, "response", opcuatx->response_buffer,
                opcuatx->response_buffer_len);
    }

    /* Close opcua. */
    jb_close(js);

    MemBufferReset(thread->buffer);
    OutputJsonBuilderBuffer(js, thread->file_ctx, &thread->buffer);

    jb_free(js);
    return TM_ECODE_OK;
}

static void OutputOPCUALogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogOPCUAFileCtx *opcualog_ctx = (LogOPCUAFileCtx *)output_ctx->data;
    SCFree(opcualog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputOPCUALogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogOPCUAFileCtx *opcualog_ctx = SCCalloc(1, sizeof(*opcualog_ctx));
    if (unlikely(opcualog_ctx == NULL)) {
        return result;
    }
    opcualog_ctx->file_ctx = ajt->file_ctx;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(opcualog_ctx);
        return result;
    }
    output_ctx->data = opcualog_ctx;
    output_ctx->DeInit = OutputOPCUALogDeInitCtxSub;

    SCLogNotice("OPCUA log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_OPCUA);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonOPCUALogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogOPCUALogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogOPCUA.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (unlikely(thread->buffer == NULL)) {
        goto error_exit;
    }

    thread->opcualog_ctx = ((OutputCtx *)initdata)->data;
    thread->file_ctx = LogFileEnsureExists(thread->opcualog_ctx->file_ctx, t->id);
    if (!thread->file_ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonOPCUALogThreadDeinit(ThreadVars *t, void *data)
{
    LogOPCUALogThread *thread = (LogOPCUALogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    if (thread->buffer != NULL) {
        MemBufferFree(thread->buffer);
    }
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonOPCUALogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_OPCUA, "eve-log", "JsonOPCUALog",
        "eve-log.opcua", OutputOPCUALogInitSub, ALPROTO_OPCUA,
        JsonOPCUALogger, JsonOPCUALogThreadInit,
        JsonOPCUALogThreadDeinit, NULL);

    SCLogNotice("OPCUA JSON logger registered.");
}
