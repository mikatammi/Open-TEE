/*****************************************************************************
** Copyright (C) 2026 Mika Tammi                                            **
**                                                                          **
** Licensed under the Apache License, Version 2.0 (the "License");          **
** you may not use this file except in compliance with the License.         **
** You may obtain a copy of the License at                                  **
**                                                                          **
**      http://www.apache.org/licenses/LICENSE-2.0                          **
**                                                                          **
** Unless required by applicable law or agreed to in writing, software      **
** distributed under the License is distributed on an "AS IS" BASIS,        **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. **
** See the License for the specific language governing permissions and      **
** limitations under the License.                                           **
*****************************************************************************/

/* Simple CA for invoking Test TA for Property Access Functions. */

#include "tee_client_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const TEEC_UUID uuid = {
    0xb8fe5b9e, 0xf765, 0x42f1, {0xb8, 0xa8, 0xa6, 0xdc, 0xe4, 0x50, 0x16, 0x05}};

static int invoke_ta_tui_cmd(TEEC_Context *context, TEEC_Session *session)
{
	int ret = -1;
	uint32_t return_origin = 0;
	TEEC_Operation op = {0};

	ret = TEEC_InvokeCommand(session, 1, &op, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("Error in TEEC_InvokeCommand\n");
	}
err:
	return ret;
}

static int invoke_ta()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Result ret;
	uint32_t return_origin;

	memset(&context, 0, sizeof(context));
	memset(&session, 0, sizeof(session));

	/* Initialize context */
	ret = TEEC_InitializeContext(NULL, &context);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext error: 0x%08x\n", ret);
		return -1;
	}

	/* Open session */
	ret = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL,
			       &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_OpenSession error: 0x%08x\n", ret);
		return -2;
	}

	ret = invoke_ta_tui_cmd(&context, &session);
	if (ret != 0)
		ret = -3;

	TEEC_CloseSession(&session);
	TEEC_FinalizeContext(&context);

	return ret;
}

int main()
{
	int ret = invoke_ta();
	printf("invoke_ta() -> %u", ret);
	if (ret != 0)
		return EXIT_FAILURE;
	return EXIT_SUCCESS;
}
