/*****************************************************************************
** SPDX-FileCopyrightText: 2026 Mika Tammi                                  **
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

#include "property_test_ctl.h"
#include "tee_internal_api.h"
#include "tee_logging.h"

#include <stdint.h>
#include <string.h>

TEE_Result TA_EXPORT TA_CreateEntryPoint(void) { return TEE_SUCCESS; }

void TA_EXPORT TA_DestroyEntryPoint(void) {}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[4],
					      void **sessionContext)
{
	(void)paramTypes;
	(void)params;
	(void)sessionContext;

	return TEE_SUCCESS;
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext) { (void)sessionContext; }

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
						uint32_t paramTypes, TEE_Param params[4])
{
	(void)sessionContext;

	if (commandID == CMD_GET_BOOLEAN) {
		uint32_t exp_types =
		    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
				    TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INPUT);
		if (paramTypes != exp_types)
			return TEE_ERROR_BAD_PARAMETERS;

		const char *name = (const char *)params[2].memref.buffer;
		if (name == NULL || params[2].memref.size == 0)
			return TEE_ERROR_BAD_PARAMETERS;

		TEE_PropSetHandle propset = (TEE_PropSetHandle)(uintptr_t)params[3].value.a;
		bool b = false;
		TEE_Result ret = TEE_GetPropertyAsBool(propset, name, &b);
		OT_LOG(LOG_ERR, "cmd 4: name=%s ret=0x%x value=%u", name, ret, (unsigned)b);
		params[0].value.a = ret;
		params[0].value.b = (uint32_t)b;
		return TEE_SUCCESS;
	} else if (commandID == CMD_GET_INTEGER) {
		uint32_t exp_types =
		    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
				    TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INPUT);
		if (paramTypes != exp_types)
			return TEE_ERROR_BAD_PARAMETERS;

		const char *name = (const char *)params[2].memref.buffer;
		if (name == NULL || params[2].memref.size == 0)
			return TEE_ERROR_BAD_PARAMETERS;

		TEE_PropSetHandle propset = (TEE_PropSetHandle)(uintptr_t)params[3].value.a;
		uint32_t val = 0;
		TEE_Result ret = TEE_GetPropertyAsU32(propset, name, &val);
		OT_LOG(LOG_ERR, "cmd 5: name=%s ret=0x%x value=%u", name, ret, val);
		params[0].value.a = ret;
		params[0].value.b = val;
		return TEE_SUCCESS;

	} else if (commandID == CMD_GET_STRING) {
		uint32_t exp_types =
		    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
				    TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INPUT);
		if (paramTypes != exp_types)
			return TEE_ERROR_BAD_PARAMETERS;

		const char *name = (const char *)params[2].memref.buffer;
		if (name == NULL || params[2].memref.size == 0)
			return TEE_ERROR_BAD_PARAMETERS;

		TEE_PropSetHandle propset = (TEE_PropSetHandle)(uintptr_t)params[3].value.a;
		size_t len = params[1].memref.size;
		TEE_Result ret =
		    TEE_GetPropertyAsString(propset, name, params[1].memref.buffer, &len);
		OT_LOG(LOG_ERR, "cmd 6: name=%s ret=0x%x", name, ret);
		params[0].value.a = ret;
		params[1].memref.size = len;
		return TEE_SUCCESS;

	} else if (commandID == CMD_GET_BINARY) {
		uint32_t exp_types =
		    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
				    TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INPUT);
		if (paramTypes != exp_types)
			return TEE_ERROR_BAD_PARAMETERS;

		const char *name = (const char *)params[2].memref.buffer;
		if (name == NULL || params[2].memref.size == 0)
			return TEE_ERROR_BAD_PARAMETERS;

		TEE_PropSetHandle propset = (TEE_PropSetHandle)(uintptr_t)params[3].value.a;
		size_t len = params[1].memref.size;
		TEE_Result ret =
		    TEE_GetPropertyAsBinaryBlock(propset, name, params[1].memref.buffer, &len);
		OT_LOG(LOG_ERR, "cmd 7: name=%s ret=0x%x size=%zu", name, ret, len);
		params[0].value.a = ret;
		params[0].value.b = (uint32_t)len;
		params[1].memref.size = len;
		return TEE_SUCCESS;

	} else if (commandID == CMD_GET_UUID) {
		uint32_t exp_types =
		    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
				    TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INPUT);
		if (paramTypes != exp_types)
			return TEE_ERROR_BAD_PARAMETERS;

		const char *name = (const char *)params[2].memref.buffer;
		if (name == NULL || params[2].memref.size == 0)
			return TEE_ERROR_BAD_PARAMETERS;

		TEE_PropSetHandle propset = (TEE_PropSetHandle)(uintptr_t)params[3].value.a;
		TEE_UUID val = {0};
		TEE_Result ret = TEE_GetPropertyAsUUID(propset, name, &val);
		OT_LOG(LOG_ERR, "cmd 8: name=%s ret=0x%x", name, ret);
		params[0].value.a = ret;
		if (ret == TEE_SUCCESS && params[1].memref.size >= sizeof(TEE_UUID))
			memcpy(params[1].memref.buffer, &val, sizeof(TEE_UUID));
		return TEE_SUCCESS;

	} else if (commandID == CMD_GET_IDENTITY) {
		uint32_t exp_types =
		    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
				    TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INPUT);
		if (paramTypes != exp_types)
			return TEE_ERROR_BAD_PARAMETERS;

		const char *name = (const char *)params[2].memref.buffer;
		if (name == NULL || params[2].memref.size == 0)
			return TEE_ERROR_BAD_PARAMETERS;

		TEE_PropSetHandle propset = (TEE_PropSetHandle)(uintptr_t)params[3].value.a;
		TEE_Identity val = {0};
		TEE_Result ret = TEE_GetPropertyAsIdentity(propset, name, &val);
		OT_LOG(LOG_ERR, "cmd 9: name=%s ret=0x%x", name, ret);
		params[0].value.a = ret;
		if (ret == TEE_SUCCESS && params[1].memref.size >= sizeof(TEE_Identity))
			memcpy(params[1].memref.buffer, &val, sizeof(TEE_Identity));
		return TEE_SUCCESS;

	} else if (commandID == CMD_ENUMERATE) {
		uint32_t exp_types =
		    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
				    TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_VALUE_INPUT);
		if (paramTypes != exp_types)
			return TEE_ERROR_BAD_PARAMETERS;

		TEE_PropSetHandle propset = (TEE_PropSetHandle)(uintptr_t)params[3].value.a;
		TEE_PropSetHandle enumerator = NULL;
		TEE_Result ret;
		uint32_t count = 0;

		ret = TEE_AllocatePropertyEnumerator(&enumerator);
		if (ret != TEE_SUCCESS) {
			params[0].value.a = ret;
			return TEE_SUCCESS;
		}

		TEE_StartPropertyEnumerator(enumerator, propset);

		for (;;) {
			size_t name_len = 256;
			char name_buf[256];
			ret = TEE_GetPropertyName(enumerator, name_buf, &name_len);
			if (ret != TEE_SUCCESS)
				break;

			size_t val_len = 512;
			char val_buf[512];
			TEE_GetPropertyAsString(enumerator, NULL, val_buf, &val_len);

			count++;

			ret = TEE_GetNextProperty(enumerator);
			if (ret != TEE_SUCCESS)
				break;
		}

		TEE_ResetPropertyEnumerator(enumerator);
		TEE_FreePropertyEnumerator(enumerator);

		params[0].value.a = TEE_SUCCESS;
		params[0].value.b = count;
		return TEE_SUCCESS;

	} else if (commandID == CMD_ENUM_EDGE_CASES) {
		uint32_t exp_types =
		    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
				    TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_VALUE_INPUT);
		if (paramTypes != exp_types)
			return TEE_ERROR_BAD_PARAMETERS;

		TEE_PropSetHandle propset = (TEE_PropSetHandle)(uintptr_t)params[3].value.a;
		TEE_PropSetHandle enumerator = NULL;
		TEE_Result ret;
		uint32_t failures = 0;

		ret = TEE_AllocatePropertyEnumerator(&enumerator);
		if (ret != TEE_SUCCESS) {
			params[0].value.a = ret;
			return TEE_SUCCESS;
		}

		/* Test 1: Exhaust enumerator, then TEE_GetPropertyName -> ITEM_NOT_FOUND */
		TEE_StartPropertyEnumerator(enumerator, propset);
		while (TEE_GetNextProperty(enumerator) == TEE_SUCCESS) {
		}
		{
			size_t nlen = 256;
			char nbuf[256];
			ret = TEE_GetPropertyName(enumerator, nbuf, &nlen);
			if (ret != TEE_ERROR_ITEM_NOT_FOUND) {
				OT_LOG(LOG_ERR, "Test 1: expected ITEM_NOT_FOUND, got 0x%x", ret);
				failures++;
			}
		}

		/* Test 2: Reset + restart, TEE_GetPropertyName with tiny buffer -> SHORT_BUFFER */
		TEE_ResetPropertyEnumerator(enumerator);
		TEE_StartPropertyEnumerator(enumerator, propset);
		{
			size_t tiny_len = 1;
			char tiny[1];
			ret = TEE_GetPropertyName(enumerator, tiny, &tiny_len);
			if (ret != TEE_ERROR_SHORT_BUFFER) {
				OT_LOG(LOG_ERR, "Test 2: expected SHORT_BUFFER, got 0x%x", ret);
				failures++;
			}
		}

		/* Test 3: Reset enumerator (zeros propset), then TEE_GetNextProperty ->
		 * ITEM_NOT_FOUND */
		TEE_ResetPropertyEnumerator(enumerator);
		ret = TEE_GetNextProperty(enumerator);
		if (ret != TEE_ERROR_ITEM_NOT_FOUND) {
			OT_LOG(LOG_ERR, "Test 3: expected ITEM_NOT_FOUND, got 0x%x", ret);
			failures++;
		}

		TEE_FreePropertyEnumerator(enumerator);
		params[0].value.a = TEE_SUCCESS;
		params[0].value.b = failures;
		return TEE_SUCCESS;

	} else if (commandID == CMD_NULL_NAME) {
		uint32_t exp_types =
		    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
				    TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_VALUE_INPUT);
		if (paramTypes != exp_types)
			return TEE_ERROR_BAD_PARAMETERS;

		TEE_PropSetHandle propset = (TEE_PropSetHandle)(uintptr_t)params[3].value.a;
		char buf[256];
		size_t len = sizeof(buf);
		TEE_Result ret = TEE_GetPropertyAsString(propset, NULL, buf, &len);
		params[0].value.a = ret;
		return TEE_SUCCESS;

	} else if (commandID == CMD_PANIC_NULL_OUTPUT) {
		uint32_t exp_types =
		    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
				    TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_VALUE_INPUT);
		if (paramTypes != exp_types)
			return TEE_ERROR_BAD_PARAMETERS;

		TEE_PropSetHandle propset = (TEE_PropSetHandle)(uintptr_t)params[3].value.a;
		uint32_t sub = params[3].value.b;
		const char *name = (const char *)params[1].memref.buffer;
		size_t len = 256;
		char buf[256];

		switch (sub) {
		case 0:
			TEE_GetPropertyAsBool(propset, name, NULL);
			break;
		case 1:
			TEE_GetPropertyAsU32(propset, name, NULL);
			break;
		case 2:
			TEE_GetPropertyAsString(propset, name, NULL, &len);
			break;
		case 3:
			TEE_GetPropertyAsBinaryBlock(propset, name, NULL, &len);
			break;
		case 4:
			TEE_GetPropertyAsUUID(propset, name, NULL);
			break;
		case 5:
			TEE_GetPropertyAsIdentity(propset, name, NULL);
			break;
		case 6:
			TEE_AllocatePropertyEnumerator(NULL);
			break;
		case 7:
			TEE_FreePropertyEnumerator(NULL);
			break;
		case 8:
			TEE_StartPropertyEnumerator(NULL, propset);
			break;
		case 9:
			TEE_ResetPropertyEnumerator(NULL);
			break;
		case 10:
			TEE_GetPropertyName(NULL, buf, &len);
			break;
		case 11:
			TEE_GetNextProperty(NULL);
			break;
		case 12: {
			TEE_PropSetHandle enum2 = NULL;
			TEE_AllocatePropertyEnumerator(&enum2);
			TEE_ResetPropertyEnumerator(enum2);
			TEE_GetPropertyName(enum2, buf, &len);
			break;
		}
		default:
			return TEE_ERROR_BAD_PARAMETERS;
		}
		/* Should not reach here — all paths above panic */
		params[0].value.a = TEE_SUCCESS;
		return TEE_SUCCESS;

	} else if (commandID == CMD_GET_U64) {
		uint32_t exp_types =
		    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
				    TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INPUT);
		if (paramTypes != exp_types)
			return TEE_ERROR_BAD_PARAMETERS;

		const char *name = (const char *)params[2].memref.buffer;
		if (name == NULL || params[2].memref.size == 0)
			return TEE_ERROR_BAD_PARAMETERS;

		TEE_PropSetHandle propset = (TEE_PropSetHandle)(uintptr_t)params[3].value.a;
		uint64_t val = 0;
		TEE_Result ret = TEE_GetPropertyAsU64(propset, name, &val);
		OT_LOG(LOG_ERR, "cmd 14: name=%s ret=0x%x value=%lu", name, ret, val);
		params[0].value.a = ret;
		params[0].value.b = (uint32_t)val;
		return TEE_SUCCESS;

	} else if (commandID == CMD_GET_BOOL_VIA_ENUM) {
		uint32_t exp_types =
		    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
				    TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_VALUE_INPUT);
		if (paramTypes != exp_types)
			return TEE_ERROR_BAD_PARAMETERS;

		TEE_PropSetHandle propset = (TEE_PropSetHandle)(uintptr_t)params[3].value.a;
		TEE_PropSetHandle enumerator = NULL;
		TEE_Result ret;

		ret = TEE_AllocatePropertyEnumerator(&enumerator);
		if (ret != TEE_SUCCESS) {
			params[0].value.a = ret;
			return TEE_SUCCESS;
		}

		TEE_StartPropertyEnumerator(enumerator, propset);

		/* Advance to a boolean property by checking with GetPropertyAsBool */
		bool found = false;
		bool val = false;
		for (;;) {
			ret = TEE_GetPropertyAsBool(enumerator, NULL, &val);
			if (ret == TEE_SUCCESS) {
				found = true;
				break;
			}
			ret = TEE_GetNextProperty(enumerator);
			if (ret != TEE_SUCCESS)
				break;
		}

		TEE_FreePropertyEnumerator(enumerator);

		if (found) {
			params[0].value.a = TEE_SUCCESS;
			params[0].value.b = (uint32_t)val;
		} else {
			params[0].value.a = TEE_ERROR_ITEM_NOT_FOUND;
		}
		return TEE_SUCCESS;

	} else if (commandID == CMD_ERROR_OUTPUT) {
		uint32_t exp_types =
		    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
				    TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_VALUE_INPUT);
		if (paramTypes != exp_types)
			return TEE_ERROR_BAD_PARAMETERS;

		uint32_t sub = params[3].value.a;
		switch (sub) {
		case 0: {
			/* Bool: ITEM_NOT_FOUND -> *value should be false */
			bool b = true;
			TEE_GetPropertyAsBool(TEE_PROPSET_TEE_IMPLEMENTATION, "nonexistent", &b);
			params[0].value.a = (uint32_t)b;
			break;
		}
		case 1: {
			/* U32: ITEM_NOT_FOUND -> *value should be 0 */
			uint32_t v = 0xDEAD;
			TEE_GetPropertyAsU32(TEE_PROPSET_TEE_IMPLEMENTATION, "nonexistent", &v);
			params[0].value.a = v;
			break;
		}
		case 2: {
			/* U64: ITEM_NOT_FOUND -> *value should be 0 */
			uint64_t v = 0xDEAD;
			TEE_GetPropertyAsU64(TEE_PROPSET_TEE_IMPLEMENTATION, "nonexistent", &v);
			params[0].value.a = (uint32_t)v;
			break;
		}
		case 3: {
			/* Bool: BAD_FORMAT (string prop as bool) -> *value should be false */
			bool b = true;
			TEE_GetPropertyAsBool(TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.apiversion",
					      &b);
			params[0].value.a = (uint32_t)b;
			break;
		}
		case 4: {
			/* U32: BAD_FORMAT (uuid prop as integer) -> *value should be 0 */
			uint32_t v = 0xDEAD;
			TEE_GetPropertyAsU32(TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.deviceID",
					     &v);
			params[0].value.a = v;
			break;
		}
		default:
			return TEE_ERROR_BAD_PARAMETERS;
		}
		return TEE_SUCCESS;

	} else if (commandID == CMD_PANIC_NULL_NAME) {
		uint32_t exp_types =
		    TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_NONE,
				    TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_VALUE_INPUT);
		if (paramTypes != exp_types)
			return TEE_ERROR_BAD_PARAMETERS;

		TEE_PropSetHandle propset = (TEE_PropSetHandle)(uintptr_t)params[3].value.a;
		uint32_t sub = params[3].value.b;

		switch (sub) {
		case 0: {
			TEE_UUID uuid = {0};
			TEE_GetPropertyAsUUID(propset, NULL, &uuid);
			break;
		}
		case 1: {
			TEE_Identity identity = {0};
			TEE_GetPropertyAsIdentity(propset, NULL, &identity);
			break;
		}
		default:
			return TEE_ERROR_BAD_PARAMETERS;
		}
		/* Should not reach here — paths above panic */
		params[0].value.a = TEE_SUCCESS;
		return TEE_SUCCESS;
	}

	return TEE_SUCCESS;
}
