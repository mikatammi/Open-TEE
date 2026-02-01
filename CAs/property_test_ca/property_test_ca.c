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

/* Simple CA for invoking Test TA for Property Access Functions. */

#include "property_test_ctl.h"
#include "tee_client_api.h"
#include "../../emulator/internal_api/tee_data_types.h"

#include <mbedtls/base64.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RED "\033[31m"
#define GREEN "\033[32m"
#define RESET "\033[0m"
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* Expected-failure comparator for properties registered but not yet implemented */
static bool expect_fail(const TEEC_Result actual, const TEEC_Result expected)
{
	return actual == expected;
}

/* Always-true dummies for runtime-dependent values */
static bool dummy_integer_true(uint64_t a, uint64_t b)
{
	(void)a;
	(void)b;
	return true;
}

static bool dummy_uuid_true(TEE_UUID a, TEE_UUID b)
{
	(void)a;
	(void)b;
	return true;
}

static bool dummy_binary_true(const void *a, const void *b)
{
	(void)a;
	(void)b;
	return true;
}

/* Exact-match comparators */
static bool string_equals(const char *a, const char *b) { return strcmp(a, b) == 0; }

static bool integer_equals(uint64_t a, uint64_t b) { return a == b; }

static bool boolean_equals(bool a, bool b) { return a == b; }

static bool uuid_equals(TEE_UUID a, TEE_UUID b) { return memcmp(&a, &b, sizeof(TEE_UUID)) == 0; }

static bool identity_equals(TEE_Identity a, TEE_Identity b)
{
	return memcmp(&a, &b, sizeof(TEE_Identity)) == 0;
}

/* Sentinel for binary exact-match; size and buf are taken from spec->param.binary in the caller */
static bool binary_equals(const void *a, const void *b)
{
	(void)a;
	(void)b;
	return false;
}

static const uint8_t tee_binaryversion[] = {0x00, 0x00, 0x01, 0x00};

enum property_type { STRING, BINARY, INTEGER, BOOLEAN, UUID_TYPE, IDENTITY };

struct property_spec {
	uint32_t propset;
	const char *name;
	enum property_type type;
	union {
		bool (*string)(const char *a, const char *b);
		bool (*binary)(const void *a, const void *b);
		bool (*integer)(uint64_t a, uint64_t b);
		bool (*boolean)(bool a, bool b);
		bool (*uuid)(TEE_UUID a, TEE_UUID b);
		bool (*identity)(TEE_Identity a, TEE_Identity b);
		bool (*expect_fail)(TEEC_Result actual, TEEC_Result expected);
	} f;
	union {
		const char *string;
		struct {
			const void *buf;
			size_t size;
		} binary;
		uint64_t integer;
		bool boolean;
		TEE_UUID uuid;
		TEE_Identity identity;
		TEEC_Result expected_ret;
	} param;
};

/* TA_Properties (10 entries) */
static const struct property_spec propset_current_ta_spec[] = {
    {PROPSET_CURRENT_TA,
     "gpd.ta.appID",
     UUID_TYPE,
     {.uuid = uuid_equals},
     {.uuid = {0xb8fe5b9e, 0xf765, 0x42f1, {0xb8, 0xa8, 0xa6, 0xdc, 0xe4, 0x50, 0x16, 0x05}}}},
    {PROPSET_CURRENT_TA,
     "gpd.ta.singleInstance",
     BOOLEAN,
     {.boolean = boolean_equals},
     {.boolean = false}},
    {PROPSET_CURRENT_TA,
     "gpd.ta.multiSession",
     BOOLEAN,
     {.boolean = boolean_equals},
     {.boolean = false}},
    {PROPSET_CURRENT_TA,
     "gpd.ta.instanceKeepAlive",
     BOOLEAN,
     {.boolean = boolean_equals},
     {.boolean = false}},
    {PROPSET_CURRENT_TA,
     "gpd.ta.dataSize",
     INTEGER,
     {.integer = integer_equals},
     {.integer = 4096}},
    {PROPSET_CURRENT_TA,
     "gpd.ta.stackSize",
     INTEGER,
     {.integer = integer_equals},
     {.integer = 512}},
    {PROPSET_CURRENT_TA, "gpd.ta.version", STRING, {.string = string_equals}, {.string = "0.1"}},
    {PROPSET_CURRENT_TA,
     "gpd.ta.description",
     STRING,
     {.string = string_equals},
     {.string = "Trusted Application"}},
    {PROPSET_CURRENT_TA, "gpd.ta.endian", INTEGER, {.integer = integer_equals}, {.integer = 0}},
    {PROPSET_CURRENT_TA,
     "gpd.ta.doesNotCloseHandleOnCorruptObject",
     BOOLEAN,
     {.boolean = boolean_equals},
     {.boolean = true}},
};

/* Client_Properties (4 entries) */
static const struct property_spec propset_current_client_spec[] = {
    {PROPSET_CURRENT_CLIENT,
     "gpd.client.identity",
     IDENTITY,
     {.identity = identity_equals},
     {.identity = {0, {0, 0, 0, {0}}}}},
    {PROPSET_CURRENT_CLIENT,
     "gpd.client.endian",
     INTEGER,
     {.integer = integer_equals},
     {.integer = 0}},
    {PROPSET_CURRENT_CLIENT,
     "gpd.client.pathHash",
     BINARY,
     {.binary = dummy_binary_true},
     {.binary = {.buf = NULL, .size = 0}}},
    {PROPSET_CURRENT_CLIENT,
     "gpd.client.path",
     BINARY,
     {.expect_fail = expect_fail},
     {.expected_ret = TEEC_ERROR_NOT_IMPLEMENTED}},
};

/* Implementation_Properties (38 entries) */
static const struct property_spec propset_tee_implementation_spec[] = {
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.apiversion",
     STRING,
     {.string = string_equals},
     {.string = "1.1"}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.internalCore.version",
     INTEGER,
     {.integer = integer_equals},
     {.integer = 0x01010000}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.description",
     STRING,
     {.string = string_equals},
     {.string = "Open-TEE"}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.deviceID",
     UUID_TYPE,
     {.uuid = dummy_uuid_true},
     {.uuid = {0}}},
    {PROPSET_TEE_IMPLEMENTATION, "gpd.tee.name", STRING, {.string = string_equals}, {.string = ""}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.implementationStackHash",
     BINARY,
     {.expect_fail = expect_fail},
     {.expected_ret = TEEC_ERROR_NOT_IMPLEMENTED}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.implementationStack",
     BINARY,
     {.expect_fail = expect_fail},
     {.expected_ret = TEEC_ERROR_NOT_IMPLEMENTED}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.systemTime.protectionLevel",
     INTEGER,
     {.expect_fail = expect_fail},
     {.expected_ret = TEEC_ERROR_NOT_IMPLEMENTED}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.TAPersistentTime.protectionLevel",
     INTEGER,
     {.expect_fail = expect_fail},
     {.expected_ret = TEEC_ERROR_NOT_IMPLEMENTED}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.arith.maxBigIntSize",
     INTEGER,
     {.integer = dummy_integer_true},
     {.integer = 0}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.cryptography.ecc",
     BOOLEAN,
     {.boolean = boolean_equals},
     {.boolean = false}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.cryptography.nist",
     BOOLEAN,
     {.boolean = boolean_equals},
     {.boolean = false}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.cryptography.bsi-r",
     BOOLEAN,
     {.boolean = boolean_equals},
     {.boolean = false}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.cryptography.bsi-t",
     BOOLEAN,
     {.boolean = boolean_equals},
     {.boolean = false}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.cryptography.ietf",
     BOOLEAN,
     {.boolean = boolean_equals},
     {.boolean = false}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.cryptography.octa",
     BOOLEAN,
     {.boolean = boolean_equals},
     {.boolean = false}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.cryptography.sec",
     BOOLEAN,
     {.boolean = boolean_equals},
     {.boolean = false}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.cryptography.falcon",
     BOOLEAN,
     {.boolean = boolean_equals},
     {.boolean = false}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.cryptography.NISTpqc.crystals",
     BOOLEAN,
     {.boolean = boolean_equals},
     {.boolean = false}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.cryptography.NISTpqc.SLHDSA",
     BOOLEAN,
     {.boolean = boolean_equals},
     {.boolean = false}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.cryptography.statefulVerification",
     BOOLEAN,
     {.boolean = boolean_equals},
     {.boolean = false}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.cryptography.statefulSignatures",
     BOOLEAN,
     {.boolean = boolean_equals},
     {.boolean = false}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.cryptography.FrodoKEM",
     BOOLEAN,
     {.boolean = boolean_equals},
     {.boolean = false}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.cryptography.NTRU",
     BOOLEAN,
     {.boolean = boolean_equals},
     {.boolean = false}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.cryptography.maxRetainedData",
     INTEGER,
     {.integer = integer_equals},
     {.integer = 0}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.trustedStorage.private.rollbackProtection",
     INTEGER,
     {.integer = integer_equals},
     {.integer = 100}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.trustedStorage.perso.rollbackProtection",
     INTEGER,
     {.integer = integer_equals},
     {.integer = 100}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.trustedStorage.protected.rollbackProtection",
     INTEGER,
     {.integer = integer_equals},
     {.integer = 10000}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.trustedStorage.antiRollback.protectionLevel",
     INTEGER,
     {.integer = integer_equals},
     {.integer = 100}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.trustedStorage.rollbackDetection.protectionLevel",
     INTEGER,
     {.integer = integer_equals},
     {.integer = 100}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.trustedos.implementation.version",
     STRING,
     {.string = string_equals},
     {.string = "0.1"}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.trustedos.implementation.binaryversion",
     BINARY,
     {.binary = binary_equals},
     {.binary = {.buf = tee_binaryversion, .size = sizeof(tee_binaryversion)}}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.trustedos.manufacturer",
     STRING,
     {.string = string_equals},
     {.string = "The Open-TEE Project"}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.firmware.implementation.version",
     STRING,
     {.string = string_equals},
     {.string = "0.1"}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.firmware.implementation.binaryversion",
     BINARY,
     {.binary = dummy_binary_true},
     {.binary = {.buf = NULL, .size = 0}}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.firmware.manufacturer",
     STRING,
     {.string = string_equals},
     {.string = "The Open-TEE Project"}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.event.maxSources",
     INTEGER,
     {.integer = integer_equals},
     {.integer = 0}},
    {PROPSET_TEE_IMPLEMENTATION,
     "gpd.tee.maskState",
     BOOLEAN,
     {.boolean = boolean_equals},
     {.boolean = false}},
};

static TEEC_Result invoke_get_boolean(TEEC_Session *session, uint32_t propset, const char *name,
				      bool *out)
{
	TEEC_Operation op = {0};
	uint32_t return_origin = 0;
	TEEC_Result ret;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INPUT);
	op.params[2].tmpref.buffer = (void *)name;
	op.params[2].tmpref.size = strlen(name) + 1;
	op.params[3].value.a = propset;

	ret = TEEC_InvokeCommand(session, CMD_GET_BOOLEAN, &op, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed: 0x%08x\n", ret);
		return ret;
	}

	/* TEE_Result from the TA is in params[0].value.a */
	TEEC_Result ta_ret = op.params[0].value.a;
	if (ta_ret != TEEC_SUCCESS)
		return ta_ret;

	*out = (bool)op.params[0].value.b;
	return TEEC_SUCCESS;
}

static TEEC_Result invoke_get_integer(TEEC_Session *session, uint32_t propset, const char *name,
				      uint32_t *out)
{
	TEEC_Operation op = {0};
	uint32_t return_origin = 0;
	TEEC_Result ret;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INPUT);
	op.params[2].tmpref.buffer = (void *)name;
	op.params[2].tmpref.size = strlen(name) + 1;
	op.params[3].value.a = propset;

	ret = TEEC_InvokeCommand(session, CMD_GET_INTEGER, &op, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed: 0x%08x\n", ret);
		return ret;
	}

	TEEC_Result ta_ret = op.params[0].value.a;
	if (ta_ret != TEEC_SUCCESS)
		return ta_ret;

	*out = op.params[0].value.b;
	return TEEC_SUCCESS;
}

static TEEC_Result invoke_get_string(TEEC_Session *session, uint32_t propset, const char *name,
				     char *buf, size_t buflen)
{
	TEEC_Operation op = {0};
	uint32_t return_origin = 0;
	TEEC_Result ret;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT);
	op.params[1].tmpref.buffer = buf;
	op.params[1].tmpref.size = buflen;
	op.params[2].tmpref.buffer = (void *)name;
	op.params[2].tmpref.size = strlen(name) + 1;
	op.params[3].value.a = propset;

	ret = TEEC_InvokeCommand(session, CMD_GET_STRING, &op, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed: 0x%08x\n", ret);
		return ret;
	}

	TEEC_Result ta_ret = op.params[0].value.a;
	return ta_ret;
}

static TEEC_Result invoke_get_binary(TEEC_Session *session, uint32_t propset, const char *name,
				     void *buf, size_t buflen, size_t *actual_size)
{
	TEEC_Operation op = {0};
	uint32_t return_origin = 0;
	TEEC_Result ret;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT);
	op.params[1].tmpref.buffer = buf;
	op.params[1].tmpref.size = buflen;
	op.params[2].tmpref.buffer = (void *)name;
	op.params[2].tmpref.size = strlen(name) + 1;
	op.params[3].value.a = propset;

	ret = TEEC_InvokeCommand(session, CMD_GET_BINARY, &op, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed: 0x%08x\n", ret);
		return ret;
	}

	TEEC_Result ta_ret = op.params[0].value.a;
	if (ta_ret != TEEC_SUCCESS)
		return ta_ret;

	*actual_size = op.params[0].value.b;
	return TEEC_SUCCESS;
}

static TEEC_Result invoke_get_uuid(TEEC_Session *session, uint32_t propset, const char *name,
				   TEE_UUID *out)
{
	TEEC_Operation op = {0};
	uint32_t return_origin = 0;
	TEEC_Result ret;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT);
	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = sizeof(TEE_UUID);
	op.params[2].tmpref.buffer = (void *)name;
	op.params[2].tmpref.size = strlen(name) + 1;
	op.params[3].value.a = propset;

	ret = TEEC_InvokeCommand(session, CMD_GET_UUID, &op, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed: 0x%08x\n", ret);
		return ret;
	}

	TEEC_Result ta_ret = op.params[0].value.a;
	return ta_ret;
}

static TEEC_Result invoke_get_identity(TEEC_Session *session, uint32_t propset, const char *name,
				       TEE_Identity *out)
{
	TEEC_Operation op = {0};
	uint32_t return_origin = 0;
	TEEC_Result ret;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT);
	op.params[1].tmpref.buffer = out;
	op.params[1].tmpref.size = sizeof(TEE_Identity);
	op.params[2].tmpref.buffer = (void *)name;
	op.params[2].tmpref.size = strlen(name) + 1;
	op.params[3].value.a = propset;

	ret = TEEC_InvokeCommand(session, CMD_GET_IDENTITY, &op, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed: 0x%08x\n", ret);
		return ret;
	}

	TEEC_Result ta_ret = op.params[0].value.a;
	return ta_ret;
}

static TEEC_Result invoke_panic_null_output(TEEC_Session *session, uint32_t propset,
					    const char *name, uint32_t sub)
{
	TEEC_Operation op = {0};
	uint32_t return_origin = 0;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_VALUE_INPUT);
	op.params[1].tmpref.buffer = (void *)name;
	op.params[1].tmpref.size = strlen(name) + 1;
	op.params[3].value.a = propset;
	op.params[3].value.b = sub;

	return TEEC_InvokeCommand(session, CMD_PANIC_NULL_OUTPUT, &op, &return_origin);
}

static bool open_test_session(TEEC_Context *context, TEEC_Session *session)
{
	uint32_t return_origin = 0;
	TEEC_Result ret;

	printf("Initializing context: ");
	ret = TEEC_InitializeContext(NULL, context);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed: 0x%08x\n", ret);
		return false;
	}
	printf("initialized\n");

	printf("Opening session: ");
	ret = TEEC_OpenSession(context, session, &(TEEC_UUID)PROPERTY_TEST_TA_UUID,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_OpenSession failed: 0x%08x\n", ret);
		TEEC_FinalizeContext(context);
		return false;
	}
	printf("opened\n");

	return true;
}

static void close_test_session(TEEC_Context *context, TEEC_Session *session)
{
	printf("Closing session: ");
	TEEC_CloseSession(session);
	printf("closed\n");

	printf("Finalizing context: ");
	TEEC_FinalizeContext(context);
	printf("finalized\n");
}

static int test_all_properties()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Result ret;
	int failures = 0;

	if (!open_test_session(&context, &session))
		return 1;

	struct {
		const char *set_name;
		const struct property_spec *specs;
		size_t count;
	} sets[] = {
	    {"CURRENT_TA", propset_current_ta_spec, ARRAY_SIZE(propset_current_ta_spec)},
	    {"CURRENT_CLIENT", propset_current_client_spec,
	     ARRAY_SIZE(propset_current_client_spec)},
	    {"TEE_IMPLEMENTATION", propset_tee_implementation_spec,
	     ARRAY_SIZE(propset_tee_implementation_spec)},
	};

	for (size_t s = 0; s < ARRAY_SIZE(sets); s++) {
		for (size_t i = 0; i < sets[s].count; i++) {
			const struct property_spec *spec = &sets[s].specs[i];

			/* XFAIL: property registered but not yet implemented */
			if (spec->f.expect_fail == expect_fail) {
				char buf[512] = {0};
				ret = invoke_get_string(&session, spec->propset, spec->name, buf,
							sizeof(buf));
				if (spec->f.expect_fail(ret, spec->param.expected_ret)) {
					printf(GREEN "PASS" RESET " xfail %s: %s returned expected "
						     "0x%08x\n",
					       sets[s].set_name, spec->name,
					       spec->param.expected_ret);
				} else {
					printf(RED "FAIL" RESET " xfail %s: %s expected 0x%08x, "
						   "got 0x%08x\n",
					       sets[s].set_name, spec->name,
					       spec->param.expected_ret, ret);
					failures++;
				}
				continue;
			}

			switch (spec->type) {
			case BOOLEAN: {
				bool val;
				ret = invoke_get_boolean(&session, spec->propset, spec->name, &val);
				if (ret != TEEC_SUCCESS) {
					printf(RED "FAIL" RESET " bool %s: %s returned 0x%08x\n",
					       sets[s].set_name, spec->name, ret);
					failures++;
					break;
				}
				if (!spec->f.boolean(val, spec->param.boolean)) {
					printf(RED "FAIL" RESET
						   " bool %s: %s value mismatch (got %s)\n",
					       sets[s].set_name, spec->name,
					       val ? "true" : "false");
					failures++;
					break;
				}
				printf(GREEN "PASS" RESET " bool %s: %s = %s\n", sets[s].set_name,
				       spec->name, val ? "true" : "false");
				break;
			}
			case INTEGER: {
				uint32_t val;
				ret = invoke_get_integer(&session, spec->propset, spec->name, &val);
				if (ret != TEEC_SUCCESS) {
					printf(RED "FAIL" RESET " int %s: %s returned 0x%08x\n",
					       sets[s].set_name, spec->name, ret);
					failures++;
					break;
				}
				if (!spec->f.integer((uint64_t)val, spec->param.integer)) {
					printf(RED "FAIL" RESET " int %s: %s value mismatch"
						   " (got %u, expected %llu)\n",
					       sets[s].set_name, spec->name, val,
					       (unsigned long long)spec->param.integer);
					failures++;
					break;
				}
				printf(GREEN "PASS" RESET " int %s: %s = %u\n", sets[s].set_name,
				       spec->name, val);
				break;
			}
			case STRING: {
				char buf[512] = {0};
				ret = invoke_get_string(&session, spec->propset, spec->name, buf,
							sizeof(buf));
				if (ret != TEEC_SUCCESS) {
					printf(RED "FAIL" RESET " str %s: %s returned 0x%08x\n",
					       sets[s].set_name, spec->name, ret);
					failures++;
					break;
				}
				if (!spec->f.string(buf, spec->param.string)) {
					printf(RED "FAIL" RESET " str %s: %s value mismatch"
						   " (got \"%s\", expected \"%s\")\n",
					       sets[s].set_name, spec->name, buf,
					       spec->param.string);
					failures++;
					break;
				}
				printf(GREEN "PASS" RESET " str %s: %s = \"%s\"\n",
				       sets[s].set_name, spec->name, buf);
				break;
			}
			case BINARY: {
				unsigned char buf[512];
				size_t actual_size = 0;
				ret = invoke_get_binary(&session, spec->propset, spec->name, buf,
							sizeof(buf), &actual_size);
				if (ret != TEEC_SUCCESS) {
					printf(RED "FAIL" RESET " bin %s: %s returned 0x%08x\n",
					       sets[s].set_name, spec->name, ret);
					failures++;
					break;
				}
				bool ok;
				if (spec->f.binary == binary_equals) {
					ok = actual_size == spec->param.binary.size &&
					     memcmp(buf, spec->param.binary.buf,
						    spec->param.binary.size) == 0;
				} else {
					ok = spec->f.binary(buf, spec->param.binary.buf);
				}
				if (!ok) {
					printf(RED "FAIL" RESET " bin %s: %s value mismatch\n",
					       sets[s].set_name, spec->name);
					failures++;
					break;
				}
				printf(GREEN "PASS" RESET " bin %s: %s = %zu bytes\n",
				       sets[s].set_name, spec->name, actual_size);
				break;
			}
			case UUID_TYPE: {
				TEE_UUID val;
				ret = invoke_get_uuid(&session, spec->propset, spec->name, &val);
				if (ret != TEEC_SUCCESS) {
					printf(RED "FAIL" RESET " uuid %s: %s returned 0x%08x\n",
					       sets[s].set_name, spec->name, ret);
					failures++;
					break;
				}
				if (!spec->f.uuid(val, spec->param.uuid)) {
					printf(RED "FAIL" RESET " uuid %s: %s value mismatch\n",
					       sets[s].set_name, spec->name);
					failures++;
					break;
				}
				printf(GREEN "PASS" RESET " uuid %s: %s = %08x-%04x-%04x\n",
				       sets[s].set_name, spec->name, val.timeLow, val.timeMid,
				       val.timeHiAndVersion);
				break;
			}
			case IDENTITY: {
				TEE_Identity val;
				ret =
				    invoke_get_identity(&session, spec->propset, spec->name, &val);
				if (ret != TEEC_SUCCESS) {
					printf(RED "FAIL" RESET " ident %s: %s returned 0x%08x\n",
					       sets[s].set_name, spec->name, ret);
					failures++;
					break;
				}
				if (!spec->f.identity(val, spec->param.identity)) {
					printf(RED "FAIL" RESET " ident %s: %s value mismatch\n",
					       sets[s].set_name, spec->name);
					failures++;
					break;
				}
				printf(GREEN "PASS" RESET " ident %s: %s = login:%u uuid:%08x\n",
				       sets[s].set_name, spec->name, val.login, val.uuid.timeLow);
				break;
			}
			}
		}
	}

	close_test_session(&context, &session);

	return failures > 0 ? 1 : 0;
}

/* Gap 1: Test TEE_GetPropertyAsString with non-STRING property types.
 * Exercises BOOL->str, INT->str, BIN->str, UUID->str, IDENT->str conversions. */
static int test_string_conversions()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Result ret;
	int failures = 0;

	if (!open_test_session(&context, &session))
		return 1;

	struct {
		uint32_t propset;
		const char *name;
		const char *label;
	} cases[] = {
	    {PROPSET_TEE_IMPLEMENTATION, "gpd.tee.maskState", "BOOL->str"},
	    {PROPSET_TEE_IMPLEMENTATION, "gpd.tee.event.maxSources", "INT->str"},
	    {PROPSET_CURRENT_CLIENT, "gpd.client.pathHash", "BIN->str"},
	    {PROPSET_TEE_IMPLEMENTATION, "gpd.tee.deviceID", "UUID->str"},
	    {PROPSET_CURRENT_CLIENT, "gpd.client.identity", "IDENT->str"},
	};

	for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
		char buf[512] = {0};
		ret =
		    invoke_get_string(&session, cases[i].propset, cases[i].name, buf, sizeof(buf));
		if (ret == TEEC_SUCCESS) {
			printf(GREEN "PASS" RESET " %s: %s = \"%s\"\n", cases[i].label,
			       cases[i].name, buf);
		} else {
			printf(RED "FAIL" RESET " %s: %s returned 0x%08x\n", cases[i].label,
			       cases[i].name, ret);
			failures++;
		}
	}

	close_test_session(&context, &session);

	return failures > 0 ? 1 : 0;
}

/* Validate that TEE_GetPropertyAsString on BINARY properties produces well-formed
 * base64 that decodes back to the exact bytes returned by TEE_GetPropertyAsBinaryBlock. */
static int test_binary_base64()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Result ret;
	int failures = 0;

	if (!open_test_session(&context, &session))
		return 1;

	struct {
		const char *set_name;
		const struct property_spec *specs;
		size_t count;
	} sets[] = {
	    {"CURRENT_TA", propset_current_ta_spec, ARRAY_SIZE(propset_current_ta_spec)},
	    {"CURRENT_CLIENT", propset_current_client_spec,
	     ARRAY_SIZE(propset_current_client_spec)},
	    {"TEE_IMPLEMENTATION", propset_tee_implementation_spec,
	     ARRAY_SIZE(propset_tee_implementation_spec)},
	};

	for (size_t s = 0; s < ARRAY_SIZE(sets); s++) {
		for (size_t i = 0; i < sets[s].count; i++) {
			const struct property_spec *spec = &sets[s].specs[i];

			if (spec->type != BINARY || spec->f.expect_fail == expect_fail)
				continue;

			/* 1. Fetch raw binary */
			unsigned char buf[512];
			size_t actual_size = 0;
			ret = invoke_get_binary(&session, spec->propset, spec->name, buf,
						sizeof(buf), &actual_size);
			if (ret != TEEC_SUCCESS) {
				printf(RED "FAIL" RESET
					   " bin-base64 %s: %s GetBinaryBlock returned 0x%08x\n",
				       sets[s].set_name, spec->name, ret);
				failures++;
				continue;
			}

			/* 2. Fetch as string (should be base64) */
			char str_buf[512] = {0};
			ret = invoke_get_string(&session, spec->propset, spec->name, str_buf,
						sizeof(str_buf));
			if (ret != TEEC_SUCCESS) {
				printf(RED "FAIL" RESET
					   " bin-base64 %s: %s GetString returned 0x%08x\n",
				       sets[s].set_name, spec->name, ret);
				failures++;
				continue;
			}

			/* 3+4. Decode base64 */
			unsigned char decoded[512];
			size_t decoded_len = 0;
			int rc =
			    mbedtls_base64_decode(decoded, sizeof(decoded), &decoded_len,
						  (const unsigned char *)str_buf, strlen(str_buf));
			if (rc != 0) {
				printf(RED "FAIL" RESET
					   " bin-base64 %s: %s invalid base64 (rc=%d)\n",
				       sets[s].set_name, spec->name, rc);
				failures++;
				continue;
			}

			/* 5. Compare */
			if (decoded_len != actual_size || memcmp(decoded, buf, actual_size) != 0) {
				printf(RED "FAIL" RESET " bin-base64 %s: %s mismatch"
					   " (decoded %zu bytes, raw %zu bytes)\n",
				       sets[s].set_name, spec->name, decoded_len, actual_size);
				failures++;
				continue;
			}

			printf(GREEN "PASS" RESET " bin-base64 %s: %s ok (%zu bytes)\n",
			       sets[s].set_name, spec->name, actual_size);
		}
	}

	close_test_session(&context, &session);

	return failures > 0 ? 1 : 0;
}

/* Gap 2: Test property enumerator API.
 * Exercises Allocate, Start, GetPropertyName, GetPropertyAsString(enumerator),
 * GetNextProperty, Reset, Free. */
static TEEC_Result invoke_enumerate(TEEC_Session *session, uint32_t propset, uint32_t *count)
{
	TEEC_Operation op = {0};
	uint32_t return_origin = 0;
	TEEC_Result ret;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_VALUE_INPUT);
	op.params[3].value.a = propset;

	ret = TEEC_InvokeCommand(session, CMD_ENUMERATE, &op, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed: 0x%08x\n", ret);
		return ret;
	}

	TEEC_Result ta_ret = op.params[0].value.a;
	if (ta_ret != TEEC_SUCCESS)
		return ta_ret;

	*count = op.params[0].value.b;
	return TEEC_SUCCESS;
}

static int test_enumeration()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Result ret;
	int failures = 0;

	if (!open_test_session(&context, &session))
		return 1;

	struct {
		uint32_t propset;
		const char *label;
	} sets[] = {
	    {PROPSET_CURRENT_TA, "CURRENT_TA"},
	    {PROPSET_CURRENT_CLIENT, "CURRENT_CLIENT"},
	    {PROPSET_TEE_IMPLEMENTATION, "TEE_IMPLEMENTATION"},
	};

	for (size_t i = 0; i < ARRAY_SIZE(sets); i++) {
		uint32_t count = 0;
		ret = invoke_enumerate(&session, sets[i].propset, &count);
		if (ret == TEEC_SUCCESS && count > 0) {
			printf(GREEN "PASS" RESET " enumerate %s: %u properties\n", sets[i].label,
			       count);
		} else {
			printf(RED "FAIL" RESET " enumerate %s: ret=0x%08x count=%u\n",
			       sets[i].label, ret, count);
			failures++;
		}
	}

	close_test_session(&context, &session);

	return failures > 0 ? 1 : 0;
}

/* Gap 3: Test TEE_ERROR_ITEM_NOT_FOUND for nonexistent property names. */
static int test_not_found()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Result ret;
	int failures = 0;

	if (!open_test_session(&context, &session))
		return 1;

	char buf[512] = {0};
	ret = invoke_get_string(&session, PROPSET_TEE_IMPLEMENTATION, "nonexistent.property", buf,
				sizeof(buf));
	if (ret == TEEC_ERROR_ITEM_NOT_FOUND) {
		printf(GREEN "PASS" RESET
			     " not-found: GetPropertyAsString returned ITEM_NOT_FOUND\n");
	} else {
		printf(RED "FAIL" RESET
			   " not-found: GetPropertyAsString expected ITEM_NOT_FOUND, got 0x%08x\n",
		       ret);
		failures++;
	}

	bool bval;
	ret =
	    invoke_get_boolean(&session, PROPSET_TEE_IMPLEMENTATION, "nonexistent.property", &bval);
	if (ret == TEEC_ERROR_ITEM_NOT_FOUND) {
		printf(GREEN "PASS" RESET
			     " not-found: GetPropertyAsBool returned ITEM_NOT_FOUND\n");
	} else {
		printf(RED "FAIL" RESET
			   " not-found: GetPropertyAsBool expected ITEM_NOT_FOUND, got 0x%08x\n",
		       ret);
		failures++;
	}

	uint32_t ival;
	ret =
	    invoke_get_integer(&session, PROPSET_TEE_IMPLEMENTATION, "nonexistent.property", &ival);
	if (ret == TEEC_ERROR_ITEM_NOT_FOUND) {
		printf(GREEN "PASS" RESET " not-found: GetPropertyAsU32 returned ITEM_NOT_FOUND\n");
	} else {
		printf(RED "FAIL" RESET
			   " not-found: GetPropertyAsU32 expected ITEM_NOT_FOUND, got 0x%08x\n",
		       ret);
		failures++;
	}

	char binbuf[64];
	size_t binsz;
	ret = invoke_get_binary(&session, PROPSET_TEE_IMPLEMENTATION, "nonexistent.property",
				binbuf, sizeof(binbuf), &binsz);
	if (ret == TEEC_ERROR_ITEM_NOT_FOUND) {
		printf(GREEN "PASS" RESET
			     " not-found: GetPropertyAsBinaryBlock returned ITEM_NOT_FOUND\n");
	} else {
		printf(RED "FAIL" RESET " not-found: GetPropertyAsBinaryBlock expected "
			   "ITEM_NOT_FOUND, got 0x%08x\n",
		       ret);
		failures++;
	}

	TEE_UUID uval;
	ret = invoke_get_uuid(&session, PROPSET_TEE_IMPLEMENTATION, "nonexistent.property", &uval);
	if (ret == TEEC_ERROR_ITEM_NOT_FOUND) {
		printf(GREEN "PASS" RESET
			     " not-found: GetPropertyAsUUID returned ITEM_NOT_FOUND\n");
	} else {
		printf(RED "FAIL" RESET
			   " not-found: GetPropertyAsUUID expected ITEM_NOT_FOUND, got 0x%08x\n",
		       ret);
		failures++;
	}

	TEE_Identity idval;
	ret = invoke_get_identity(&session, PROPSET_TEE_IMPLEMENTATION, "nonexistent.property",
				  &idval);
	if (ret == TEEC_ERROR_ITEM_NOT_FOUND) {
		printf(GREEN "PASS" RESET
			     " not-found: GetPropertyAsIdentity returned ITEM_NOT_FOUND\n");
	} else {
		printf(RED "FAIL" RESET " not-found: GetPropertyAsIdentity expected "
			   "ITEM_NOT_FOUND, got 0x%08x\n",
		       ret);
		failures++;
	}

	close_test_session(&context, &session);

	return failures > 0 ? 1 : 0;
}

/* Test enumerator edge cases: exhausted enum, short buffer name, reset+GetNextProperty. */
static int test_enum_edge_cases()
{
	TEEC_Context context;
	TEEC_Session session;
	uint32_t return_origin = 0;
	TEEC_Result ret;
	int failures = 0;

	if (!open_test_session(&context, &session))
		return 1;

	TEEC_Operation op = {0};
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_VALUE_INPUT);
	op.params[3].value.a = PROPSET_TEE_IMPLEMENTATION;

	ret = TEEC_InvokeCommand(&session, CMD_ENUM_EDGE_CASES, &op, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf(RED "FAIL" RESET " enum-edge: TEEC_InvokeCommand failed 0x%08x\n", ret);
		failures++;
	} else {
		TEEC_Result ta_ret = op.params[0].value.a;
		uint32_t ta_failures = op.params[0].value.b;
		if (ta_ret == TEEC_SUCCESS && ta_failures == 0) {
			printf(GREEN "PASS" RESET " enum-edge: all sub-tests passed\n");
		} else {
			printf(RED "FAIL" RESET " enum-edge: ta_ret=0x%08x failures=%u\n", ta_ret,
			       ta_failures);
			failures++;
		}
	}

	close_test_session(&context, &session);

	return failures > 0 ? 1 : 0;
}

/* Test calling getter with NULL property name -> ITEM_NOT_FOUND. */
static int test_null_name()
{
	TEEC_Context context;
	TEEC_Session session;
	uint32_t return_origin = 0;
	TEEC_Result ret;
	int failures = 0;

	if (!open_test_session(&context, &session))
		return 1;

	TEEC_Operation op = {0};
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_VALUE_INPUT);
	op.params[3].value.a = PROPSET_TEE_IMPLEMENTATION;

	ret = TEEC_InvokeCommand(&session, CMD_NULL_NAME, &op, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf(RED "FAIL" RESET " null-name: TEEC_InvokeCommand failed 0x%08x\n", ret);
		failures++;
	} else {
		TEEC_Result ta_ret = op.params[0].value.a;
		if (ta_ret == TEEC_ERROR_ITEM_NOT_FOUND) {
			printf(GREEN "PASS" RESET
				     " null-name: NULL name returned ITEM_NOT_FOUND\n");
		} else {
			printf(RED "FAIL" RESET " null-name: expected ITEM_NOT_FOUND, got 0x%08x\n",
			       ta_ret);
			failures++;
		}
	}

	close_test_session(&context, &session);

	return failures > 0 ? 1 : 0;
}

/* Gap 4: Test TEE_ERROR_BAD_FORMAT for type-mismatched property requests. */
static int check_bad_format(const char *label, TEEC_Result ret, int *failures)
{
	if (ret == TEEC_ERROR_BAD_FORMAT) {
		printf(GREEN "PASS" RESET " bad-format: %s returned BAD_FORMAT\n", label);
	} else {
		printf(RED "FAIL" RESET " bad-format: %s expected BAD_FORMAT, got 0x%08x\n", label,
		       ret);
		(*failures)++;
	}
	return 0;
}

static int test_bad_format()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Result ret;
	int failures = 0;

	if (!open_test_session(&context, &session))
		return 1;

	/* STRING property requested as bool -> BAD_FORMAT */
	bool b;
	ret = invoke_get_boolean(&session, PROPSET_TEE_IMPLEMENTATION, "gpd.tee.apiversion", &b);
	check_bad_format("STRING as bool", ret, &failures);

	/* UUID property requested as integer -> BAD_FORMAT */
	uint32_t ival;
	ret = invoke_get_integer(&session, PROPSET_TEE_IMPLEMENTATION, "gpd.tee.deviceID", &ival);
	check_bad_format("UUID as integer", ret, &failures);

	/* STRING property requested as binary -> BAD_FORMAT */
	char buf[512];
	size_t sz = 0;
	ret = invoke_get_binary(&session, PROPSET_TEE_IMPLEMENTATION, "gpd.tee.apiversion", buf,
				sizeof(buf), &sz);
	check_bad_format("STRING as binary", ret, &failures);

	/* STRING property requested as UUID -> BAD_FORMAT */
	TEE_UUID u = {0};
	ret = invoke_get_uuid(&session, PROPSET_TEE_IMPLEMENTATION, "gpd.tee.apiversion", &u);
	check_bad_format("STRING as UUID", ret, &failures);

	/* STRING property requested as identity -> BAD_FORMAT */
	TEE_Identity id = {0};
	ret = invoke_get_identity(&session, PROPSET_TEE_IMPLEMENTATION, "gpd.tee.apiversion", &id);
	check_bad_format("STRING as identity", ret, &failures);

	close_test_session(&context, &session);

	return failures > 0 ? 1 : 0;
}

/* Test TEE_GetPropertyAsU64 directly via CMD_GET_U64. */
static TEEC_Result invoke_get_u64(TEEC_Session *session, uint32_t propset, const char *name,
				  uint32_t *out_low)
{
	TEEC_Operation op = {0};
	uint32_t return_origin = 0;
	TEEC_Result ret;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_MEMREF_TEMP_INPUT,
					 TEEC_VALUE_INPUT);
	op.params[2].tmpref.buffer = (void *)name;
	op.params[2].tmpref.size = strlen(name) + 1;
	op.params[3].value.a = propset;

	ret = TEEC_InvokeCommand(session, CMD_GET_U64, &op, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed: 0x%08x\n", ret);
		return ret;
	}

	TEEC_Result ta_ret = op.params[0].value.a;
	if (ta_ret != TEEC_SUCCESS)
		return ta_ret;

	*out_low = op.params[0].value.b;
	return TEEC_SUCCESS;
}

static int test_u64()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Result ret;
	int failures = 0;

	if (!open_test_session(&context, &session))
		return 1;

	struct {
		uint32_t propset;
		const char *name;
	} cases[] = {
	    {PROPSET_CURRENT_TA, "gpd.ta.endian"},
	    {PROPSET_CURRENT_CLIENT, "gpd.client.endian"},
	    {PROPSET_TEE_IMPLEMENTATION, "gpd.tee.event.maxSources"},
	    {PROPSET_TEE_IMPLEMENTATION, "gpd.tee.cryptography.maxRetainedData"},
	};

	for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
		uint32_t val = 0;
		ret = invoke_get_u64(&session, cases[i].propset, cases[i].name, &val);
		if (ret == TEEC_SUCCESS) {
			printf(GREEN "PASS" RESET " u64: %s = %u\n", cases[i].name, val);
		} else {
			printf(RED "FAIL" RESET " u64: %s returned 0x%08x\n", cases[i].name, ret);
			failures++;
		}
	}

	close_test_session(&context, &session);

	return failures > 0 ? 1 : 0;
}

/* Test GetPropertyAsBool with enumerator handle via CMD_GET_BOOL_VIA_ENUM. */
static int test_enum_with_getter()
{
	TEEC_Context context;
	TEEC_Session session;
	uint32_t return_origin = 0;
	TEEC_Result ret;
	int failures = 0;

	if (!open_test_session(&context, &session))
		return 1;

	TEEC_Operation op = {0};
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_VALUE_INPUT);
	op.params[3].value.a = PROPSET_TEE_IMPLEMENTATION;

	ret = TEEC_InvokeCommand(&session, CMD_GET_BOOL_VIA_ENUM, &op, &return_origin);
	if (ret != TEEC_SUCCESS) {
		printf(RED "FAIL" RESET " enum-getter: TEEC_InvokeCommand failed 0x%08x\n", ret);
		failures++;
	} else {
		TEEC_Result ta_ret = op.params[0].value.a;
		if (ta_ret == TEEC_SUCCESS) {
			printf(GREEN "PASS" RESET " enum-getter: GetPropertyAsBool via enumerator"
				     " = %s\n",
			       op.params[0].value.b ? "true" : "false");
		} else {
			printf(RED "FAIL" RESET " enum-getter: ta_ret=0x%08x\n", ta_ret);
			failures++;
		}
	}

	close_test_session(&context, &session);

	return failures > 0 ? 1 : 0;
}

/* Test that error output values are set correctly per spec (false/0 on error). */
static int test_error_output_values()
{
	TEEC_Context context;
	TEEC_Session session;
	uint32_t return_origin = 0;
	TEEC_Result ret;
	int failures = 0;

	if (!open_test_session(&context, &session))
		return 1;

	static const char *labels[] = {
	    "Bool ITEM_NOT_FOUND -> false", "U32 ITEM_NOT_FOUND -> 0", "U64 ITEM_NOT_FOUND -> 0",
	    "Bool BAD_FORMAT -> false",	    "U32 BAD_FORMAT -> 0",
	};

	for (uint32_t sub = 0; sub < 5; sub++) {
		TEEC_Operation op = {0};
		op.paramTypes =
		    TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_VALUE_INPUT);
		op.params[3].value.a = sub;

		ret = TEEC_InvokeCommand(&session, CMD_ERROR_OUTPUT, &op, &return_origin);
		if (ret != TEEC_SUCCESS) {
			printf(RED "FAIL" RESET " error-output[%u] %s: invoke failed 0x%08x\n", sub,
			       labels[sub], ret);
			failures++;
			continue;
		}

		uint32_t output_val = op.params[0].value.a;
		if (output_val == 0) {
			printf(GREEN "PASS" RESET " error-output[%u] %s: output = %u\n", sub,
			       labels[sub], output_val);
		} else {
			printf(RED "FAIL" RESET " error-output[%u] %s: expected 0, got %u\n", sub,
			       labels[sub], output_val);
			failures++;
		}
	}

	close_test_session(&context, &session);

	return failures > 0 ? 1 : 0;
}

/* Gap 5: Test getter panics when propset handle is NULL (propset=0).
 * Passing propset=0 yields a NULL TEE_PropSetHandle, which panics in
 * find_property() and kills the TA. Each test needs a fresh session. */
static int test_panics()
{
	int failures = 0;

	/* Any valid property name works — the panic fires on the NULL
	 * propset handle before the property is looked up. */
	const char *name = "gpd.ta.appID";

	static const char *labels[] = {
	    "GetPropertyAsBool",	"GetPropertyAsU32",  "GetPropertyAsString",
	    "GetPropertyAsBinaryBlock", "GetPropertyAsUUID", "GetPropertyAsIdentity",
	};

	for (size_t i = 0; i < ARRAY_SIZE(labels); i++) {
		/* Fresh context + session for each panic test (panic kills the TA) */
		TEEC_Context context;
		TEEC_Session session;
		uint32_t return_origin = 0;
		TEEC_Result ret;

		ret = TEEC_InitializeContext(NULL, &context);
		if (ret != TEEC_SUCCESS) {
			printf(RED "FAIL" RESET " panic %s: InitializeContext failed 0x%08x\n",
			       labels[i], ret);
			failures++;
			continue;
		}

		ret = TEEC_OpenSession(&context, &session, &(TEEC_UUID)PROPERTY_TEST_TA_UUID,
				       TEEC_LOGIN_PUBLIC, NULL, NULL, &return_origin);
		if (ret != TEEC_SUCCESS) {
			printf(RED "FAIL" RESET " panic %s: OpenSession failed 0x%08x\n", labels[i],
			       ret);
			TEEC_FinalizeContext(&context);
			failures++;
			continue;
		}

		/* propset=0 -> NULL TEE_PropSetHandle -> panic in find_property() */
		bool bval;
		uint32_t ival;
		char buf[8];
		size_t sz;
		TEE_UUID uuid;
		TEE_Identity ident;

		switch (i) {
		case 0:
			ret = invoke_get_boolean(&session, 0, name, &bval);
			break;
		case 1:
			ret = invoke_get_integer(&session, 0, name, &ival);
			break;
		case 2:
			ret = invoke_get_string(&session, 0, name, buf, sizeof(buf));
			break;
		case 3:
			ret = invoke_get_binary(&session, 0, name, buf, sizeof(buf), &sz);
			break;
		case 4:
			ret = invoke_get_uuid(&session, 0, name, &uuid);
			break;
		case 5:
			ret = invoke_get_identity(&session, 0, name, &ident);
			break;
		}

		if (ret == TEEC_ERROR_TARGET_DEAD || ret == TEEC_ERROR_GENERIC) {
			printf(GREEN "PASS" RESET " panic %s: NULL propset -> 0x%08x\n", labels[i],
			       ret);
		} else {
			printf(RED "FAIL" RESET " panic %s: expected TA death, got 0x%08x\n",
			       labels[i], ret);
			failures++;
		}

		TEEC_CloseSession(&session);
		TEEC_FinalizeContext(&context);
	}

	/* NULL name with propset for UUID/Identity -> panic per spec 4.4.5/4.4.6 */
	static const char *null_name_labels[] = {
	    "GetPropertyAsUUID(propset, NULL, ...)",
	    "GetPropertyAsIdentity(propset, NULL, ...)",
	};

	for (size_t i = 0; i < ARRAY_SIZE(null_name_labels); i++) {
		TEEC_Context context;
		TEEC_Session session;
		uint32_t return_origin = 0;
		TEEC_Result ret;

		ret = TEEC_InitializeContext(NULL, &context);
		if (ret != TEEC_SUCCESS) {
			printf(RED "FAIL" RESET " panic %s: InitializeContext failed 0x%08x\n",
			       null_name_labels[i], ret);
			failures++;
			continue;
		}

		ret = TEEC_OpenSession(&context, &session, &(TEEC_UUID)PROPERTY_TEST_TA_UUID,
				       TEEC_LOGIN_PUBLIC, NULL, NULL, &return_origin);
		if (ret != TEEC_SUCCESS) {
			printf(RED "FAIL" RESET " panic %s: OpenSession failed 0x%08x\n",
			       null_name_labels[i], ret);
			TEEC_FinalizeContext(&context);
			failures++;
			continue;
		}

		TEEC_Operation op = {0};
		op.paramTypes =
		    TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_VALUE_INPUT);
		op.params[3].value.a = PROPSET_TEE_IMPLEMENTATION;
		op.params[3].value.b = (uint32_t)i;

		ret = TEEC_InvokeCommand(&session, CMD_PANIC_NULL_NAME, &op, &return_origin);

		if (ret == TEEC_ERROR_TARGET_DEAD || ret == TEEC_ERROR_GENERIC) {
			printf(GREEN "PASS" RESET " panic %s: -> 0x%08x\n", null_name_labels[i],
			       ret);
		} else {
			printf(RED "FAIL" RESET " panic %s: expected TA death, got 0x%08x\n",
			       null_name_labels[i], ret);
			failures++;
		}

		TEEC_CloseSession(&session);
		TEEC_FinalizeContext(&context);
	}

	/* Second loop: CMD_PANIC_NULL_OUTPUT sub-commands (NULL output pointers) */
	static const char *null_labels[] = {
	    "GetPropertyAsBool(NULL out)",	"GetPropertyAsU32(NULL out)",
	    "GetPropertyAsString(NULL buf)",	"GetPropertyAsBinaryBlock(NULL buf)",
	    "GetPropertyAsUUID(NULL out)",	"GetPropertyAsIdentity(NULL out)",
	    "AllocatePropertyEnumerator(NULL)", "FreePropertyEnumerator(NULL)",
	    "StartPropertyEnumerator(NULL,..)", "ResetPropertyEnumerator(NULL)",
	    "GetPropertyName(NULL,..)",		"GetNextProperty(NULL)",
	    "GetPropertyName(zeroed enum)",
	};

	for (size_t i = 0; i < ARRAY_SIZE(null_labels); i++) {
		TEEC_Context context;
		TEEC_Session session;
		uint32_t return_origin = 0;
		TEEC_Result ret;

		ret = TEEC_InitializeContext(NULL, &context);
		if (ret != TEEC_SUCCESS) {
			printf(RED "FAIL" RESET " panic %s: InitializeContext failed 0x%08x\n",
			       null_labels[i], ret);
			failures++;
			continue;
		}

		ret = TEEC_OpenSession(&context, &session, &(TEEC_UUID)PROPERTY_TEST_TA_UUID,
				       TEEC_LOGIN_PUBLIC, NULL, NULL, &return_origin);
		if (ret != TEEC_SUCCESS) {
			printf(RED "FAIL" RESET " panic %s: OpenSession failed 0x%08x\n",
			       null_labels[i], ret);
			TEEC_FinalizeContext(&context);
			failures++;
			continue;
		}

		ret = invoke_panic_null_output(&session, PROPSET_TEE_IMPLEMENTATION,
					       "gpd.tee.apiversion", (uint32_t)i);

		if (ret == TEEC_ERROR_TARGET_DEAD || ret == TEEC_ERROR_GENERIC) {
			printf(GREEN "PASS" RESET " panic %s: -> 0x%08x\n", null_labels[i], ret);
		} else {
			printf(RED "FAIL" RESET " panic %s: expected TA death, got 0x%08x\n",
			       null_labels[i], ret);
			failures++;
		}

		TEEC_CloseSession(&session);
		TEEC_FinalizeContext(&context);
	}

	return failures > 0 ? 1 : 0;
}

/* Gap 6: Test TEE_ERROR_SHORT_BUFFER for undersized output buffers. */
static int check_short_buffer(const char *label, TEEC_Result ret, int *failures)
{
	if (ret == TEEC_ERROR_SHORT_BUFFER) {
		printf(GREEN "PASS" RESET " short-buffer: %s returned SHORT_BUFFER\n", label);
	} else if (ret == TEEC_SUCCESS) {
		printf(GREEN "PASS" RESET " short-buffer: %s value fit in tiny buffer\n", label);
	} else {
		printf(RED "FAIL" RESET " short-buffer: %s expected SHORT_BUFFER, got 0x%08x\n",
		       label, ret);
		(*failures)++;
	}
	return 0;
}

static const char *type_label(enum property_type t)
{
	switch (t) {
	case STRING:
		return "STR";
	case BINARY:
		return "BIN";
	case INTEGER:
		return "INT->str";
	case BOOLEAN:
		return "BOOL->str";
	case UUID_TYPE:
		return "UUID->str";
	case IDENTITY:
		return "IDENT->str";
	}
	return "???";
}

static int test_short_buffer()
{
	TEEC_Context context;
	TEEC_Session session;
	TEEC_Result ret = TEEC_SUCCESS;
	int failures = 0;

	if (!open_test_session(&context, &session))
		return 1;

	struct {
		const char *set_name;
		const struct property_spec *specs;
		size_t count;
	} sets[] = {
	    {"CURRENT_TA", propset_current_ta_spec, ARRAY_SIZE(propset_current_ta_spec)},
	    {"CURRENT_CLIENT", propset_current_client_spec,
	     ARRAY_SIZE(propset_current_client_spec)},
	    {"TEE_IMPLEMENTATION", propset_tee_implementation_spec,
	     ARRAY_SIZE(propset_tee_implementation_spec)},
	};

	char tiny[1] = {0};
	size_t sz = 0;
	char label[256];

	for (size_t s = 0; s < ARRAY_SIZE(sets); s++) {
		for (size_t i = 0; i < sets[s].count; i++) {
			const struct property_spec *spec = &sets[s].specs[i];

			/* Skip properties that are not implemented */
			if (spec->f.expect_fail == expect_fail)
				continue;

			snprintf(label, sizeof(label), "%s %s %s", type_label(spec->type),
				 sets[s].set_name, spec->name);

			switch (spec->type) {
			case STRING:
				ret = invoke_get_string(&session, spec->propset, spec->name, tiny,
							sizeof(tiny));
				break;
			case BINARY:
				ret = invoke_get_binary(&session, spec->propset, spec->name, tiny,
							sizeof(tiny), &sz);
				check_short_buffer(label, ret, &failures);
				/* Also test BIN->str conversion path (base64) */
				snprintf(label, sizeof(label), "BIN->str %s %s", sets[s].set_name,
					 spec->name);
				ret = invoke_get_string(&session, spec->propset, spec->name, tiny,
							sizeof(tiny));
				break;
			case INTEGER:
			case BOOLEAN:
			case UUID_TYPE:
			case IDENTITY:
				/* Type-conversion: request as string with tiny buffer */
				ret = invoke_get_string(&session, spec->propset, spec->name, tiny,
							sizeof(tiny));
				break;
			}

			check_short_buffer(label, ret, &failures);
		}
	}

	close_test_session(&context, &session);

	return failures > 0 ? 1 : 0;
}

int main()
{
	printf("START: property test app\n\n");

	int ret = test_all_properties();
	ret |= test_u64();
	ret |= test_string_conversions();
	ret |= test_binary_base64();
	ret |= test_enum_with_getter();
	ret |= test_enumeration();
	ret |= test_not_found();
	ret |= test_error_output_values();
	ret |= test_enum_edge_cases();
	ret |= test_null_name();
	ret |= test_bad_format();
	ret |= test_short_buffer();
	ret |= test_panics();

	printf("\n");
	if (ret == 0) {
		printf(GREEN "!!! SUCCESS !!!" RESET "\n");
		printf("Property test app did not find any errors.\n");
		printf(GREEN "^^^ SUCCESS ^^^" RESET "\n");
	} else {
		printf(RED "### ERROR ###" RESET "\n");
		printf("Property test app found some errors.\n");
		printf(RED "^^^ ERROR ^^^" RESET "\n");
	}

	return ret;
}
