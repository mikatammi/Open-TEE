// SPDX-FileCopyrightText: 2026 Mika Tammi
//
// SPDX-License-Identifier: Apache-2.0

#ifndef PROPERTY_TEST_CTL_H
#define PROPERTY_TEST_CTL_H

/* Property set pseudo-handles (match TEE_PROPSET_* values from Internal API) */
#define PROPSET_CURRENT_TA 0xFFFFFFFFU
#define PROPSET_CURRENT_CLIENT 0xFFFFFFFEU
#define PROPSET_TEE_IMPLEMENTATION 0xFFFFFFFDU

/* TA UUID for property_test_ta */
#define PROPERTY_TEST_TA_UUID                                                                      \
	{0xb8fe5b9e, 0xf765, 0x42f1, {0xb8, 0xa8, 0xa6, 0xdc, 0xe4, 0x50, 0x16, 0x05}}

/* Command IDs shared between property_test_ca and property_test_ta */
#define CMD_GET_BOOLEAN 4
#define CMD_GET_INTEGER 5
#define CMD_GET_STRING 6
#define CMD_GET_BINARY 7
#define CMD_GET_UUID 8
#define CMD_GET_IDENTITY 9
#define CMD_ENUMERATE 10
#define CMD_ENUM_EDGE_CASES 11
#define CMD_NULL_NAME 12
#define CMD_PANIC_NULL_OUTPUT 13
#define CMD_GET_U64 14
#define CMD_GET_BOOL_VIA_ENUM 15
#define CMD_ERROR_OUTPUT 16
#define CMD_PANIC_NULL_NAME 17

#endif /* PROPERTY_TEST_CTL_H */
