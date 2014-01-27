/*-
 * Copyright (C) 2010, Romain Tartiere, Romuald Conty.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 * $Id$
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <freefare.h>

#include "freefare_internal.h"

#define NXP_MANUFACTURER_CODE 0x04

static struct supported_tag supported_tags[] = {
    { CLASSIC_1K,   "Mifare Classic 1k",            0x08, 0, 0, { 0x00 }, NULL },
    { CLASSIC_1K,   "Mifare Classic 1k (Emulated)", 0x28, 0, 0, { 0x00 }, NULL },
    { CLASSIC_1K,   "Mifare Classic 1k (Emulated)", 0x68, 0, 0, { 0x00 }, NULL },
    { CLASSIC_1K,   "Infineon Mifare Classic 1k",   0x88, 0, 0, { 0x00 }, NULL },
    { CLASSIC_4K,   "Mifare Classic 4k",            0x18, 0, 0, { 0x00 }, NULL },
    { CLASSIC_4K,   "Mifare Classic 4k (Emulated)", 0x38, 0, 0, { 0x00 }, NULL },
    { DESFIRE,      "Mifare DESFire",               0x20, 5, 4, { 0x75, 0x77, 0x81, 0x02 /*, 0xXX */ }, NULL},
    { ULTRALIGHT_C, "Mifare UltraLightC",           0x00, 0, 0, { 0x00 }, mifare_ultralightc_is_on_reader },
    { ULTRALIGHT,   "Mifare UltraLight",            0x00, 0, 0, { 0x00 }, NULL },
};

struct supported_reader {
    FreefareFlags identifying_flag;
    void(*tag_free)(MifareTag tag);
    char*(*get_uid)(MifareTag tag);
    const char*(*strerror)(MifareTag tag);
    int(*connect)(MifareTag tag);
    int(*disconnect)(MifareTag tag);
    int(*transceive_bytes)(MifareTag tag, uint8_t *send, size_t send_length, uint8_t *recv, size_t recv_length, int timeout);
};

#define DEFAULT_READER_LIST_LENGTH 16

static FreefareContext implicit_context = NULL;
const nfc_modulation FREEFARE_LIBNFC_DEFAULT_MODULATION = {.nmt = NMT_ISO14443A, .nbr = NBR_106 };

static MifareTag 	*_freefare_tags_get (FreefareContext ctx, enum mifare_tag_type tag_type, struct freefare_enumeration_state *state);

static MifareTag	 _libnfc_tag_new(FreefareContext ctx, FreefareFlags flags, int device_handle, nfc_iso14443a_info info, nfc_modulation modulation, enum mifare_tag_type tag_type);

static void 		 _reader_context_free(struct freefare_reader_context **conptr);
static int 		 _reader_device_store(struct freefare_context *ctx, struct freefare_reader_device *reader_device);
static void 		 _reader_device_free(struct freefare_reader_device **devptr);
static const struct supported_reader *_reader_driver_lookup(FreefareFlags identifying_flag);

FreefareContext freefare_implicit_context(void)
{
    if(implicit_context) {
	return implicit_context;
    }

    return implicit_context = freefare_init(0);
}

/*
 * Legacy function to automagically allocate a new MifareTag
 * given a device and target info
 */
MifareTag
freefare_tag_new (nfc_device *device, nfc_iso14443a_info nai)
{
    FreefareContext ctx = freefare_implicit_context();
    return freefare_tag_new_ex(ctx, (ctx->global_flags & FREEFARE_FLAG_MASK_GLOBAL_INHERIT) | FREEFARE_FLAG_READER_LIBNFC, FREEFARE_TAG_LIBNFC(device, nai, FREEFARE_LIBNFC_DEFAULT_MODULATION), NO_TAG_TYPE);
}

/*
 * Automagically allocate a MifareTag given a reader driver specific information.
 * Will try to use the tag as given by tag_type, or reject it otherwise
 */
MifareTag
freefare_tag_new_ex (FreefareContext ctx, FreefareFlags flags, FreefareReaderTag reader_tag, enum mifare_tag_type tag_type)
{
    if(!ctx) {
	return NULL;
    }

    if(flags & FREEFARE_FLAG_READER_LIBNFC) {
	struct freefare_reader_device *reader_device = calloc(1, sizeof(*reader_device));
	if(!reader_device) {
	    return NULL;
	}

	reader_device->flags = FREEFARE_FLAG_READER_LIBNFC | (ctx->global_flags & FREEFARE_FLAG_MASK_GLOBAL_INHERIT);
	reader_device->internal = 1;
	reader_device->device = FREEFARE_DEVICE_LIBNFC(reader_tag.libnfc.device);
	int slot = _reader_device_store(ctx, reader_device);
	if(slot < 0) {
	    _reader_device_free(&reader_device);
	    return NULL;
	}

	MifareTag result = _libnfc_tag_new(ctx, flags, slot, reader_tag.libnfc.nai, reader_tag.libnfc.modulation, tag_type);
	_reader_device_free(ctx->reader_devices + slot);
	return result;
    }

    return NULL;
}

static MifareTag _freefare_tag_allocate(FreefareContext ctx, FreefareFlags flags, const struct supported_tag *tag_info)
{
    if(!ctx || !tag_info) {
	return NULL;
    }

    MifareTag result = NULL;
    switch (tag_info->type) {
    case NO_TAG_TYPE:
	result = NULL;
	break;
    case CLASSIC_1K:
    case CLASSIC_4K:
	result = mifare_classic_tag_new ();
	break;
    case DESFIRE:
	result = mifare_desfire_tag_new ();
	break;
    case ULTRALIGHT:
    case ULTRALIGHT_C:
	result = mifare_ultralight_tag_new ();
	break;
    }

    if (!result)
	return NULL;

    /*
     * Initialize common fields
     * (Target specific fields are initialized in mifare_*_tag_new(),
     *  Reader driver specific fields in _freefare_tag_new_*())
     */
    result->ctx = ctx;
    result->active = 0;
    result->tag_info = tag_info;
    result->flags = flags;

    return result;
}

/*
 * Determine if the tag is compatible with tag_type, if given, or determine
 * the tag type.
 * TODO: Currently only determines the tag type. Does not correctly account
 * for multiple identity tags (e.g. SmartMX with included Classic emulation).
 */
static const struct supported_tag *_libnfc_tag_type(FreefareContext ctx, FreefareFlags flags, struct freefare_reader_device *device, nfc_iso14443a_info info, enum mifare_tag_type tag_type)
{
    /* Ensure the target is supported */
    for (size_t i = 0; i < sizeof (supported_tags) / sizeof (struct supported_tag); i++) {
	if (((info.szUidLen == 4) || (info.abtUid[0] == NXP_MANUFACTURER_CODE)) &&
	    (info.btSak == supported_tags[i].SAK) &&
	    (!supported_tags[i].ATS_min_length || ((info.szAtsLen >= supported_tags[i].ATS_min_length) &&
						   (0 == memcmp (info.abtAts, supported_tags[i].ATS, supported_tags[i].ATS_compare_length)))) &&
	    ((supported_tags[i].check_tag_on_reader == NULL) ||
	     supported_tags[i].check_tag_on_reader(ctx, flags, FREEFARE_TAG_LIBNFC(device->device.libnfc, info, FREEFARE_LIBNFC_DEFAULT_MODULATION)))) {
		/*
		 * FIXME The FREEFARE_TAG_LIBNFC above is bonkers. This method should have gotten a FreefareReaderTag object passed in. Or actual, a FreefareReaderTagInternal (to be defined) or something.
		 */

	    if(tag_type == NO_TAG_TYPE || supported_tags[i].type == tag_type) {
		return &(supported_tags[i]);
	    }
	}
    }

    return NULL;
}

static MifareTag _libnfc_tag_new(FreefareContext ctx, FreefareFlags flags, int device_handle, nfc_iso14443a_info info, nfc_modulation modulation, enum mifare_tag_type tag_type)
{

    if(!ctx || !ctx->reader_devices[device_handle]) {
	return NULL;
    }

    const struct supported_reader *reader_fns = _reader_driver_lookup(FREEFARE_FLAG_READER_LIBNFC);
    if(!reader_fns) {
	return NULL;
    }

    const struct supported_tag *tag_info = _libnfc_tag_type(ctx, flags, ctx->reader_devices[device_handle], info, tag_type);
    if(!tag_info) {
	return NULL;
    }

    if(tag_type != NO_TAG_TYPE && tag_info->type != tag_type) {
	return NULL;
    }

    MifareTag result = _freefare_tag_allocate(ctx, flags, tag_info);
    if(!result) {
	return NULL;
    }

    /*
     * Initialize libnfc specific fields
     */
    result->libnfc.reader_device_handle = device_handle;
    result->libnfc.info = info;
    result->libnfc.modulation = modulation;
    result->reader = reader_fns;

    /*
     * Increment reference count on the reader_device
     */
    result->ctx->reader_devices[result->libnfc.reader_device_handle]->references++;

    return result;
}

static void _libnfc_tag_free(MifareTag tag)
{
    if(!tag || !tag->ctx) {
	return;
    }

    /*
     * Decrement reference count on the reader_device
     */
    _reader_device_free(tag->ctx->reader_devices + tag->libnfc.reader_device_handle);
}

static int _libnfc_connect(MifareTag tag)
{
    if(!tag) return errno = EBADF, -1;
    return nfc_initiator_select_passive_target (tag->ctx->reader_devices[tag->libnfc.reader_device_handle]->device.libnfc, tag->libnfc.modulation, tag->libnfc.info.abtUid, tag->libnfc.info.szUidLen, &tag->libnfc.pnti);
}

static int _libnfc_disconnect(MifareTag tag)
{
    if(!tag) return errno = EBADF, -1;
    return nfc_initiator_deselect_target (tag->ctx->reader_devices[tag->libnfc.reader_device_handle]->device.libnfc);
}

static int _libnfc_transceive_bytes(MifareTag tag, uint8_t *send, size_t send_length, uint8_t *recv, size_t recv_length, int timeout)
{
    return nfc_initiator_transceive_bytes (tag->ctx->reader_devices[tag->libnfc.reader_device_handle]->device.libnfc, send, send_length, recv, recv_length, timeout);
}


/*
 * MIFARE card common functions
 *
 * The following functions send NFC commands to the initiator to prepare
 * communication with a MIFARE card, and perform required cleannups after using
 * the targets.
 */

/*
 * Get a list of the MIFARE targets near to the provided NFC initiator.
 *
 * The list has to be freed using the freefare_free_tags() function.
 */
MifareTag *
freefare_get_tags (nfc_device *device)
{
    FreefareContext ctx = freefare_implicit_context();

    /*
     * Use the tags_get functionality, but with a local enumeration state
     * and limited to a temporary reader_device injected into the context
     */
    struct freefare_enumeration_state state;
    memset(&state, 0, sizeof(state));

    struct freefare_reader_device *reader_device = calloc(1, sizeof(*reader_device));
    if(reader_device == NULL) {
	return NULL;
    }
    reader_device->device = FREEFARE_DEVICE_LIBNFC(device);
    reader_device->flags = FREEFARE_FLAG_READER_LIBNFC | (ctx->global_flags & FREEFARE_FLAG_MASK_GLOBAL_INHERIT);
    reader_device->internal = 1;

    int slot = _reader_device_store(ctx, reader_device);
    if(slot < 0) {
	_reader_device_free(&reader_device);
	return NULL;
    }

    state.phase = FREEFARE_ENUMERATION_PHASE_EXT_DEVICE;
    state.single_device = 1;
    state.device_handle = slot;

    MifareTag *tags = _freefare_tags_get(ctx, NO_TAG_TYPE, &state);

    _reader_device_free(ctx->reader_devices + slot);

    return tags;
}

/*
 * Returns the type of the provided tag.
 */
enum mifare_tag_type
freefare_get_tag_type (MifareTag tag)
{
    return tag->tag_info->type;
}

/*
 * Returns the friendly name of the provided tag.
 */
const char *
freefare_get_tag_friendly_name (MifareTag tag)
{
    return tag->tag_info->friendly_name;
}

/*
 * Returns the UID of the provided tag.
 */
char *
freefare_get_tag_uid (MifareTag tag)
{
    if(!tag || !tag->reader) {
	return NULL;
    }
    return tag->reader->get_uid(tag);
}

static char *
_libnfc_get_tag_uid(MifareTag tag)
{
    if(!tag) {
	return NULL;
    }
    char *res = malloc (2 * tag->libnfc.info.szUidLen + 1);
    for (size_t i =0; i < tag->libnfc.info.szUidLen; i++)
        snprintf (res + 2*i, 3, "%02x", tag->libnfc.info.abtUid[i]);
    return res;
}

/*
 * Free the provided tag.
 */
void
freefare_free_tag (MifareTag tag)
{
    if(!tag) {
	return;
    }

    /*
     * Free any reader specific data
     */
    tag->reader->tag_free(tag);

    /*
     * Free the tag specific and tag data
     */
    if (tag) {
        switch (tag->tag_info->type) {
        case NO_TAG_TYPE:
            break;
        case CLASSIC_1K:
        case CLASSIC_4K:
            mifare_classic_tag_free (tag);
            break;
        case DESFIRE:
            mifare_desfire_tag_free (tag);
            break;
        case ULTRALIGHT:
        case ULTRALIGHT_C:
            mifare_ultralight_tag_free (tag);
            break;
        }
    }
}

const char *
_libnfc_strerror(MifareTag tag)
{
    if(!tag) {
	return NULL;
    }

    if (nfc_device_get_last_error (tag->ctx->reader_devices[tag->libnfc.reader_device_handle]->device.libnfc) < 0) {
	return nfc_strerror (tag->ctx->reader_devices[tag->libnfc.reader_device_handle]->device.libnfc);
    }

    return NULL;
}

const char *
freefare_strerror (MifareTag tag)
{
    if(!tag || !tag->reader) {
	return NULL;
    }


    const char *p = tag->reader->strerror(tag);

    if(p) {
	return p;
    }

    p = "Unknown error";

    if (tag->tag_info->type == DESFIRE) {
	if (MIFARE_DESFIRE (tag)->last_pcd_error) {
	    p = mifare_desfire_error_lookup (MIFARE_DESFIRE (tag)->last_pcd_error);
	} else if (MIFARE_DESFIRE (tag)->last_picc_error) {
	    p = mifare_desfire_error_lookup (MIFARE_DESFIRE (tag)->last_picc_error);
	}
    }

    return p;
}

int
freefare_strerror_r (MifareTag tag, char *buffer, size_t len)
{
    return (snprintf (buffer, len, "%s", freefare_strerror (tag)) < 0) ? -1 : 0;
}

void
freefare_perror (MifareTag tag, const char *string)
{
    fprintf (stderr, "%s: %s\n", string, freefare_strerror (tag));
}

/*
 * Free the provided tag list.
 */
void
freefare_free_tags (MifareTag *tags)
{
    if (tags) {
	for (int i=0; tags[i]; i++) {
	    freefare_free_tag(tags[i]);
	}
	free (tags);
    }
}


static struct freefare_reader_context *_libnfc_context_open(FreefareFlags flags)
{
    struct freefare_reader_context *result = calloc(1, sizeof(*result));
    if(!result) {
	return NULL;
    }
    nfc_init(&(result->context.libnfc));
    result->flags = flags;

    return result;
}

static void _libnfc_context_free(struct freefare_reader_context *context)
{
    if(!context) {
	return;
    }
    if(context->flags & FREEFARE_FLAG_AUTOCLOSE) {
	nfc_exit(context->context.libnfc);
    }
    free(context);
}

static struct freefare_reader_device *_libnfc_device_open(struct freefare_reader_context *context, nfc_connstring connstring, FreefareFlags flags)
{
    if(!context || !(context->flags & FREEFARE_FLAG_READER_LIBNFC)) {
	return NULL;
    }

    struct freefare_reader_device *result = calloc(1, sizeof(*result));
    if(!result) {
	return NULL;
    }

    nfc_device *device = nfc_open(context->context.libnfc, connstring);
    if(!device) {
	free(result);
	return NULL;
    }

    if(flags & FREEFARE_FLAG_DISABLE_ISO14443_4) {
	nfc_device_set_property_bool(device, NP_AUTO_ISO14443_4, false);
    } else {
	nfc_device_set_property_bool(device, NP_AUTO_ISO14443_4, true);
    }

    result->device = FREEFARE_DEVICE_LIBNFC(device);
    result->flags = flags | FREEFARE_FLAG_READER_LIBNFC;
    result->references = 1;

    return result;
}

static void _libnfc_device_free(struct freefare_reader_device *device)
{
    if(!device) {
	return;
    }
    if(device->flags & FREEFARE_FLAG_AUTOCLOSE) {
	nfc_close(device->device.libnfc);
    }
    free(device);
}

static int _libnfc_enumerate_device(FreefareContext ctx, int device_handle, struct freefare_enumeration_state *state, MifareTag *result)
{
    if(!ctx || !ctx->reader_devices[device_handle]) {
	return -1;
    }

    if(!state->libnfc.candidates) {
	state->libnfc.candidates_length = DEFAULT_READER_LIST_LENGTH;
	state->libnfc.candidates = calloc(state->libnfc.candidates_length, sizeof(state->libnfc.candidates[0]));
	if(!state->libnfc.candidates) {
	    state->libnfc.candidates_length = 0;
	    return -1;
	}

	nfc_initiator_init(ctx->reader_devices[device_handle]->device.libnfc);

	// Drop the field for a while
	nfc_device_set_property_bool(ctx->reader_devices[device_handle]->device.libnfc,NP_ACTIVATE_FIELD,false);

	// Configure the CRC and Parity settings
	nfc_device_set_property_bool(ctx->reader_devices[device_handle]->device.libnfc,NP_HANDLE_CRC,true);
	nfc_device_set_property_bool(ctx->reader_devices[device_handle]->device.libnfc,NP_HANDLE_PARITY,true);
	if(ctx->reader_devices[device_handle]->flags & FREEFARE_FLAG_DISABLE_ISO14443_4) {
	    nfc_device_set_property_bool(ctx->reader_devices[device_handle]->device.libnfc,NP_AUTO_ISO14443_4,false);
	} else {
	    nfc_device_set_property_bool(ctx->reader_devices[device_handle]->device.libnfc,NP_AUTO_ISO14443_4,true);
	}

	// Enable field so more power consuming cards can power themselves up
	nfc_device_set_property_bool(ctx->reader_devices[device_handle]->device.libnfc,NP_ACTIVATE_FIELD,true);

	// Poll for a ISO14443A (MIFARE) tag
	state->libnfc.modulation = FREEFARE_LIBNFC_DEFAULT_MODULATION;
	state->libnfc.candidates_length = nfc_initiator_list_passive_targets(ctx->reader_devices[device_handle]->device.libnfc, state->libnfc.modulation, state->libnfc.candidates, state->libnfc.candidates_length);
	if (state->libnfc.candidates_length < 0) {
	    free(state->libnfc.candidates);
	    state->libnfc.candidates_length = 0;
	    return -1;
	}
	state->libnfc.candidate_index = 0;
    }

    while(state->libnfc.candidate_index < state->libnfc.candidates_length) {
	*result = _libnfc_tag_new(ctx, FREEFARE_FLAG_READER_LIBNFC, device_handle, state->libnfc.candidates[state->libnfc.candidate_index].nti.nai, state->libnfc.modulation, state->tag_type);
	state->libnfc.candidate_index++;
	if(*result) {
	    return 0;
	}
    }

    free(state->libnfc.candidates);
    state->libnfc.candidates = 0;
    state->libnfc.candidates_length = 0;

    return 0;
}

/*
 * This enumerates (via nfc_list_devices()) all readers in a libnfc context, then calls _libnfc_enumerate_device()
 * for all of them using a temporary struct freefare_reader_device. If a tag has been found, the struct freefare_reader_device
 * is persisted into ctx.
 * It's written in a slightly complicated way to allow return and resume after a tag detection
 */
static int _libnfc_enumerate_context(FreefareContext ctx, struct freefare_reader_context *context, struct freefare_enumeration_state *state, MifareTag *result)
{
    if(!ctx || !context || !state || !result) {
	return -1;
    }

    if(!state->libnfc.connstrings) {
	/*
	 * Enumerate readers
	 */
	state->libnfc.connstrings_length = DEFAULT_READER_LIST_LENGTH;
	state->libnfc.connstrings = calloc(state->libnfc.connstrings_length, sizeof(state->libnfc.connstrings[0]));
	if(!state->libnfc.connstrings) {
	    state->libnfc.connstrings_length = 0;
	    return -1;
	}
	state->libnfc.connstrings_length = nfc_list_devices(context->context.libnfc, state->libnfc.connstrings, state->libnfc.connstrings_length);
    }

    while(state->context_device_index < state->libnfc.connstrings_length) {
	if(!state->tmp_device) {
	    state->tmp_device = _libnfc_device_open(context, state->libnfc.connstrings[state->context_device_index],
		    FREEFARE_FLAG_AUTOCLOSE | (context->flags & FREEFARE_FLAG_MASK_GLOBAL_INHERIT));
	    if(!state->tmp_device) {
		return -1;
	    }
	    state->tmp_device->internal = 1;
	    state->tmp_device_handle = _reader_device_store(ctx, state->tmp_device);
	    if(state->tmp_device_handle < 0) {
		_reader_device_free(&state->tmp_device);
		return -1;
	    }
	}

	if(_libnfc_enumerate_device(ctx, state->tmp_device_handle, state, result) < 0) {
	    return -1;
	}

	if(*result) {
	    /*
	     * The reference counter in the tmp_device structure has already been
	     * incremented.
	     */
	    return 0;

	}

	/*
	 * This is a no-op if the device is referenced by a tag, otherwise it
	 * will close and free the device structure.
	 */
	_reader_device_free(ctx->reader_devices + state->tmp_device_handle);
	state->context_device_index++;
    }

    if(state->libnfc.connstrings) {
	free(state->libnfc.connstrings);
	state->libnfc.connstrings = NULL;
    }
    state->libnfc.connstrings_length = 0;

    return 0;
}

static int _embiggen_array(void **array, size_t *array_length, size_t element_size, size_t min_elements)
{
    if(!array || !array_length) {
	return -1;
    }

    if(*array && *array_length >= min_elements) {
	return 0;
    }

    void *new_array = calloc(min_elements, element_size);
    if(!new_array) {
	return -1;
    }

    if(*array) {
	memcpy(new_array, *array, element_size * (*array_length));
    }
    free(*array);
    *array = new_array;
    *array_length = min_elements;
    return 0;
}

static int _array_store(void ***array, size_t *array_length, size_t element_size, void *new_element)
{
    if(!array || !array_length) {
	return -1;
    }

    /*
     * Ensure the array is allocated
     */
    if(_embiggen_array((void**)array, array_length, element_size, DEFAULT_READER_LIST_LENGTH) < 0) {
	return -1;
    }

    /*
     * Search through the array for the first free slot and use it
     */
    for(size_t i=0; i<*array_length; i++) {
	if((*array)[i] == NULL) {
	    (*array)[i] = new_element;
	    return i;
	}
    }

    /*
     * No slot found, enlarge the array and use the next one
     */
    int slot = *array_length;
    if(_embiggen_array((void**)array, array_length, element_size, slot+1) < 0) {
	return -1;
    } else {
	(*array)[slot] = new_element;
	return slot;
    }

    return -1;
}

static int _reader_context_store(struct freefare_context *ctx, struct freefare_reader_context *reader_context)
{
    if(!ctx || !reader_context) {
	return -1;
    }

    return _array_store((void***)&ctx->reader_contexts, &ctx->reader_contexts_length, sizeof(ctx->reader_contexts[0]), reader_context);
}

static int _reader_device_store(struct freefare_context *ctx, struct freefare_reader_device *reader_device)
{
    if(!ctx || !reader_device) {
	return -1;
    }

    return _array_store((void***)&ctx->reader_devices, &ctx->reader_devices_length, sizeof(ctx->reader_devices[0]), reader_device);
}

/*
 * Allocate a new library context, possibly initialize lower-level
 * reader library connections
 */
FreefareContext	 freefare_init (FreefareFlags flags)
{
    struct freefare_context *result = calloc(1, sizeof(*result));
    if(!result) {
	return NULL;
    }

    result->global_flags = flags;
    if(result->global_flags & FREEFARE_FLAG_READER_ALL) {
	result->global_flags &= ~FREEFARE_FLAG_READER_ALL;
	result->global_flags |= FREEFARE_FLAG_MASK_READER_ALL;
    }

    if(result->global_flags & FREEFARE_FLAG_READER_LIBNFC) {
	/*
	 * Initialize an internal libnfc connection
	 */
	struct freefare_reader_context *libnfc_context = _libnfc_context_open(
		FREEFARE_FLAG_READER_LIBNFC | FREEFARE_FLAG_AUTOCLOSE |
		(result->global_flags & FREEFARE_FLAG_MASK_GLOBAL_INHERIT)
	);
	if(!libnfc_context) {
	    goto abort;
	}
	libnfc_context->internal = 1;
	if(_reader_context_store(result, libnfc_context) < 0) {
	    _libnfc_context_free(libnfc_context);
	    goto abort;
	}
    }

    return result;
abort:
    freefare_exit(result);
    return NULL;
}

MifareTag _freefare_tag_next (FreefareContext ctx, struct freefare_enumeration_state *state)
{
    if(!ctx || !state) {
	return NULL;
    }

    MifareTag result = NULL;

    switch(state->phase) {
    case FREEFARE_ENUMERATION_PHASE_NONE:
	state->phase = FREEFARE_ENUMERATION_PHASE_EXT_DEVICE;
	state->device_handle = 0;
	/*
	 * No break, due to fall-through
	 */
    case FREEFARE_ENUMERATION_PHASE_EXT_DEVICE:
	while(state->device_handle < ctx->reader_devices_length) {
	    /*
	     * Ignore empty slots and "internal" devices except when in single_device mode
	     */
	    if(!ctx->reader_devices[state->device_handle] || (ctx->reader_devices[state->device_handle]->internal && !state->single_device)) {
		if(state->single_device) {
		    break;
		}
		state->device_handle++;
		continue;
	    }

	    if( ctx->reader_devices[state->device_handle]->flags & FREEFARE_FLAG_READER_LIBNFC ) {
		_libnfc_enumerate_device(ctx, state->device_handle, state, &result);
	    }

	    if(result) {
		return result;
	    }

	    if(state->single_device) {
		break;
	    }
	    state->device_handle++;
	}

	if(state->single_device) {
	    break;
	}
	state->phase = FREEFARE_ENUMERATION_PHASE_EXT_CONTEXT;
	state->context_handle = 0;
	state->context_device_index = 0;
	/*
	 * No break, due to fall-through
	 */
    case FREEFARE_ENUMERATION_PHASE_EXT_CONTEXT:
	while(state->context_handle < ctx->reader_contexts_length) {
	    if(!ctx->reader_contexts[state->context_handle] || ctx->reader_contexts[state->context_handle]->internal) {
		state->context_handle++;
		continue;
	    }

	    if( ctx->reader_contexts[state->context_handle]->flags & FREEFARE_FLAG_READER_LIBNFC ) {
		_libnfc_enumerate_context(ctx, ctx->reader_contexts[state->context_handle], state, &result);
	    }

	    if(result) {
		return result;
	    }

	    state->context_handle++;
	}

	state->phase = FREEFARE_ENUMERATION_PHASE_INT;
	state->context_handle = 0;
	state->context_device_index = 0;
	/*
	 * No break, due to fall-through
	 */
    case FREEFARE_ENUMERATION_PHASE_INT:
	while(state->context_handle < ctx->reader_contexts_length) {
	    if(!ctx->reader_contexts[state->context_handle] || !ctx->reader_contexts[state->context_handle]->internal) {
		state->context_handle++;
		continue;
	    }

	    if( ctx->reader_contexts[state->context_handle]->flags & FREEFARE_FLAG_READER_LIBNFC ) {
		_libnfc_enumerate_context(ctx, ctx->reader_contexts[state->context_handle], state, &result);
	    }

	    if(result) {
		return result;
	    }

	    state->context_handle++;
	}

    }

    return result;
}

MifareTag _freefare_tag_first (FreefareContext ctx, struct freefare_enumeration_state *state, enum mifare_tag_type tag_type)
{
    if(!ctx || !state) {
	return NULL;
    }
    /*
     * If there's currently an enumeration ongoing, clean it up
     */
    if(state->libnfc.device) {
	nfc_close(state->libnfc.device);
	state->libnfc.device = NULL;
    }

    if(state->libnfc.connstrings) {
	free(state->libnfc.connstrings);
	state->libnfc.connstrings = NULL;
    }

    if(!state->single_device) {
	state->device_handle = -1;
    }
    state->context_handle = -1;
    state->context_device_index = -1;

    /*
     * Take note of which tag_type the caller requests, then
     * have _freefare_tag_next() handle the remainder of the operation
     */
    state->tag_type = tag_type;

    return _freefare_tag_next(ctx, state);
}

MifareTag freefare_tag_first (FreefareContext ctx, enum mifare_tag_type tag_type)
{
    if(!ctx) return NULL;
    return _freefare_tag_first(ctx, &(ctx->enumeration_state), tag_type);
}
MifareTag freefare_tag_next (FreefareContext ctx)
{
    if(!ctx) return NULL;
    return _freefare_tag_next(ctx, &(ctx->enumeration_state));
}

MifareTag *_freefare_tags_get (FreefareContext ctx, enum mifare_tag_type tag_type, struct freefare_enumeration_state *state)
{
    MifareTag *result = NULL;
    size_t result_length = 0;
    MifareTag tag = NULL;

    if( (tag = _freefare_tag_first(ctx, state, tag_type)) ) do {
	size_t slot = result_length;
	if(_embiggen_array((void**)&result, &result_length, sizeof(*result), slot+1) < 0) {
	    goto abort;
	} else {
	    result[slot] = tag;
	}
    } while( (tag = _freefare_tag_next(ctx, state)) );

    /*
     * Make sure that there's at least one trailing NULL in the array
     */
    if(_embiggen_array((void**)&result, &result_length, sizeof(*result), result_length+1) < 0) {
	goto abort;
    }

    return result;
abort:
    freefare_free_tags(result);
    return NULL;

}

MifareTag *freefare_tags_get (FreefareContext ctx, enum mifare_tag_type tag_type)
{
    /*
     * Use a tag_first/tag_next loop, but store state in a local variable
     * so that it's independent from the global enumeration state in ctx.
     */
    struct freefare_enumeration_state state;
    memset(&state, 0, sizeof(state));

    return _freefare_tags_get(ctx, tag_type, &state);
}

static void _reader_context_free(struct freefare_reader_context **conptr)
{
    if(!conptr || !*conptr) {
	return;
    }

    if((*conptr)->flags & FREEFARE_FLAG_READER_LIBNFC) {
	_libnfc_context_free(*conptr);
	*conptr = NULL;
    }
}

static void _reader_device_free(struct freefare_reader_device **devptr)
{
    if(!devptr || !*devptr) {
	return;
    }

    if((*devptr)->references > 1) {
	(*devptr)->references--;
	return;
    }

    (*devptr)->references--;
    if((*devptr)->flags & FREEFARE_FLAG_READER_LIBNFC) {
	_libnfc_device_free(*devptr);
	*devptr = NULL;
    }
}

void freefare_exit (FreefareContext ctx)
{
    if(!ctx) {
	ctx = implicit_context;
    }
    if(!ctx) {
	return;
    }

    for(size_t i=0; i<ctx->reader_contexts_length; i++) {
	_reader_context_free(ctx->reader_contexts + i);
    }

    for(size_t i=0; i<ctx->reader_devices_length; i++) {
	_reader_device_free(ctx->reader_devices + i);
    }

    if(ctx->reader_contexts) {
	free(ctx->reader_contexts);
    }

    if(ctx->reader_devices) {
	free(ctx->reader_devices);
    }

    memset(ctx, 0, sizeof(*ctx));
    free(ctx);

    if(ctx == implicit_context) {
	implicit_context = NULL;
    }
}

/*
 * Low-level API
 */

void *
memdup (const void *p, const size_t n)
{
    void *res;
    if ((res = malloc (n))) {
	memcpy (res, p, n);
    }
    return res;
}

/*
 * Link table to the reader driver specific functions
 */
const static struct supported_reader SUPPORTED_READERS[] = {
	{FREEFARE_FLAG_READER_LIBNFC, _libnfc_tag_free, _libnfc_get_tag_uid, _libnfc_strerror, _libnfc_connect, _libnfc_disconnect},
};

static const struct supported_reader *_reader_driver_lookup(FreefareFlags identifying_flag)
{
    for(size_t i=0; i<sizeof(SUPPORTED_READERS)/sizeof(SUPPORTED_READERS[0]); i++) {
	if( (SUPPORTED_READERS[i].identifying_flag & identifying_flag) == identifying_flag) {
	    return SUPPORTED_READERS + i;
	}
    }
    return NULL;
}
