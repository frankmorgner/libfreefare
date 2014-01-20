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

#include <freefare.h>

#include "freefare_internal.h"

#define MAX_CANDIDATES 16

#define NXP_MANUFACTURER_CODE 0x04

struct supported_tag supported_tags[] = {
    { CLASSIC_1K,   "Mifare Classic 1k",            0x08, 0, 0, { 0x00 }, NULL },
    { CLASSIC_1K,   "Mifare Classic 1k (Emulated)", 0x28, 0, 0, { 0x00 }, NULL },
    { CLASSIC_1K,   "Mifare Classic 1k (Emulated)", 0x68, 0, 0, { 0x00 }, NULL },
    { CLASSIC_1K,   "Infineon Mifare Classic 1k",   0x88, 0, 0, { 0x00 }, NULL },
    { CLASSIC_4K,   "Mifare Classic 4k",            0x18, 0, 0, { 0x00 }, NULL },
    { CLASSIC_4K,   "Mifare Classic 4k (Emulated)", 0x38, 0, 0, { 0x00 }, NULL },
    { DESFIRE,      "Mifare DESFire",               0x20, 5, 4, { 0x75, 0x77, 0x81, 0x02 /*, 0xXX */ }, NULL},
    { ULTRALIGHT_C, "Mifare UltraLightC",           0x00, 0, 0, { 0x00 }, is_mifare_ultralightc_on_reader },
    { ULTRALIGHT,   "Mifare UltraLight",            0x00, 0, 0, { 0x00 }, NULL },
};

#define FREEFARE_FLAG_MASK_READER_ALL (FREEFARE_FLAG_READER_LIBNFC)
#define FREEFARE_FLAG_MASK_GLOBAL_INHERIT (FREEFARE_FLAG_DISABLE_ISO14443_4)

#define DEFAULT_READER_LIST_LENGTH 16

/*
 * Automagically allocate a MifareTag given a device and target info.
 */
MifareTag
freefare_tag_new (nfc_device *device, nfc_iso14443a_info nai)
{
    bool found = false;
    struct supported_tag *tag_info;
    MifareTag tag;

    /* Ensure the target is supported */
    for (size_t i = 0; i < sizeof (supported_tags) / sizeof (struct supported_tag); i++) {
	if (((nai.szUidLen == 4) || (nai.abtUid[0] == NXP_MANUFACTURER_CODE)) &&
	    (nai.btSak == supported_tags[i].SAK) &&
	    (!supported_tags[i].ATS_min_length || ((nai.szAtsLen >= supported_tags[i].ATS_min_length) &&
						   (0 == memcmp (nai.abtAts, supported_tags[i].ATS, supported_tags[i].ATS_compare_length)))) &&
	    ((supported_tags[i].check_tag_on_reader == NULL) ||
	     supported_tags[i].check_tag_on_reader(device, nai))) {

	    tag_info = &(supported_tags[i]);
	    found = true;
	    break;
	}
    }

    if (!found)
	return NULL;

    /* Allocate memory for the found MIFARE target */
    switch (tag_info->type) {
    case CLASSIC_1K:
    case CLASSIC_4K:
	tag = mifare_classic_tag_new ();
	break;
    case DESFIRE:
	tag = mifare_desfire_tag_new ();
	break;
    case ULTRALIGHT:
    case ULTRALIGHT_C:
	tag = mifare_ultralight_tag_new ();
	break;
    }

    if (!tag)
	return NULL;

    /*
     * Initialize common fields
     * (Target specific fields are initialized in mifare_*_tag_new())
     */
    tag->device = device;
    tag->info = nai;
    tag->active = 0;
    tag->tag_info = tag_info;

    return tag;
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
    MifareTag *tags = NULL;
    int tag_count = 0;

    nfc_initiator_init(device);

    // Drop the field for a while
    nfc_device_set_property_bool(device,NP_ACTIVATE_FIELD,false);

    // Configure the CRC and Parity settings
    nfc_device_set_property_bool(device,NP_HANDLE_CRC,true);
    nfc_device_set_property_bool(device,NP_HANDLE_PARITY,true);
    nfc_device_set_property_bool(device,NP_AUTO_ISO14443_4,true);

    // Enable field so more power consuming cards can power themselves up
    nfc_device_set_property_bool(device,NP_ACTIVATE_FIELD,true);

    // Poll for a ISO14443A (MIFARE) tag
    nfc_target candidates[MAX_CANDIDATES];
    int candidates_count;
    nfc_modulation modulation = {
	.nmt = NMT_ISO14443A,
	.nbr = NBR_106
    };
    if ((candidates_count = nfc_initiator_list_passive_targets(device, modulation, candidates, MAX_CANDIDATES)) < 0)
	return NULL;

    tags = malloc(sizeof (void *));
    if(!tags) return NULL;
    tags[0] = NULL;

    for (int c = 0; c < candidates_count; c++) {
	MifareTag t;
	if ((t = freefare_tag_new(device, candidates[c].nti.nai))) {
	    /* (Re)Allocate memory for the found MIFARE targets array */
	    MifareTag *p = realloc (tags, (tag_count + 2) * sizeof (MifareTag));
	    if (p)
		tags = p;
	    else
		return tags; // FAIL! Return what has been found so far.
	    tags[tag_count++] = t;
	    tags[tag_count] = NULL;
	}
    }

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
    char *res = malloc (2 * tag->info.szUidLen + 1);
    for (size_t i =0; i < tag->info.szUidLen; i++)
        snprintf (res + 2*i, 3, "%02x", tag->info.abtUid[i]);
    return res;
}

/*
 * Free the provided tag.
 */
void
freefare_free_tag (MifareTag tag)
{
    if (tag) {
        switch (tag->tag_info->type) {
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
freefare_strerror (MifareTag tag)
{
    const char *p = "Unknown error";
    if (nfc_device_get_last_error (tag->device) < 0) {
      p = nfc_strerror (tag->device);
    } else {
      if (tag->tag_info->type == DESFIRE) {
        if (MIFARE_DESFIRE (tag)->last_pcd_error) {
          p = mifare_desfire_error_lookup (MIFARE_DESFIRE (tag)->last_pcd_error);
        } else if (MIFARE_DESFIRE (tag)->last_picc_error) {
          p = mifare_desfire_error_lookup (MIFARE_DESFIRE (tag)->last_picc_error);
        }
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

static void _libnfc_context_close(struct freefare_reader_context *context)
{
    if(!context) {
	return;
    }
    nfc_exit(context->context.libnfc);
    free(context);
}

static void _libnfc_device_close(struct freefare_reader_device *device)
{
    if(!device) {
	return;
    }
    nfc_close(device->device.libnfc);
    free(device);
}

static int _embiggen_array(void ***array, size_t *array_length, size_t element_size, size_t min_elements)
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

    memcpy(new_array, *array, element_size * min_elements);
    *array = new_array;
    *array_length = min_elements;
    return 0;
}

static int _reader_context_store(struct freefare_context *ctx, struct freefare_reader_context *reader_context)
{
    if(!ctx) {
	return -1;
    }

    /*
     * Ensure the array is allocated
     */
    if(_embiggen_array((void***)&ctx->reader_contexts, &ctx->reader_contexts_length, sizeof(ctx->reader_contexts[0]), DEFAULT_READER_LIST_LENGTH) < 0) {
	return -1;
    }

    /*
     * Search through the array for the first free slot and use it
     */
    for(size_t i=0; i<ctx->reader_contexts_length; i++) {
	if(ctx->reader_contexts[i] == NULL) {
	    ctx->reader_contexts[i] = reader_context;
	    return i;
	}
    }

    /*
     * No slot found, enlarge the array and use the next one
     */
    int slot = ctx->reader_contexts_length;
    if(_embiggen_array((void***)&ctx->reader_contexts, &ctx->reader_contexts_length, sizeof(ctx->reader_contexts[0]), slot+1) < 0) {
	return -1;
    } else {
	ctx->reader_contexts[slot] = reader_context;
	return slot;
    }

    return -1;
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
	    _libnfc_context_close(libnfc_context);
	    goto abort;
	}
    }

    return result;
abort:
    freefare_exit(result);
    return NULL;
}

void freefare_exit (FreefareContext ctx)
{
    if(!ctx) {
	return;
    }

    for(size_t i=0; i<ctx->reader_contexts_length; i++) {
	if(ctx->reader_contexts[i] && (ctx->reader_contexts[i]->flags & FREEFARE_FLAG_AUTOCLOSE)) {
	    if(ctx->reader_contexts[i]->flags & FREEFARE_FLAG_READER_LIBNFC) {
		_libnfc_context_close(ctx->reader_contexts[i]);
		ctx->reader_contexts[i] = NULL;
	    }
	}
    }

    for(size_t i=0; i<ctx->reader_devices_length; i++) {
	if(ctx->reader_devices[i] && (ctx->reader_devices[i]->flags & FREEFARE_FLAG_AUTOCLOSE)) {
	    if(ctx->reader_devices[i]->flags & FREEFARE_FLAG_READER_LIBNFC) {
		_libnfc_device_close(ctx->reader_devices[i]);
		ctx->reader_devices[i] = NULL;
	    }
	}
    }

    if(ctx->reader_contexts) {
	free(ctx->reader_contexts);
    }

    if(ctx->reader_devices) {
	free(ctx->reader_devices);
    }

    memset(ctx, 0, sizeof(*ctx));
    free(ctx);
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
