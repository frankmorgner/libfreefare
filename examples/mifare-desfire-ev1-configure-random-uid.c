/*-
 * Copyright (C) 2010, Romain Tartiere.
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

#include "config.h"

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nfc/nfc.h>

#include <freefare.h>

uint8_t key_data_picc[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

struct {
    bool interactive;
} configure_options = {
    .interactive = true
};

static void
usage(char *progname)
{
    fprintf (stderr, "usage: %s [-y] [-K 11223344AABBCCDD]\n", progname);
    fprintf (stderr, "\nOptions:\n");
    fprintf (stderr, "  -y     Do not ask for confirmation (dangerous)\n");
    fprintf (stderr, "  -K     Provide another PICC key than the default one\n");
}

int
main(int argc, char *argv[])
{
    int ch;
    int error = EXIT_SUCCESS;
    MifareTag *tags = NULL;

    while ((ch = getopt (argc, argv, "hyK:")) != -1) {
	switch (ch) {
	case 'h':
	    usage(argv[0]);
	    exit (EXIT_SUCCESS);
	    break;
	case 'y':
	    configure_options.interactive = false;
	    break;
	case 'K':
	    if (strlen(optarg) != 16) {
		usage(argv[0]);
		exit (EXIT_FAILURE);
	    }
	    uint64_t n = strtoull(optarg, NULL, 16);
	    int i;
	    for (i=7; i>=0; i--) {
		key_data_picc[i] = (uint8_t) n;
		n >>= 8;
	    }
	    break;
	default:
	    usage(argv[0]);
	    exit (EXIT_FAILURE);
	}
    }
    // Remaining args, if any, are in argv[optind .. (argc-1)]

    FreefareContext ctx = freefare_init(FREEFARE_FLAG_READER_ALL);
    if (ctx == NULL)
	errx(EXIT_FAILURE, "Unable to init libfreefare");

    tags = freefare_tags_get (ctx, DESFIRE);
    if (!tags) {
	freefare_exit(ctx);
	errx (EXIT_FAILURE, "Error listing Mifare DESFire tags.");
    }

    for (int i = 0; (!error) && tags[i]; i++) {
	if (DESFIRE != freefare_get_tag_type (tags[i]))
	    continue;

	char *tag_uid = freefare_get_tag_uid (tags[i]);
	char buffer[BUFSIZ];

	int res;

	res = mifare_desfire_connect (tags[i]);
	if (res < 0) {
	    warnx ("Can't connect to Mifare DESFire target.");
	    error = EXIT_FAILURE;
	    break;
	}

	// Make sure we've at least an EV1 version
	struct mifare_desfire_version_info info;
	res = mifare_desfire_get_version (tags[i], &info);
	if (res < 0) {
	    freefare_perror (tags[i], "mifare_desfire_get_version");
	    error = 1;
	    break;
	}
	if (info.software.version_major < 1) {
	    warnx ("Found old DESFire, skipping");
	    continue;
	}

	printf ("Found %s with UID %s. ", freefare_get_tag_friendly_name (tags[i]), tag_uid);
	bool do_it = true;

	size_t tag_uid_len = strlen (tag_uid) / 2;
	switch (tag_uid_len) {
	case 7: // Regular UID
	    if (configure_options.interactive) {
		printf ("Configure random UID (this cannot be undone) [yN] ");
		fgets (buffer, BUFSIZ, stdin);
		do_it = ((buffer[0] == 'y') || (buffer[0] == 'Y'));
	    } else {
		printf ("\n");
	    }

	    if (do_it) {

		MifareDESFireKey key_picc = mifare_desfire_des_key_new_with_version (key_data_picc);
		res = mifare_desfire_authenticate (tags[i], 0, key_picc);
		if (res < 0) {
		    freefare_perror (tags[i], "mifare_desfire_authenticate");
		    error = EXIT_FAILURE;
		    break;
		}
		mifare_desfire_key_free (key_picc);

		res = mifare_desfire_set_configuration (tags[i], false, true);
		if (res < 0) {
		    freefare_perror (tags[i], "mifare_desfire_set_configuration");
		    error = EXIT_FAILURE;
		    break;
		}
	    }
	    break;
	case 4: // Random UID
	{} // Compilation fails if label is directly followed by the declaration rather than a statement
	MifareDESFireKey key_picc = mifare_desfire_des_key_new_with_version (key_data_picc);
	res = mifare_desfire_authenticate (tags[i], 0, key_picc);
	if (res < 0) {
	    freefare_perror (tags[i], "mifare_desfire_authenticate");
	    error = EXIT_FAILURE;
	    break;
	}
	mifare_desfire_key_free (key_picc);

	char *old_tag_uid;
	res = mifare_desfire_get_card_uid (tags[i], &old_tag_uid);
	if (res < 0) {
	    freefare_perror (tags[i], "mifare_desfire_get_card_uid");
	    error = EXIT_FAILURE;
	    break;
	}

	printf ("Old card UID: %s\n", old_tag_uid);
	free (old_tag_uid);

	break;
	default: // Should not happen
	    warnx ("Unsupported UID length %d.", (int) tag_uid_len);
	    error = EXIT_FAILURE;
	    break;
	}

	mifare_desfire_disconnect (tags[i]);
	free (tag_uid);
    }

    freefare_free_tags (tags);
    freefare_exit(ctx);
    exit (error);
} /* main() */

