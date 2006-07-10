/*
 * libwbxml, the WBXML Library.
 * Copyright (C) 2002-2005 Aymerick Jehanne <aymerick@jehanne.org>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * 
 * LGPL v2.1: http://www.gnu.org/copyleft/lesser.txt
 * 
 * Contact: libwbxml@aymerick.com
 * Home: http://libwbxml.aymerick.com
 */

/**
 * @file wbxml2xml_tool.c
 * @ingroup wbxml2xml_tool
 *
 * @author Aymerick J�hanne <libwbxml@aymerick.com>
 * @date 03/02/22
 *
 * @brief WBXML to XML Converter Tool
 *
 */

#if !defined ( __SYMBIAN32__ )
#include <memory.h>
#endif /* ! __SYMBIAN32__ */

#include "wbxml.h" /* libwbxml2 */
#include "getopt.h"

/*
 * This sytem include is here instead of the *.c files because
 * we want it to be included AFTER 'e32def.h' (in 'wbxml.h') on Symbian.
 * If not so, Warnings are displayed ('NULL' : macro redefinition)
 */
#include <stdio.h>


#define INPUT_BUFFER_SIZE 1000


static WBXMLLanguage get_lang(const WB_TINY *lang)
{
#if defined( WBXML_SUPPORT_WML )
    if (WBXML_STRCMP(lang, "WML10") == 0)
        return WBXML_LANG_WML10;
    if (WBXML_STRCMP(lang, "WML11") == 0)
        return WBXML_LANG_WML11;
    if (WBXML_STRCMP(lang, "WML12") == 0)
        return WBXML_LANG_WML12;
    if (WBXML_STRCMP(lang, "WML13") == 0)
        return WBXML_LANG_WML13;
#endif /* WBXML_SUPPORT_WML */

#if defined( WBXML_SUPPORT_WTA )
    if (WBXML_STRCMP(lang, "WTA10") == 0)
        return WBXML_LANG_WTA10;
    if (WBXML_STRCMP(lang, "WTAWML12") == 0)
        return WBXML_LANG_WTAWML12;
    if (WBXML_STRCMP(lang, "CHANNEL11") == 0)
        return WBXML_LANG_CHANNEL11;
    if (WBXML_STRCMP(lang, "CHANNEL12") == 0)
        return WBXML_LANG_CHANNEL12;
#endif /* WBXML_SUPPORT_WTA */

#if defined( WBXML_SUPPORT_SI )
    if (WBXML_STRCMP(lang, "SI10") == 0)
        return WBXML_LANG_SI10;
#endif /* WBXML_SUPPORT_SI */

#if defined( WBXML_SUPPORT_SL )
    if (WBXML_STRCMP(lang, "SL10") == 0)
        return WBXML_LANG_SL10;
#endif /* WBXML_SUPPORT_SL */

#if defined( WBXML_SUPPORT_CO )
    if (WBXML_STRCMP(lang, "CO10") == 0)
        return WBXML_LANG_CO10;
#endif /* WBXML_SUPPORT_CO */

#if defined( WBXML_SUPPORT_PROV )
    if (WBXML_STRCMP(lang, "PROV10") == 0)
        return WBXML_LANG_PROV10;
#endif /* WBXML_SUPPORT_PROV */

#if defined( WBXML_SUPPORT_EMN )
    if (WBXML_STRCMP(lang, "EMN10") == 0)
        return WBXML_LANG_EMN10;
#endif /* WBXML_SUPPORT_EMN */

#if defined( WBXML_SUPPORT_DRMREL )
    if (WBXML_STRCMP(lang, "DRMREL10") == 0)
        return WBXML_LANG_DRMREL10;
#endif /* WBXML_SUPPORT_DRMREL */

#if defined( WBXML_SUPPORT_OTA_SETTINGS )
    if (WBXML_STRCMP(lang, "OTA") == 0)
        return WBXML_LANG_OTA_SETTINGS;
#endif /* WBXML_SUPPORT_OTA_SETTINGS */

#if defined( WBXML_SUPPORT_SYNCML )
    if (WBXML_STRCMP(lang, "SYNCML10") == 0)
        return WBXML_LANG_SYNCML_SYNCML10;
    if (WBXML_STRCMP(lang, "DEVINF10") == 0)
        return WBXML_LANG_SYNCML_DEVINF10;
    if (WBXML_STRCMP(lang, "SYNCML11") == 0)
        return WBXML_LANG_SYNCML_SYNCML11;
    if (WBXML_STRCMP(lang, "DEVINF11") == 0)
        return WBXML_LANG_SYNCML_DEVINF11;
    if (WBXML_STRCMP(lang, "METINF11") == 0)
        return WBXML_LANG_SYNCML_METINF11;
    if (WBXML_STRCMP(lang, "SYNCML12") == 0)
        return WBXML_LANG_SYNCML_SYNCML12;
    if (WBXML_STRCMP(lang, "DEVINF12") == 0)
        return WBXML_LANG_SYNCML_DEVINF12;
    if (WBXML_STRCMP(lang, "METINF12") == 0)
        return WBXML_LANG_SYNCML_METINF12;
#endif /* WBXML_SUPPORT_SYNCML */

#if defined( WBXML_SUPPORT_WV )
    if (WBXML_STRCMP(lang, "CSP11") == 0)
        return WBXML_LANG_WV_CSP11;
    if (WBXML_STRCMP(lang, "CSP12") == 0)
        return WBXML_LANG_WV_CSP12;
#endif /* WBXML_SUPPORT_WV */

    return WBXML_LANG_UNKNOWN;
}


static void help(void)
{
    fprintf(stderr, "wbxml2xml [libwbxml %s] by Aymerick Jehanne <aymerick@jehanne.org>\n", WBXML_LIB_VERSION);
    fprintf(stderr, "If you use this tool, please send feedbacks to libwbxml@aymerick.com\n");
    fprintf(stderr, "http://libwbxml.aymerick.com/\n");
#if defined( HAVE_EXPAT )
    fprintf(stderr, "This tool is linked with Expat (http://expat.sourceforge.net)\n\n");
#endif /* HAVE_EXPAT */
    fprintf(stderr, "Usage: \n");
    fprintf(stderr, "  wbxml2xml -o output.xml input.wbxml\n");
    fprintf(stderr, "  wbxml2xml -i 4 -l CSP12 -o output.xml input.wbxml\n\n");
    fprintf(stderr, "Options: \n");
    fprintf(stderr, "    -o output.xml : output file\n");
    fprintf(stderr, "    -m X (Generation mode - Default: 1) with:\n");
    fprintf(stderr, "       0: Compact Generation\n");
    fprintf(stderr, "       1: Indent Generation\n");
    fprintf(stderr, "       2: Canonical Generation\n");
    fprintf(stderr, "    -i X (Indent delta when using mode '1' - Default: 1)\n");
    fprintf(stderr, "    -k (Keep Ignorable Whitespaces - Default: FALSE)\n");
    fprintf(stderr, "    -l X (Force Language Type of document to parse)\n");
#if defined( WBXML_SUPPORT_WML )
    fprintf(stderr, "       WML10 : WML 1.0\n");
    fprintf(stderr, "       WML11 : WML 1.1\n");
    fprintf(stderr, "       WML12 : WML 1.2\n");
    fprintf(stderr, "       WML13 : WML 1.3\n");
#endif /* WBXML_SUPPORT_WML */
#if defined( WBXML_SUPPORT_WTA )
    fprintf(stderr, "       WTA10 : WTA 1.0\n");
    fprintf(stderr, "       WTAWML12 : WTAWML 1.2\n");
    fprintf(stderr, "       CHANNEL11 : CHANNEL 1.1\n");
    fprintf(stderr, "       CHANNEL12 : CHANNEL 1.2\n");
#endif /* WBXML_SUPPORT_WTA */
#if defined( WBXML_SUPPORT_SI )
    fprintf(stderr, "       SI10 : SI 1.0\n");
#endif /* WBXML_SUPPORT_SI */
#if defined( WBXML_SUPPORT_SL )
    fprintf(stderr, "       SL10 : SL 1.0\n");
#endif /* WBXML_SUPPORT_SL */
#if defined( WBXML_SUPPORT_CO )
    fprintf(stderr, "       CO10 : CO 1.0\n");
#endif /* WBXML_SUPPORT_CO */
#if defined( WBXML_SUPPORT_PROV )
    fprintf(stderr, "       PROV10 : PROV 1.0\n");
#endif /* WBXML_SUPPORT_PROV */
#if defined( WBXML_SUPPORT_EMN )
    fprintf(stderr, "       EMN10 : EMN 1.0\n");
#endif /* WBXML_SUPPORT_EMN */
#if defined( WBXML_SUPPORT_DRMREL )
    fprintf(stderr, "       DRMREL10 : DRMREL 1.0\n");
#endif /* WBXML_SUPPORT_DRMREL */
#if defined( WBXML_SUPPORT_OTA_SETTINGS )
    fprintf(stderr, "       OTA : OTA Settings\n");
#endif /* WBXML_SUPPORT_OTA_SETTINGS */
#if defined( WBXML_SUPPORT_SYNCML )
    fprintf(stderr, "       SYNCML10 : SYNCML 1.0\n");
    fprintf(stderr, "       DEVINF10 : DEVINF 1.0\n");
    fprintf(stderr, "       SYNCML11 : SYNCML 1.1\n");
    fprintf(stderr, "       DEVINF11 : DEVINF 1.1\n");
    fprintf(stderr, "       METINF11 : METINF 1.1\n");
    fprintf(stderr, "       SYNCML12 : SYNCML 1.2\n");
    fprintf(stderr, "       DEVINF12 : DEVINF 1.2\n");
    fprintf(stderr, "       METINF12 : METINF 1.2\n");
#endif /* WBXML_SUPPORT_SYNCML */
#if defined( WBXML_SUPPORT_WV )
    fprintf(stderr, "       CSP11 : WV CSP 1.1\n");
    fprintf(stderr, "       CSP12 : WV CSP 1.2\n");
#endif /* WBXML_SUPPORT_WV */
    fprintf(stderr, "\nNote: '-' can be used to mean stdin on input or stdout on output\n\n");
}


WB_LONG main(WB_LONG argc, WB_TINY **argv)
{
    WB_UTINY *wbxml = NULL, *output = NULL, *xml = NULL;
    FILE *input_file = NULL, *output_file = NULL;
    WB_LONG count = 0, wbxml_len = 0, total = 0;
    WB_ULONG xml_len = 0;
    WB_TINY opt;
    WBXMLError ret = WBXML_OK;
    WB_UTINY input_buffer[INPUT_BUFFER_SIZE + 1];
    WBXMLGenXMLParams params;

    /* Init Default Parameters */
    params.lang = WBXML_LANG_UNKNOWN;
    params.gen_type = WBXML_GEN_XML_INDENT;
    params.indent = 1;
    params.keep_ignorable_ws = FALSE;

    while ((opt = (WB_TINY) getopt(argc, argv, "kh?o:m:i:l:")) != EOF)
    {
        switch (opt) {
        case 'k':
            params.keep_ignorable_ws = TRUE;
            break;
        case 'i':
            params.indent = (WB_UTINY) atoi((const WB_TINY*)optarg);
            break;
        case 'l':
            params.lang = get_lang((const WB_TINY*)optarg);
            break;
        case 'm':
            switch (atoi((const WB_TINY*)optarg)) {
            case 0:
                params.gen_type = WBXML_GEN_XML_COMPACT;
                break;
            case 1:
                params.gen_type = WBXML_GEN_XML_INDENT;
                break;
            case 2:
                params.gen_type = WBXML_GEN_XML_CANONICAL;
                break;
            default:
                params.gen_type = WBXML_GEN_XML_INDENT;
            }
            break;
        case 'o':
            output = (WB_UTINY*) optarg;
            break;
        case 'h':
        case '?':
        default:
            help();
            return 0;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Missing arguments\n");
        help();
        return 0;
    }

#ifdef WBXML_USE_LEAKTRACKER
    lt_init_mem();
    lt_log_open_file("wbxml2xml.log");
    lt_log(0, "\n***************************\n Converting file: %s", argv[optind]);
#endif

    /**********************************
     *  Read the WBXML Document
     */

    if (WBXML_STRCMP(argv[optind], "-") == 0) {
        input_file = stdin;
    } else {
        /* Open WBXML document */
        input_file = fopen(argv[optind], "rb");
        if (input_file == NULL) {
            fprintf(stderr, "Failed to open %s\n", argv[optind]);
            goto clean_up;
        }
    }

    /* Read WBXML document */
    while(!feof(input_file))    {
        count = fread(input_buffer, sizeof(WB_UTINY), INPUT_BUFFER_SIZE, input_file);
        if (ferror(input_file))      {
            fprintf(stderr, "Error while reading from file %s\n", argv[optind]);
            if (input_file != stdin)
                fclose(input_file);
            if (wbxml != NULL)
                wbxml_free(wbxml);
            goto clean_up;
        }

        total += count;
        wbxml = wbxml_realloc(wbxml, total);
        if (wbxml == NULL) {
            fprintf(stderr, "Not enought memory\n");
            if (input_file != stdin)
                fclose(input_file);
            if (wbxml != NULL)
                wbxml_free(wbxml);
            goto clean_up;
        }

        memcpy(wbxml + wbxml_len, input_buffer, count);
        wbxml_len += count;
    }

    if (input_file != stdin)
        fclose(input_file);

    /* Convert WBXML document */
    ret = wbxml_conv_wbxml2xml_withlen(wbxml, wbxml_len, &xml, &xml_len, &params);
    if (ret != WBXML_OK) {
        fprintf(stderr, "wbxml2xml failed: %s\n", wbxml_errors_string(ret));
    }
    else {
        /* fprintf(stderr, "wbxml2xml succeded: \n%s\n", xml); */
        fprintf(stderr, "wbxml2xml succeded\n");

        if (output != NULL) {
            if (WBXML_STRCMP(output, "-") == 0) {
                output_file = stdout;
            } else {
                /* Open Output File */
                output_file = fopen((const WB_TINY*) output, "w");
            }

            if (output_file == NULL) {
                fprintf(stderr, "Failed to open output file: %s\n", output);
            }

            /* Write to Output File */
            if (fwrite(xml, sizeof(WB_UTINY), xml_len, output_file) < xml_len)
                fprintf(stderr, "Error while writing to file: %s\n", output);
            /*
            else
                fprintf(stderr, "Written %u bytes to file: %s\n", xml_len, output);
            */

            if (output_file != stdout)
                fclose(output_file);
        }

        /* Clean-up */
        wbxml_free(xml);
    }

    wbxml_free(wbxml);

clean_up:

#ifdef WBXML_USE_LEAKTRACKER
    lt_check_leaks();
    lt_shutdown_mem();
    lt_log_close_file();
#endif

    return 0;
}
