/*_
 * Copyright (c) 2018 Hirochika Asai <asai@jar.jp>
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>

struct dumper {
    int snaplen;
    pcap_dumper_t *dumper;
};

/*
 * Usage
 */
void
usage(const char *prog)
{
    fprintf(stderr, "%s: <input> <output> <snaplen>\n", prog);
    exit(EXIT_FAILURE);
}

/*
 * Callback handler
 */
void
handler(u_char *dumper, const struct pcap_pkthdr *hdr, const u_char *data)
{
    struct pcap_pkthdr nhdr;
    struct dumper *dp;

    dp = (struct dumper *)dumper;

    memcpy(&nhdr, hdr, sizeof(struct pcap_pkthdr));
    if ( (int)nhdr.caplen > dp->snaplen ) {
        nhdr.caplen = dp->snaplen;
    }
    pcap_dump((u_char *)dp->dumper, &nhdr, data);
}

/*
 * Main routine
 */
int
main(int argc, const char *const argv[])
{
    const char *fname_in;
    const char *fname_out;
    int orig_snaplen;
    pcap_t *fin;
    pcap_t *fout;
    char errbuf[PCAP_ERRBUF_SIZE];
    FILE *fp;
    int ret;
    struct dumper dumper;

    if ( argc != 4 ) {
        usage(argv[0]);
    }

    fname_in = argv[1];
    fname_out = argv[2];
    dumper.snaplen = atoi(argv[3]);

    /* Open the input file */
    if ( 0 == strcmp("-", fname_in) ) {
        fin = pcap_fopen_offline_with_tstamp_precision(stdin,
                                                       PCAP_TSTAMP_PRECISION_NANO,
                                                       errbuf);
    } else {
        fin = pcap_open_offline_with_tstamp_precision(fname_in,
                                                      PCAP_TSTAMP_PRECISION_NANO,
                                                      errbuf);
    }
    if ( NULL == fin ) {
        fprintf(stderr, "%s\n", errbuf);
        return EXIT_FAILURE;
    }
    orig_snaplen = pcap_snapshot(fin);

    /* Open output file */
    fout = pcap_open_dead_with_tstamp_precision(pcap_datalink(fin),
                                                dumper.snaplen,
                                                PCAP_TSTAMP_PRECISION_NANO);
    if ( NULL == fout ) {
        fprintf(stderr, "Failed to open the output pcap handler.\n");
        return EXIT_FAILURE;
    }
    fp = fopen(fname_out, "r");
    if ( NULL != fp ) {
        fprintf(stderr, "%s already exists.\n", fname_out);
        fclose(fp);
        return EXIT_FAILURE;
    }
    dumper.dumper = pcap_dump_open(fout, fname_out);
    if ( NULL == fout ) {
        fprintf(stderr, "Failed to open the output pcap dumper.\n");
        return EXIT_FAILURE;
    }

    /* Execute truncation */
    fprintf(stderr, "Truncating %s with snaplen=%d to %s with snaplen=%d\n",
            fname_in, orig_snaplen, fname_out, dumper.snaplen);
    ret = pcap_loop(fin, -1, handler, (u_char *)&dumper);
    if ( 0 != ret ) {
        fprintf(stderr, "Failed truncation.\n");
        return EXIT_FAILURE;
    }

    /* Close */
    pcap_dump_close(dumper.dumper);

    return 0;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
