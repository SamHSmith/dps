
#include<stdlib.h>
#include<stdio.h>
#include <openssl/sha.h>
#include <zstd.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>

struct pkg_blob
{
    char** dest;
    u_int32_t dest_count;

    unsigned char blob_hash[SHA512_DIGEST_LENGTH];
    u_int64_t blob_start, blob_length, blob_final_length;
};

void binpkg_load(char* binpkg_path)
{
    FILE* pkgfile = fopen(binpkg_path, "r");
    char magic[15];
    fgets(magic, 15, pkgfile);
    assert(!strcmp(magic, "dps-binary-pkg"));

    u_int64_t fd_start = ftell(pkgfile);

    u_int64_t fd_len;
    fread(&fd_len, 8, 1, pkgfile);

    struct pkg_blob* pkg_blobs = malloc(sizeof(struct pkg_blob));
    u_int32_t blobcount = 0;

    while(ftell(pkgfile) < fd_start + fd_len)
    {
        pkg_blobs = realloc(pkg_blobs, (blobcount + 1) * sizeof(struct pkg_blob));

        fread(&pkg_blobs[blobcount].blob_hash, SHA512_DIGEST_LENGTH, 1, pkgfile);
        fread(&pkg_blobs[blobcount].blob_start, 8, 1, pkgfile);
        fread(&pkg_blobs[blobcount].blob_length, 8, 1, pkgfile);
        fread(&pkg_blobs[blobcount].blob_final_length, 8, 1, pkgfile);
        fread(&pkg_blobs[blobcount].dest_count, 4, 1, pkgfile);

        char* destbuf = malloc(1);
        u_int32_t destlen = 0;
        pkg_blobs[blobcount].dest = malloc(pkg_blobs[blobcount].dest_count * sizeof(char*));
        for(u_int32_t j = 0; j < pkg_blobs[blobcount].dest_count; )
        {
            char c = fgetc(pkgfile);
            destlen += 1;
            destbuf = realloc(destbuf, destlen);
            if(c == ':') {
                destbuf[destlen - 1] = 0;
                char* d = malloc(destlen);
                strcpy(d, destbuf);
                pkg_blobs[blobcount].dest[j] = d;
                j++;
                destlen = 0;
            }
            else { destbuf[destlen - 1] = c; }
        }
        free(destbuf);
        blobcount += 1;
    }
    printf("done\n");
}

int main(int argc, char* argv[])
{
    printf("this is dps\n");
    binpkg_load("dps-build/test/pkg.dpsbp");
}
