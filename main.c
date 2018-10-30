#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "AES128.h"
const char core_key[] = "hzHRAmso5kInbaxW";
const char meta_key[] = "#14ljk_!\\]&0U<'(";
int base64_decode(const char *base64, unsigned char *bindata)
{
    const char base64char[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, j, k, m;
    unsigned char temp[4];
    for ( i = j = 0; base64[i]; i += 4 )
    {
        memset( temp, 0xFF, sizeof(temp));
        for(m=0; m<4; m++) for ( k = 0 ; k < 64 ; k ++ )if( base64char[k] == base64[i+m])
                {
                    temp[m]= k;
                }
        bindata[j++] = ((temp[0] << 2)&0xFC) | ((temp[1]>>4)&0x03);
        if ( base64[i+2] == '=' )
        {
            break;
        }
        bindata[j++] = ((temp[1] << 4)&0xF0) | ((temp[2]>>2)&0x0F);
        if ( base64[i+3] == '=' )
        {
            break;
        }
        bindata[j++] = (((temp[2] << 6)&0xF0)) | (temp[3]&0x3F);
    }
    return j;
}
unsigned char key_box[256], key_serial;
void set_key_stream_generator(unsigned char* init_key, int key_length)
{
    int i;
    unsigned char c, temp;
    for(i=0; i<256; i++)
    {
        key_box[i]=i;
    }
    c=0;
    for(i=0; i<256; i++)
    {
        c += key_box[i] + init_key[i%key_length];
        temp=key_box[c];
        key_box[c]=key_box[i];
        key_box[i]=temp;
    }
    key_serial=0;
}
unsigned char get_next_key()
{
    unsigned char j;
    key_serial++;
    j = key_box[key_serial] + key_serial;
    j = key_box[key_serial] + key_box[j];
    return key_box[j];
}
void dump(char *file_in)
{
    FILE* f, *g;
    char header[10];
    char *file_out;
    int i, j, n;
    cJSON *root, *obj;
    unsigned char *buffer, *meta, *meta_data, *fmt;
    unsigned int key_length, meta_length, image_size;
    printf("in: %s\n", file_in);
    f = fopen(file_in, "rb");
    fread(header, 1, 10, f);
    if(strncasecmp(header, "CTENFDAM", 8))
    {
        printf("wrong file format\n");
        return;
    }
    //get key of stream cipher
    fread(&key_length, 4, 1, f);
    buffer=malloc(key_length);
    fread(buffer, 1, key_length, f);
    for(i=0; i<key_length; i++)
    {
        buffer[i]^=0x64;
    }
    KeyExpansion(core_key);
    for(i=0; i<key_length; i+=16)
    {
        InvCipher(&buffer[i], &buffer[i]);
    }
    set_key_stream_generator(&buffer[17], key_length-17-buffer[key_length-1]);
    free(buffer);
    //get meta (base64 encoded)
    fread(&meta_length, 4, 1, f);
    buffer=malloc(meta_length+1);
    fread(buffer, 1, meta_length, f);
    for(i=0; i<meta_length; i++)
    {
        buffer[i]^=0x63;
    }
    buffer[i]=0;
    //base64 decode
    meta=strchr((char *)buffer, ':')+1;
    meta_length=strlen(meta)/4*3;
    meta_data=malloc(meta_length);
    meta_length=base64_decode(meta, meta_data);
    if(meta_length%16)
    {
        printf("[warning]");
    }
    KeyExpansion(meta_key);
    for(i=0; i<meta_length; i+=16)
    {
        InvCipher(&meta_data[i], &meta_data[i]);
    }
    meta_data[meta_length-meta_data[meta_length-1]]=0;//unpad
    root=cJSON_Parse(strchr((char *)meta_data, '{'));
    fmt=cJSON_GetObjectItemCaseSensitive(root, "format")->valuestring;
    obj=cJSON_GetObjectItemCaseSensitive(root, "musicName");
    if(cJSON_IsString(obj))
    {
        printf("name: %s\n", obj->valuestring);
    }
    obj=cJSON_GetObjectItemCaseSensitive(root, "album");
    if(cJSON_IsString(obj))
    {
        printf("album: %s\n", obj->valuestring);
    }
    obj=cJSON_GetObjectItemCaseSensitive(root, "bitrate");
    if(cJSON_IsNumber(obj))
    {
        printf("bitrate: %dK\n", obj->valueint/1000);
    }
    printf("format: %s\n", fmt);
    file_out=malloc(strlen(file_in)-3+strlen(fmt));
    strcpy(file_out, file_in);
    strcpy(strrchr(file_out, '.')+1, fmt);
    cJSON_Delete(root);
    free(buffer);
    free(meta_data);
    printf("out: %s\n", file_out);
    g = fopen(file_out, "wb");
    if(!g)
    {
        printf("output file warning\n");
    }
    fseek(f, 9, SEEK_CUR);
    fread(&image_size, 4, 1, f);
    fseek(f, image_size, SEEK_CUR);
    buffer=malloc(0x40000);
    j=0;
    do
    {
        n=fread(buffer, 1, 0x40000, f);
        printf("%d,%d\n", n, j);
        j+=n;
        if(!n)
        {
            break;
        }
        for(i=0; i<n; i++)
        {
            buffer[i]^=get_next_key();
        }
        fwrite(buffer, 1, n, g);
    }
    while(!feof(f));
    fclose(f);
    fclose(g);
    free(file_out);
    free(buffer);
}
int main(int argc, char **argv)
{
    if(argc!=2)
    {
        printf("usage: ncmdump <.ncm filepath>\n");
    }
    else
    {
        dump(argv[1]);
    }
    return 0;
}
