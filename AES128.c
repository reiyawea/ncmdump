#include "AES_Sbox.h"
#include "AES128.h"
unsigned char EXP_KEYS [176];
static unsigned char State[4][4];
static unsigned char CurrentKey[4][4];
typedef struct word
{
    unsigned char b0;
    unsigned char b1;
    unsigned char b2;
    unsigned char b3;
} word;
static void InvSubBytes    (void);
static void InvShiftRows   (void);
static void InvMixColumns  (void);
static void AddRoundKey    (void);
static void StateIn     (unsigned char *in);
static void StateOut    (unsigned char *out);
static void LoadKeys    (char i);
static unsigned char FFMultiply (unsigned char x, unsigned char y);
void KeyExpansion (const unsigned char* CIPHER_KEY)
{
    unsigned char i;
    unsigned char tempbyte;
    word tempword;
    const unsigned char Rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
    word w[4*(10+1)];
    for (i = 0; i < 4; i++)
    {
        w[i].b0 = CIPHER_KEY[i*4];
        w[i].b1 = CIPHER_KEY[i*4+1];
        w[i].b2 = CIPHER_KEY[i*4+2];
        w[i].b3 = CIPHER_KEY[i*4+3];
    }
    for (i = 4;  i < (4 * (10+1)); i++)
    {
        tempword = w[i-1];
        if ((i % 4) == 0)
        {
            tempbyte = tempword.b0;
            tempword.b0 = tempword.b1;
            tempword.b1 = tempword.b2;
            tempword.b2 = tempword.b3;
            tempword.b3 = tempbyte;
            tempword.b0 = Sbox [tempword.b0];
            tempword.b1 = Sbox [tempword.b1];
            tempword.b2 = Sbox [tempword.b2];
            tempword.b3 = Sbox [tempword.b3];
            tempword.b0 ^= Rcon[(unsigned char)i/4 - 1];
        }
        else if ( (4 > 6) && ((i % 4) == 4) )
        {
            tempword.b0 = Sbox [tempword.b0];
            tempword.b1 = Sbox [tempword.b1];
            tempword.b2 = Sbox [tempword.b2];
            tempword.b3 = Sbox [tempword.b3];
        }
        w[i].b0 = w[i-4].b0 ^ tempword.b0;
        w[i].b1 = w[i-4].b1 ^ tempword.b1;
        w[i].b2 = w[i-4].b2 ^ tempword.b2;
        w[i].b3 = w[i-4].b3 ^ tempword.b3;
    }
    for (i = 0; i < 4 * (10 + 1); i++)
    {
        EXP_KEYS [i*4]   = w[i].b0;
        EXP_KEYS [i*4+1] = w[i].b1;
        EXP_KEYS [i*4+2] = w[i].b2;
        EXP_KEYS [i*4+3] = w[i].b3;
    }
}
void InvCipher (unsigned char *in, unsigned char *out)
{
    char r = 10;
    StateIn(in);
    LoadKeys(10);
    AddRoundKey();
    for(r = (10-1); r > 0; r--)
    {
        InvShiftRows ();
        InvSubBytes ();
        LoadKeys (r);
        AddRoundKey ();
        InvMixColumns ();
    }
    InvShiftRows ();
    InvSubBytes ();
    LoadKeys (0);
    AddRoundKey ();
    StateOut (out);
}
static void StateIn(unsigned char *in)
{
    unsigned char col,row;
    for(col = 0; col < 4; col++)
    {
        for(row = 0; row < 4; row++)
        {
            State[row][col] = *(in++);
        }
    }
}
static void StateOut (unsigned char *out)
{
    unsigned char col,row;
    for(col = 0; col < 4; col++)
    {
        for(row = 0; row < 4; row++)
        {
            *(out++) = State[row][col];
        }
    }
}
static void InvSubBytes (void)
{
    State[0][0] = InvSbox[State[0][0]];
    State[0][1] = InvSbox[State[0][1]];
    State[0][2] = InvSbox[State[0][2]];
    State[0][3] = InvSbox[State[0][3]];
    State[1][0] = InvSbox[State[1][0]];
    State[1][1] = InvSbox[State[1][1]];
    State[1][2] = InvSbox[State[1][2]];
    State[1][3] = InvSbox[State[1][3]];
    State[2][0] = InvSbox[State[2][0]];
    State[2][1] = InvSbox[State[2][1]];
    State[2][2] = InvSbox[State[2][2]];
    State[2][3] = InvSbox[State[2][3]];
    State[3][0] = InvSbox[State[3][0]];
    State[3][1] = InvSbox[State[3][1]];
    State[3][2] = InvSbox[State[3][2]];
    State[3][3] = InvSbox[State[3][3]];
}
static void InvShiftRows (void)
{
    unsigned char hold;
    hold = State[1][3];
    State[1][3] = State[1][2];
    State[1][2] = State[1][1];
    State[1][1] = State[1][0];
    State[1][0] = hold;
    hold = State[2][2];
    State[2][2] = State[2][0];
    State[2][0] = hold;
    hold = State[2][3];
    State[2][3] = State[2][1];
    State[2][1] = hold;
    hold = State[3][0];
    State[3][0] = State[3][1];
    State[3][1] = State[3][2];
    State[3][2] = State[3][3];
    State[3][3] = hold;
}
static void InvMixColumns (void)
{
    unsigned char aux0, aux1, aux2, aux3;
    aux0 = FFMultiply(0x0E, State[0][0]) ^ FFMultiply(0x0B, State[1][0]) ^
           FFMultiply(0x0D, State[2][0]) ^ FFMultiply(0x09, State[3][0]);
    aux1 = FFMultiply(0x09, State[0][0]) ^ FFMultiply(0x0E, State[1][0]) ^
           FFMultiply(0x0B, State[2][0]) ^ FFMultiply(0x0D, State[3][0]);
    aux2 = FFMultiply(0x0D, State[0][0]) ^ FFMultiply(0x09, State[1][0]) ^
           FFMultiply(0x0E, State[2][0]) ^ FFMultiply(0x0B, State[3][0]);
    aux3 = FFMultiply(0x0B, State[0][0]) ^ FFMultiply(0x0D, State[1][0]) ^
           FFMultiply(0x09, State[2][0]) ^ FFMultiply(0x0E, State[3][0]);
    State[0][0] = aux0;
    State[1][0] = aux1;
    State[2][0] = aux2;
    State[3][0] = aux3;
    aux0 = FFMultiply(0x0E, State[0][1]) ^ FFMultiply(0x0B, State[1][1]) ^
           FFMultiply(0x0D, State[2][1]) ^ FFMultiply(0x09, State[3][1]);
    aux1 = FFMultiply(0x09, State[0][1]) ^ FFMultiply(0x0E, State[1][1]) ^
           FFMultiply(0x0B, State[2][1]) ^ FFMultiply(0x0D, State[3][1]);
    aux2 = FFMultiply(0x0D, State[0][1]) ^ FFMultiply(0x09, State[1][1]) ^
           FFMultiply(0x0E, State[2][1]) ^ FFMultiply(0x0B, State[3][1]);
    aux3 = FFMultiply(0x0B, State[0][1]) ^ FFMultiply(0x0D, State[1][1]) ^
           FFMultiply(0x09, State[2][1]) ^ FFMultiply(0x0E, State[3][1]);
    State[0][1] = aux0;
    State[1][1] = aux1;
    State[2][1] = aux2;
    State[3][1] = aux3;
    aux0 = FFMultiply(0x0E, State[0][2]) ^ FFMultiply(0x0B, State[1][2]) ^
           FFMultiply(0x0D, State[2][2]) ^ FFMultiply(0x09, State[3][2]);
    aux1 = FFMultiply(0x09, State[0][2]) ^ FFMultiply(0x0E, State[1][2]) ^
           FFMultiply(0x0B, State[2][2]) ^ FFMultiply(0x0D, State[3][2]);
    aux2 = FFMultiply(0x0D, State[0][2]) ^ FFMultiply(0x09, State[1][2]) ^
           FFMultiply(0x0E, State[2][2]) ^ FFMultiply(0x0B, State[3][2]);
    aux3 = FFMultiply(0x0B, State[0][2]) ^ FFMultiply(0x0D, State[1][2]) ^
           FFMultiply(0x09, State[2][2]) ^ FFMultiply(0x0E, State[3][2]);
    State[0][2] = aux0;
    State[1][2] = aux1;
    State[2][2] = aux2;
    State[3][2] = aux3;
    aux0 = FFMultiply(0x0E, State[0][3]) ^ FFMultiply(0x0B, State[1][3]) ^
           FFMultiply(0x0D, State[2][3]) ^ FFMultiply(0x09, State[3][3]);
    aux1 = FFMultiply(0x09, State[0][3]) ^ FFMultiply(0x0E, State[1][3]) ^
           FFMultiply(0x0B, State[2][3]) ^ FFMultiply(0x0D, State[3][3]);
    aux2 = FFMultiply(0x0D, State[0][3]) ^ FFMultiply(0x09, State[1][3]) ^
           FFMultiply(0x0E, State[2][3]) ^ FFMultiply(0x0B, State[3][3]);
    aux3 = FFMultiply(0x0B, State[0][3]) ^ FFMultiply(0x0D, State[1][3]) ^
           FFMultiply(0x09, State[2][3]) ^ FFMultiply(0x0E, State[3][3]);
    State[0][3] = aux0;
    State[1][3] = aux1;
    State[2][3] = aux2;
    State[3][3] = aux3;
}
static void AddRoundKey (void)
{
    State[0][0] ^= CurrentKey[0][0];
    State[0][1] ^= CurrentKey[0][1];
    State[0][2] ^= CurrentKey[0][2];
    State[0][3] ^= CurrentKey[0][3];
    State[1][0] ^= CurrentKey[1][0];
    State[1][1] ^= CurrentKey[1][1];
    State[1][2] ^= CurrentKey[1][2];
    State[1][3] ^= CurrentKey[1][3];
    State[2][0] ^= CurrentKey[2][0];
    State[2][1] ^= CurrentKey[2][1];
    State[2][2] ^= CurrentKey[2][2];
    State[2][3] ^= CurrentKey[2][3];
    State[3][0] ^= CurrentKey[3][0];
    State[3][1] ^= CurrentKey[3][1];
    State[3][2] ^= CurrentKey[3][2];
    State[3][3] ^= CurrentKey[3][3];
}
static void LoadKeys (unsigned char i)
{
    unsigned char index = i * 16;
    CurrentKey[0][0] = EXP_KEYS[index++];
    CurrentKey[1][0] = EXP_KEYS[index++];
    CurrentKey[2][0] = EXP_KEYS[index++];
    CurrentKey[3][0] = EXP_KEYS[index++];
    CurrentKey[0][1] = EXP_KEYS[index++];
    CurrentKey[1][1] = EXP_KEYS[index++];
    CurrentKey[2][1] = EXP_KEYS[index++];
    CurrentKey[3][1] = EXP_KEYS[index++];
    CurrentKey[0][2] = EXP_KEYS[index++];
    CurrentKey[1][2] = EXP_KEYS[index++];
    CurrentKey[2][2] = EXP_KEYS[index++];
    CurrentKey[3][2] = EXP_KEYS[index++];
    CurrentKey[0][3] = EXP_KEYS[index++];
    CurrentKey[1][3] = EXP_KEYS[index++];
    CurrentKey[2][3] = EXP_KEYS[index++];
    CurrentKey[3][3] = EXP_KEYS[index++];
}
static unsigned char FFMultiply (unsigned char x, unsigned char y)
{
    unsigned int temp_result;
    if (y==0)
    {
        return 0;
    }
    temp_result = (unsigned int)log_table[x] + (unsigned int)log_table[y];
    if (temp_result>=0x100)
    {
        temp_result += 1;
        temp_result &= 0xFF;
    }
    return exp_table[temp_result];
}
