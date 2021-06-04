// https://shaih.github.io/pubs/mars/mars.pdf
// http://reto.orgfree.com/us/projectlinks/MARSReport.html
/* MARS is another AES candidate, operating on block of 128 bits and supporting key raging from 128 to 448 bits.
 * Work on 32 bit words, based on a type-3 Feistel network in which one word of data is used to update the other
 * 3 during the rounds. Uses simple operations like additions, subtraction and xor. It also uses a lookup table of 512 entries
 * of 32 bit words called S-box. Sometimes this table is seen a two tables of 256 entries.
 */
public class MarsCipher {
    private final static int BLOCK_LEN = 16; // 16 bytes - 128 bits
    private final static int EXPANDED_KEY_LENGTH = 40; // 40 words
    private final static int TEMP_KEY_LENGTH = 15; // 15 words
    private static int[] K;

    // #define rol32(N, R)    _lrotl(N, R)
    // rotate left
    private static int rotl(int val, int pas) {
        //return (val << pas) | (val >>> (32 - pas));
        return Integer.rotateLeft(val, pas);
    }

    // #define ror32(N, R)    _lrotr(N, R)
    // rotate right
    private static int rotr(int val, int pas) {
        //return (val >>> pas) | (val << (32 - pas));
        return Integer.rotateRight(val, pas);
    }

    private static int[] toIntArray(byte[] data) {
        int[] ret = new int[data.length / 4];       //int 4 bytes
        int off = 0;
        for (int i = 0; i < ret.length; i++) {
            ret[i] = ((data[off++] & 0xff)) |       //0xff = 255 = 11111111
                    ((data[off++] & 0xff) << 8) |
                    ((data[off++] & 0xff) << 16) |
                    ((data[off++] & 0xff) << 24);

        }
        return ret;
    }

    private static byte[] toByteArray(int[] data) {
        byte[] ret = new byte[data.length * 4];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = (byte) ((data[i / 4] >>> (i % 4) * 8) & 0xff);
        }
        return ret;
    }

    private static int generateMask(int x) {
        // Generate a bit-mask M
        int m;
        m = (~x ^ (x >>> 1)) & 0x7fffffff;
        m &= (m >> 1) & (m >> 2);
        m &= (m >> 3) & (m >> 6);

        if (m == 0)
            return 0;

        m <<= 1;
        m |= (m << 1);
        m |= (m << 2);
        m |= (m << 4);
        m |= (m << 1) & ~x & 0x80000000;

        return m & 0xfffffffc;
    }

    // MARS algorithm has a variable key length. The interval of the key length is either
    // from 128 to 448 bit or 128 to 1248 bit with some restrictions. Internal the algorithm
    // works with 40 key words, which is equal to 1280 bit.
    private static int[] expandKey(byte[] key) {
        // http://reto.orgfree.com/us/projectlinks/keyexp.html
        int[] data = toIntArray(key);
        int n = key.length / 4; // the number of words in the key buffer k[ ];
        int[] K = new int[EXPANDED_KEY_LENGTH]; // K[ ]is the expanded key array, consisting of 40 words
        int[] T = new int[TEMP_KEY_LENGTH]; // T[ ]is a temporary array, consisting of 15 words
        int[] B = {0xa4a8d57b, 0x5b5d193b, 0xc8a8309b, 0x73f9a978};// B[ ]is a fixed table of four words

        // Initialize T[ ]with key data
        // T[0 ... n-1] = k[0 ... n-1], T[n] =n, T[n + 1...14] = 0
        for (int i = 0; i < T.length; i++) {
            if (i < data.length) {
                T[i] = data[i];
            } else if (i == data.length) {
                T[i] = n;
            } else {
                T[i] = 0;
            }
        }

        // Four iterations, computing 10 words of K[ ]in each
        for (int j = 0; j < 4; j++) {
            // Linear transformation
            // T[i] = T[i] (+) ((T[i-7 mod 15] (+) T[i-2 mod 15]) <<< 3) (+) (4i + j)
            // ^ for XOR
            // rotl for  <<< 3
            for (int i = 0; i < T.length; i++) {
                T[i] = T[i] ^ (rotl(T[Math.abs(i - 7 % TEMP_KEY_LENGTH)]
                        ^ T[Math.abs(i - 2 % TEMP_KEY_LENGTH)], 3) ^ (4 * i + j));
            }

            // Four stirring rounds
            // T[i] = (T[i] +S[low 9 bits of T[i-1 mod 15]]) <<< 9
            for (int c = 0; c < 4; c++)
                for (int i = 0; i < T.length; i++) {
                    T[i] = T[i] + rotl(SBox[T[Math.abs(i - 1 % TEMP_KEY_LENGTH)] & 0x000001ff], 9);
                }

            // store next 10 words into K[ ]
            for (int i = 0; i <= 9; i++) {
                K[10 * j + i] = T[4 * i % TEMP_KEY_LENGTH];
            }

        }

        // Modify multiplication keys
        int j, w, m, r, p;
        for (int i = 5; i <= 35; i++) {
            j = K[i] & 0x00000003; // least two bits of K[i]
            w = K[i] | 0x00000003; // K[i] with both of the least two bits set to 1
            m = generateMask(w); // M = 1 if w` belongs to a sequence of ten consecutive 0’s or 1’s in w
            r = K[i - 1] & 0x0000001f; // least five bits of K[i-1] // Rotation amount
            p = rotl(B[j], r); // Select a pattern from the fixed table and rotate it
            K[i] = w ^ (p & m); // Modify K[i] with p under the control of the mask M
        }
        return K;
    }

    private static byte[] encryptBlock(byte[] in) {
        int[] data = toIntArray(in);

        // forward mixing(key addition)
        int A = data[0] + K[0];
        int B = data[1] + K[1];
        int C = data[2] + K[2];
        int D = data[3] + K[3];

        // forward mixing(eight rounds of unkeyed forward mixing) - type-3 Feistel mixing
        int aux;
        for (int i = 0; i <= 7; i++) {
            // In each round we use one data word (called the source word) to modify the other
            // three data words (called the target words). If we denote the four bytes of the source
            // words by b0; b1; b2; b3 (where b0 is the lowest byte and b3 is the highest byte), then
            // we use b0; b2 as indices into the S-box S0 and b1; b3 as indices into the S-box S1
            B = B ^ SBox[A & 0xff]; // xor S0[b0] into the first target word
            B = B + SBox[(rotr(A, 8) & 0xff) + 256]; // add S1[b1] to the same word
            C = C + SBox[rotr(A, 16) & 0xff]; // add S0[b2] to the second target word
            D = D ^ SBox[(rotr(A, 24) & 0xff) + 256]; //  xor S1[b3] to the third target word

            A = rotr(A, 24); // rotate the source word by 24 positions to the right

            if (i == 1 || i == 5) {
                A = A + B;
            } // after the first and fifth rounds we add the third target word back into the source

            if (i == 0 || i == 4) {
                A = A + D;
            }// after the second and sixth round we add the first target word back into the source word


            // for the next round we rotate the four words
            aux = A; //
            A = B; // the current first target word becomes the next source word
            B = C; // the current second target word becomes the next first target word
            C = D; // the current third target word becomes the next second target word
            D = aux; // the current source word become the next third target word.
        }

        // cryptographic core (eight rounds of keyed forward transformation/backwards transformation)
        for (int i = 0; i <= 15; i++) {
            int[] eout = EFunc(A, K[2 * i + 4], K[2 * i + 5]);
            // the three output words from the E-function are added or xored to the other three data words

            A = rotl(A, 13); // source word is rotated by 13 positions to the left

            /* To ensure that the cipher has the same resistance to chosen ciphertext attacks as it has for chosen
            plaintext attacks, the three outputs from the E-function are used in a different order in the first
            eight rounds than in the last eight rounds */
            C = C + eout[1]; // add the first output of the E function to the second target word
            if (i < 8) {
                B = B + eout[0]; // add the first output of the E-function to the first target word
                D = D ^ eout[2]; // xor the third output into the third target word
            } else {
                D = D + eout[0]; // add the second output of the E-function to the third target word
                B = B ^ eout[2]; // xor the third output into the first target word
            }

            aux = A;
            A = B;
            B = C;
            C = D;
            D = aux;
        }

        // backwards mixing(eight rounds of unkeyed backwards mixing)
        for (int i = 0; i <= 7; i++) {
            // In each round one source word to modify the other three
            // target words. Denote the four bytes of the source words by b0; b1; b2; b3 as before. We use b0; b2 as
            // indices into the S-box S1 and b1; b3 as indices into the S-box S0.

            if (i == 3 || i == 7)
                A = A - B; // before the fourth and eighth rounds we subtract the first target word from the source word
            if (i == 2 || i == 6)
                A = A - D; // before the third and seventh round we subtract the third target word from the source word

            B = B ^ SBox[(A & 0xff) + 256]; // xor S1[b0] into the first target word
            C = C - SBox[rotr(A, 24) & 0xff]; // subtract S0[b3] from the second data word
            D = D - SBox[(rotr(A, 16) & 0xff) + 256]; // subtract S1[b2] from the third target word
            D = D ^ SBox[rotr(A, 8) & 0xff]; // xor S0[b1] also into the third target word

            A = rotl(A, 24); // rotate the source word by 24 positions to the left

            aux = A;
            A = B; // the current first target word becomes the next source word
            B = C; // the current second target word becomes the next first target word
            C = D; // the current third target word becomes the next second target word
            D = aux; // the current source word become the next third target word
        }

        // backwards mixing(key subtraction)
        A = A - K[36];
        B = B - K[37];
        C = C - K[38];
        D = D - K[39];

        data[0] = A;
        data[1] = B;
        data[2] = C;
        data[3] = D;

        return toByteArray(data);
    }

    // keyed E-function (E for expansion) which is based on a novel
    // combination of multiplication, data-dependent rotations, and an S-box lookup
    private static int[] EFunc(int in, int k1, int k2) {
        int M, L, R; // left, middle and right -  three “lines” in the function

        M = in + k1; // sum of the source word and the first key word
        R = rotl(in, 13) * k2; // source word rotated by 13 positions to the left, multiply by 2nd key word, which must be odd
        L = SBox[M & 0x000001ff]; // view the lowest nine bits of M as an index to a 512-entry S-box
        R = rotl(R, 5); // rotate R by 5 positions to the left
        M = rotl(M, R & 0x0000001f); // rotate to the left by five lowest bits of R
        L = L ^ R; // xor R into L
        R = rotl(R, 5);
        L = L ^ R; // xor R into L
        L = rotl(L, R & 0x0000001f); // rotate to the left by five lowest bits of R

        int[] ret = new int[3];
        ret[0] = L;
        ret[1] = M;
        ret[2] = R;

        return ret;
    }

    private static byte[] decryptBlock(byte[] in) {
        int[] data = toIntArray(in);
        int A = data[0] + K[36];
        int B = data[1] + K[37];
        int C = data[2] + K[38];
        int D = data[3] + K[39];

        int aux;
        //forward mixing
        for (int i = 7; i >= 0; i--) {
            aux = D;
            D = C;
            C = B;
            B = A;
            A = aux;

            A = rotr(A, 24);

            D = D ^ SBox[(rotr(A, 8) & 0xff)];
            D = D + SBox[(rotr(A, 16) & 0xff) + 256];
            C = C + SBox[rotr(A, 24) & 0xff];
            B = B ^ SBox[(A & 0xff) + 256];

            if (i == 2 || i == 6) A = A + D;
            if (i == 3 || i == 7) A = A + B;
        }

        // cryptographic core
        for (int i = 15; i >= 0; i--) {
            aux = D;
            D = C;
            C = B;
            B = A;
            A = aux;

            A = rotr(A, 13);
            int[] eout = EFunc(A, K[2 * i + 4], K[2 * i + 5]);

            C = C - eout[1];
            if (i < 8) {
                B = B - eout[0];
                D = D ^ eout[2];
            } else {
                D = D - eout[0];
                B = B ^ eout[2];
            }
        }

        //backward mixing
        for (int i = 7; i >= 0; i--) {
            aux = D;
            D = C;
            C = B;
            B = A;
            A = aux;

            if (i == 0 || i == 4) A = A - D;
            if (i == 1 || i == 5) A = A - B;

            A = rotl(A, 24);

            D = D ^ SBox[(rotr(A, 24) & 0xff) + 256];
            C = C - SBox[rotr(A, 16) & 0xff];
            B = B - SBox[(rotr(A, 8) & 0xff) + 256];
            B = B ^ SBox[A & 0xff];
        }
        A = A - K[0];
        B = B - K[1];
        C = C - K[2];
        D = D - K[3];

        data[0] = A;
        data[1] = B;
        data[2] = C;
        data[3] = D;

        return toByteArray(data);
    }

    public static byte[] encrypt(byte[] in, byte[] key) {
        K = expandKey(key); // expand user key to internal key

        int length = BLOCK_LEN - in.length % BLOCK_LEN;
        byte[] padding = new byte[length];
        padding[0] = (byte) 0x80;

        byte[] tmp = new byte[in.length + length];
        byte[] block = new byte[BLOCK_LEN];

        int count = 0;
        int i;
        for (i = 0; i < in.length + length; i++) {
            if (i > 0 && i % BLOCK_LEN == 0) {
                block = encryptBlock(block);
                System.arraycopy(block, 0, tmp, i - BLOCK_LEN, block.length);
            }
            if (i < in.length)
                block[i % BLOCK_LEN] = in[i];
            else {
                block[i % BLOCK_LEN] = padding[count % BLOCK_LEN];
                count++;
            }
        }
        if (block.length == BLOCK_LEN) {
            block = encryptBlock(block);
            System.arraycopy(block, 0, tmp, i - BLOCK_LEN, block.length);
        }
        return tmp;
    }

    public static byte[] decrypt(byte[] in, byte[] key) {
        byte[] tmp = new byte[in.length];
        byte[] block = new byte[BLOCK_LEN];
        K = expandKey(key);
        int i;
        for (i = 0; i < in.length; i++) {
            if (i > 0 && i % BLOCK_LEN == 0) {
                block = decryptBlock(block);
                System.arraycopy(block, 0, tmp, i - BLOCK_LEN, block.length);
            }
            if (i < in.length)
                block[i % BLOCK_LEN] = in[i];
        }
        block = decryptBlock(block);
        System.arraycopy(block, 0, tmp, i - BLOCK_LEN, block.length);

        tmp = deletePadding(tmp);
        return tmp;
    }

    private static byte[] deletePadding(byte[] input) {
        int count = 0;

        int i = input.length - 1;
        while (input[i] == 0) {
            count++;
            i--;
        }

        byte[] tmp = new byte[input.length - count - 1];
        System.arraycopy(input, 0, tmp, 0, tmp.length);
        return tmp;
    }

    // In the design of the S-box S, we generated the entries of S in a “pseudorandom fashion” and tested
    // that the resulting S-box has good differential and linear properties
    private final static int[] SBox = {
            0x09d0c479, 0x28c8ffe0, 0x84aa6c39, 0x9dad7287, 0x7dff9be3, 0xd4268361, 0xc96da1d4, 0x7974cc93, 0x85d0582e, 0x2a4b5705,
            0x1ca16a62, 0xc3bd279d, 0x0f1f25e5, 0x5160372f, 0xc695c1fb, 0x4d7ff1e4, 0xae5f6bf4, 0x0d72ee46, 0xff23de8a, 0xb1cf8e83,
            0xf14902e2, 0x3e981e42, 0x8bf53eb6, 0x7f4bf8ac, 0x83631f83, 0x25970205, 0x76afe784, 0x3a7931d4, 0x4f846450, 0x5c64c3f6,
            0x210a5f18, 0xc6986a26, 0x28f4e826, 0x3a60a81c, 0xd340a664, 0x7ea820c4, 0x526687c5, 0x7eddd12b, 0x32a11d1d, 0x9c9ef086,
            0x80f6e831, 0xab6f04ad, 0x56fb9b53, 0x8b2e095c, 0xb68556ae, 0xd2250b0d, 0x294a7721, 0xe21fb253, 0xae136749, 0xe82aae86,
            0x93365104, 0x99404a66, 0x78a784dc, 0xb69ba84b, 0x04046793, 0x23db5c1e, 0x46cae1d6, 0x2fe28134, 0x5a223942, 0x1863cd5b,
            0xc190c6e3, 0x07dfb846, 0x6eb88816, 0x2d0dcc4a, 0xa4ccae59, 0x3798670d, 0xcbfa9493, 0x4f481d45, 0xeafc8ca8, 0xdb1129d6,
            0xb0449e20, 0x0f5407fb, 0x6167d9a8, 0xd1f45763, 0x4daa96c3, 0x3bec5958, 0xababa014, 0xb6ccd201, 0x38d6279f, 0x02682215,
            0x8f376cd5, 0x092c237e, 0xbfc56593, 0x32889d2c, 0x854b3e95, 0x05bb9b43, 0x7dcd5dcd, 0xa02e926c, 0xfae527e5, 0x36a1c330,
            0x3412e1ae, 0xf257f462, 0x3c4f1d71, 0x30a2e809, 0x68e5f551, 0x9c61ba44, 0x5ded0ab8, 0x75ce09c8, 0x9654f93e, 0x698c0cca,
            0x243cb3e4, 0x2b062b97, 0x0f3b8d9e, 0x00e050df, 0xfc5d6166, 0xe35f9288, 0xc079550d, 0x0591aee8, 0x8e531e74, 0x75fe3578,
            0x2f6d829a, 0xf60b21ae, 0x95e8eb8d, 0x6699486b, 0x901d7d9b, 0xfd6d6e31, 0x1090acef, 0xe0670dd8, 0xdab2e692, 0xcd6d4365,
            0xe5393514, 0x3af345f0, 0x6241fc4d, 0x460da3a3, 0x7bcf3729, 0x8bf1d1e0, 0x14aac070, 0x1587ed55, 0x3afd7d3e, 0xd2f29e01,
            0x29a9d1f6, 0xefb10c53, 0xcf3b870f, 0xb414935c, 0x664465ed, 0x024acac7, 0x59a744c1, 0x1d2936a7, 0xdc580aa6, 0xcf574ca8,
            0x040a7a10, 0x6cd81807, 0x8a98be4c, 0xaccea063, 0xc33e92b5, 0xd1e0e03d, 0xb322517e, 0x2092bd13, 0x386b2c4a, 0x52e8dd58,
            0x58656dfb, 0x50820371, 0x41811896, 0xe337ef7e, 0xd39fb119, 0xc97f0df6, 0x68fea01b, 0xa150a6e5, 0x55258962, 0xeb6ff41b,
            0xd7c9cd7a, 0xa619cd9e, 0xbcf09576, 0x2672c073, 0xf003fb3c, 0x4ab7a50b, 0x1484126a, 0x487ba9b1, 0xa64fc9c6, 0xf6957d49,
            0x38b06a75, 0xdd805fcd, 0x63d094cf, 0xf51c999e, 0x1aa4d343, 0xb8495294, 0xce9f8e99, 0xbffcd770, 0xc7c275cc, 0x378453a7,
            0x7b21be33, 0x397f41bd, 0x4e94d131, 0x92cc1f98, 0x5915ea51, 0x99f861b7, 0xc9980a88, 0x1d74fd5f, 0xb0a495f8, 0x614deed0,
            0xb5778eea, 0x5941792d, 0xfa90c1f8, 0x33f824b4, 0xc4965372, 0x3ff6d550, 0x4ca5fec0, 0x8630e964, 0x5b3fbbd6, 0x7da26a48,
            0xb203231a, 0x04297514, 0x2d639306, 0x2eb13149, 0x16a45272, 0x532459a0, 0x8e5f4872, 0xf966c7d9, 0x07128dc0, 0x0d44db62,
            0xafc8d52d, 0x06316131, 0xd838e7ce, 0x1bc41d00, 0x3a2e8c0f, 0xea83837e, 0xb984737d, 0x13ba4891, 0xc4f8b949, 0xa6d6acb3,
            0xa215cdce, 0x8359838b, 0x6bd1aa31, 0xf579dd52, 0x21b93f93, 0xf5176781, 0x187dfdde, 0xe94aeb76, 0x2b38fd54, 0x431de1da,
            0xab394825, 0x9ad3048f, 0xdfea32aa, 0x659473e3, 0x623f7863, 0xf3346c59, 0xab3ab685, 0x3346a90b, 0x6b56443e, 0xc6de01f8,
            0x8d421fc0, 0x9b0ed10c, 0x88f1a1e9, 0x54c1f029, 0x7dead57b, 0x8d7ba426, 0x4cf5178a, 0x551a7cca, 0x1a9a5f08, 0xfcd651b9,
            0x25605182, 0xe11fc6c3, 0xb6fd9676, 0x337b3027, 0xb7c8eb14, 0x9e5fd030, 0x6b57e354, 0xad913cf7, 0x7e16688d, 0x58872a69,
            0x2c2fc7df, 0xe389ccc6, 0x30738df1, 0x0824a734, 0xe1797a8b, 0xa4a8d57b, 0x5b5d193b, 0xc8a8309b, 0x73f9a978, 0x73398d32,
            0x0f59573e, 0xe9df2b03, 0xe8a5b6c8, 0x848d0704, 0x98df93c2, 0x720a1dc3, 0x684f259a, 0x943ba848, 0xa6370152, 0x863b5ea3,
            0xd17b978b, 0x6d9b58ef, 0x0a700dd4, 0xa73d36bf, 0x8e6a0829, 0x8695bc14, 0xe35b3447, 0x933ac568, 0x8894b022, 0x2f511c27,
            0xddfbcc3c, 0x006662b6, 0x117c83fe, 0x4e12b414, 0xc2bca766, 0x3a2fec10, 0xf4562420, 0x55792e2a, 0x46f5d857, 0xceda25ce,
            0xc3601d3b, 0x6c00ab46, 0xefac9c28, 0xb3c35047, 0x611dfee3, 0x257c3207, 0xfdd58482, 0x3b14d84f, 0x23becb64, 0xa075f3a3,
            0x088f8ead, 0x07adf158, 0x7796943c, 0xfacabf3d, 0xc09730cd, 0xf7679969, 0xda44e9ed, 0x2c854c12, 0x35935fa3, 0x2f057d9f,
            0x690624f8, 0x1cb0bafd, 0x7b0dbdc6, 0x810f23bb, 0xfa929a1a, 0x6d969a17, 0x6742979b, 0x74ac7d05, 0x010e65c4, 0x86a3d963,
            0xf907b5a0, 0xd0042bd3, 0x158d7d03, 0x287a8255, 0xbba8366f, 0x096edc33, 0x21916a7b, 0x77b56b86, 0x951622f9, 0xa6c5e650,
            0x8cea17d1, 0xcd8c62bc, 0xa3d63433, 0x358a68fd, 0x0f9b9d3c, 0xd6aa295b, 0xfe33384a, 0xc000738e, 0xcd67eb2f, 0xe2eb6dc2,
            0x97338b02, 0x06c9f246, 0x419cf1ad, 0x2b83c045, 0x3723f18a, 0xcb5b3089, 0x160bead7, 0x5d494656, 0x35f8a74b, 0x1e4e6c9e,
            0x000399bd, 0x67466880, 0xb4174831, 0xacf423b2, 0xca815ab3, 0x5a6395e7, 0x302a67c5, 0x8bdb446b, 0x108f8fa4, 0x10223eda,
            0x92b8b48b, 0x7f38d0ee, 0xab2701d4, 0x0262d415, 0xaf224a30, 0xb3d88aba, 0xf8b2c3af, 0xdaf7ef70, 0xcc97d3b7, 0xe9614b6c,
            0x2baebff4, 0x70f687cf, 0x386c9156, 0xce092ee5, 0x01e87da6, 0x6ce91e6a, 0xbb7bcc84, 0xc7922c20, 0x9d3b71fd, 0x060e41c6,
            0xd7590f15, 0x4e03bb47, 0x183c198e, 0x63eeb240, 0x2ddbf49a, 0x6d5cba54, 0x923750af, 0xf9e14236, 0x7838162b, 0x59726c72,
            0x81b66760, 0xbb2926c1, 0x48a0ce0d, 0xa6c0496d, 0xad43507b, 0x718d496a, 0x9df057af, 0x44b1bde6, 0x054356dc, 0xde7ced35,
            0xd51a138b, 0x62088cc9, 0x35830311, 0xc96efca2, 0x686f86ec, 0x8e77cb68, 0x63e1d6b8, 0xc80f9778, 0x79c491fd, 0x1b4c67f2,
            0x58656dfb, 0x50820371, 0x41811896, 0xe337ef7e, 0xd39fb119, 0xc97f0df6, 0x68fea01b, 0xa150a6e5, 0x55258962, 0xeb6ff41b,
            0xd7c9cd7a, 0xa619cd9e, 0xbcf09576, 0x2672c073, 0xf003fb3c, 0x4ab7a50b, 0x1484126a, 0x487ba9b1, 0xa64fc9c6, 0xf6957d49,
            0x38b06a75, 0xdd805fcd, 0x63d094cf, 0xf51c999e, 0x1aa4d343, 0xb8495294, 0xce9f8e99, 0xbffcd770, 0xc7c275cc, 0x378453a7,
            0x7b21be33, 0x397f41bd, 0x4e94d131, 0x92cc1f98, 0x5915ea51, 0x99f861b7, 0xc9980a88, 0x1d74fd5f, 0xb0a495f8, 0x614deed0,
            0xb5778eea, 0x5941792d, 0xfa90c1f8, 0x33f824b4, 0xc4965372, 0x3ff6d550, 0x4ca5fec0, 0x8630e964, 0x5b3fbbd6, 0x7da26a48,
            0xb203231a, 0x04297514, 0x2d639306, 0x2eb13149, 0x16a45272, 0x532459a0, 0x8e5f4872, 0xf966c7d9, 0x07128dc0, 0x0d44db62,
            0xafc8d52d, 0x06316131, 0xd838e7ce, 0x1bc41d00, 0x3a2e8c0f, 0xea83837e, 0xb984737d, 0x13ba4891, 0xc4f8b949, 0xa6d6acb3,
            0xa215cdce, 0x8359838b, 0x6bd1aa31, 0xf579dd52, 0x21b93f93, 0xf5176781, 0x187dfdde, 0xe94aeb76, 0x2b38fd54, 0x431de1da,
            0xab394825, 0x9ad3048f, 0xdfea32aa, 0x659473e3, 0x623f7863, 0xf3346c59, 0xab3ab685, 0x3346a90b, 0x6b56443e, 0xc6de01f8,
            0x8d421fc0, 0x9b0ed10c, 0x88f1a1e9, 0x54c1f029, 0x7dead57b, 0x8d7ba426, 0x4cf5178a, 0x551a7cca, 0x1a9a5f08, 0xfcd651b9,
            0x25605182, 0xe11fc6c3, 0xb6fd9676, 0x337b3027, 0xb7c8eb14, 0x9e5fd030, 0x6b57e354, 0xad913cf7, 0x7e16688d, 0x58872a69,
            0x2c2fc7df, 0xe389ccc6, 0x30738df1, 0x0824a734, 0xe1797a8b, 0xa4a8d57b, 0x5b5d193b, 0xc8a8309b, 0x73f9a978, 0x73398d32,
            0x0f59573e, 0xe9df2b03, 0xe8a5b6c8, 0x848d0704, 0x98df93c2, 0x720a1dc3, 0x684f259a, 0x943ba848, 0xa6370152, 0x863b5ea3,
            0xd17b978b, 0x6d9b58ef, 0x0a700dd4, 0xa73d36bf, 0x8e6a0829, 0x8695bc14, 0xe35b3447, 0x933ac568, 0x8894b022, 0x2f511c27,
            0xddfbcc3c, 0x006662b6, 0x117c83fe, 0x4e12b414, 0xc2bca766, 0x3a2fec10, 0xf4562420, 0x55792e2a, 0x46f5d857, 0xceda25ce,
            0xc3601d3b, 0x6c00ab46, 0xefac9c28, 0xb3c35047, 0x611dfee3, 0x257c3207, 0xfdd58482, 0x3b14d84f, 0x23becb64, 0xa075f3a3,
            0x088f8ead, 0x07adf158, 0x7796943c, 0xfacabf3d, 0xc09730cd, 0xf7679969, 0xda44e9ed, 0x2c854c12, 0x35935fa3, 0x2f057d9f,
            0x690624f8, 0x1cb0bafd, 0x7b0dbdc6, 0x810f23bb, 0xfa929a1a, 0x6d969a17, 0x6742979b, 0x74ac7d05, 0x010e65c4, 0x86a3d963,
            0xf907b5a0, 0xd0042bd3, 0x158d7d03, 0x287a8255, 0xbba8366f, 0x096edc33, 0x21916a7b, 0x77b56b86, 0x951622f9, 0xa6c5e650,
            0x8cea17d1, 0xcd8c62bc, 0xa3d63433, 0x358a68fd, 0x0f9b9d3c, 0xd6aa295b, 0xfe33384a, 0xc000738e, 0xcd67eb2f, 0xe2eb6dc2,
            0x97338b02, 0x06c9f246, 0x419cf1ad, 0x2b83c045, 0x3723f18a, 0xcb5b3089, 0x160bead7, 0x5d494656, 0x35f8a74b, 0x1e4e6c9e,
            0x000399bd, 0x67466880, 0xb4174831, 0xacf423b2, 0xca815ab3, 0x5a6395e7, 0x302a67c5, 0x8bdb446b, 0x108f8fa4, 0x10223eda,
            0x92b8b48b, 0x7f38d0ee, 0xab2701d4, 0x0262d415, 0xaf224a30, 0xb3d88aba, 0xf8b2c3af, 0xdaf7ef70, 0xcc97d3b7, 0xe9614b6c,
            0x2baebff4, 0x70f687cf, 0x386c9156, 0xce092ee5, 0x01e87da6, 0x6ce91e6a, 0xbb7bcc84, 0xc7922c20, 0x9d3b71fd, 0x060e41c6,
            0xd7590f15, 0x4e03bb47, 0x183c198e, 0x63eeb240, 0x2ddbf49a, 0x6d5cba54, 0x923750af, 0xf9e14236, 0x7838162b, 0x59726c72,
            0x81b66760, 0xbb2926c1, 0x48a0ce0d, 0xa6c0496d, 0xad43507b, 0x718d496a, 0x9df057af, 0x44b1bde6, 0x054356dc, 0xde7ced35,
            0xd51a138b, 0x62088cc9, 0x35830311, 0xc96efca2, 0x686f86ec, 0x8e77cb68, 0x63e1d6b8, 0xc80f9778, 0x79c491fd, 0x1b4c67f2,
    };
}
