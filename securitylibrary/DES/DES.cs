using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    
    public class DES : CryptographicTechnique
    {
        static string[] Round_keys_in_hex = new string[16];
        static string[] Round_keys_in_binary = new string[16];
        static int[] expansion_d_box = new int[] {32, 1, 2, 3, 4, 5, 4, 5,
                                                 6, 7, 8, 9, 8, 9, 10, 11,
                                                 12, 13, 12, 13, 14, 15, 16, 17,
                                                 16, 17, 18, 19, 20, 21, 20, 21,
                                                 22, 23, 24, 25, 24, 25, 26, 27,
                                                 28, 29, 28, 29, 30, 31, 32, 1 };
        static int[,,] s_box = new int[,,] {
            { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
              { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
              { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
              { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } },

            { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
              { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
              { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
              { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } },
            { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
              { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
              { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
              { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } },
            { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
              { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
              { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
              { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } },
            { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
              { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
              { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
              { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } },
            { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
              { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
              { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
              { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } },
            { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
              { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
              { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
              { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } },
            { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
              { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
              { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
              { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } }
        };
        static int[] final_permutation = new int[] {40, 8, 48, 16, 56, 24, 64, 32,
                                            39, 7, 47, 15, 55, 23, 63, 31,
                                            38, 6, 46, 14, 54, 22, 62, 30,
                                            37, 5, 45, 13, 53, 21, 61, 29,
                                             36, 4, 44, 12, 52, 20, 60, 28,
                                             35, 3, 43, 11, 51, 19, 59, 27,
                                             34, 2, 42, 10, 50, 18, 58, 26,
                                             33, 1, 41, 9, 49, 17, 57, 25 };

        ///convert to binary
        public static string ToBinary(string s)
        {
            string[] binary = new string[] { "0000", "0001", "0010", "0011", "0100", "0101", "0110", "0111", "1000", "1001", "1010"
                , "1011", "1100", "1101", "1110", "1111" };
            string binary_s = "";
            int size_of_string = s.Length;
            for (int i = 0; i < size_of_string; ++i)
            {
                if (s[i].Equals('A')) binary_s += binary[10];
                else if (s[i].Equals('B')) binary_s += binary[11];
                else if (s[i].Equals('C')) binary_s += binary[12];
                else if (s[i].Equals('D')) binary_s += binary[13];
                else if (s[i].Equals('E')) binary_s += binary[14];
                else if (s[i].Equals('F')) binary_s += binary[15];
                else binary_s += binary[s[i] - '0'];
            }
            return binary_s;
        }

        /// convert to hex
        public static string ToHex(string s)
        {
            Dictionary<string, string> binary = new Dictionary<string, string>();
            binary["0000"] = "0";
            binary["0001"] = "1";
            binary["0010"] = "2";
            binary["0011"] = "3";
            binary["0100"] = "4";
            binary["0101"] = "5";
            binary["0110"] = "6";
            binary["0111"] = "7";
            binary["1000"] = "8";
            binary["1001"] = "9";
            binary["1010"] = "A";
            binary["1011"] = "B";
            binary["1100"] = "C";
            binary["1101"] = "D";
            binary["1110"] = "E";
            binary["1111"] = "F";

            int size_of_string = s.Length;
            string hex = "";
            for (int i = 0; i < size_of_string; i += 4)
            {
                string sub = s.Substring(i, 4);
                hex += binary[sub];
            }
            return hex;
        }

        public override string Decrypt(string cipherText, string key)
        {
            string binary_key = ToBinary(key.Substring(2));
            int len = binary_key.Length;
            Key_operations(binary_key);
            string[] reversed_round_keys = new string[16];
            int k = 0;
            for (int i = 15; i >= 0; --i)
            {
                reversed_round_keys[k] = Round_keys_in_binary[i];
                k++;
            }
            for (int i = 0; i < 16; ++i)
            {
                Round_keys_in_binary[i] = reversed_round_keys[i];
            }
            string binary_plain_text = ToBinary(cipherText.Substring(2));

            // 1- initial permutation
            int[] initial_permutation = new int[] {58, 50, 42, 34, 26, 18, 10, 2,
                                                     60, 52, 44, 36, 28, 20, 12, 4,
                                                     62, 54, 46, 38, 30, 22, 14, 6,
                                                     64, 56, 48, 40, 32, 24, 16, 8,
                                                     57, 49, 41, 33, 25, 17, 9, 1,
                                                     59, 51, 43, 35, 27, 19, 11, 3,
                                                     61, 53, 45, 37, 29, 21, 13, 5,
                                                     63, 55, 47, 39, 31, 23, 15, 7 };
            string plain_text_permutated = "";
            for (int i = 0; i < 64; ++i)
            {
                plain_text_permutated += binary_plain_text[initial_permutation[i] - 1];
            }

            // 2- split into right and left
            string left_plain_text = plain_text_permutated.Substring(0, 32);
            string right_plain_text = plain_text_permutated.Substring(32);

            // 3- perform expansion d-box, xor, then combine
            for (int i = 0; i < 16; ++i)
            {
                string right_expanded = Right_expansion(right_plain_text);
                string xored = XOR(right_expanded, Round_keys_in_binary[i]);

                string op = "";
                for (int j = 0; j < 8; j++)
                {
                    int row = 2 * (xored[j * 6] - '0') + (xored[j * 6 + 5] - '0');
                    int col = 8 * (xored[j * 6 + 1] - '0') + 4 * (xored[j * 6 + 2] - '0') + 2 *
                        (xored[j * 6 + 3] - '0') + (xored[j * 6 + 4] - '0');
                    int val = s_box[j, row, col];
                    op += Convert.ToChar(val / 8 + '0');
                    val = val % 8;
                    op += Convert.ToChar(val / 4 + '0');
                    val = val % 4;
                    op += Convert.ToChar(val / 2 + '0');
                    val = val % 2;
                    op += Convert.ToChar(val + '0');
                }
                string new_op = "";
                new_op = Straight_permutation(op);
                string left_xored = XOR(new_op, left_plain_text);
                left_plain_text = left_xored;

                string temp = "";
                if (i != 15)
                {
                    temp = left_plain_text;
                    left_plain_text = right_plain_text;
                    right_plain_text = temp;
                }
            }

            string whole_plain_text = left_plain_text + right_plain_text;

            // 4- perform final permutation
            string final = "";
            for (int i = 0; i < 64; ++i)
            {
                final += whole_plain_text[final_permutation[i] - 1];
            }
            final = ToHex(final);

            return ("0x" + final);
        }

        public override string Encrypt(string plainText, string key)
        {
            // convert key to binary then do the key operations
            string binary_key = ToBinary(key.Substring(2));
            int len = binary_key.Length;
            Key_operations(binary_key);

            string binary_plain_text = ToBinary(plainText.Substring(2));

            // 1- initial permutation
            int[] initial_permutation = new int[] {58, 50, 42, 34, 26, 18, 10, 2,
                                                     60, 52, 44, 36, 28, 20, 12, 4,
                                                     62, 54, 46, 38, 30, 22, 14, 6,
                                                     64, 56, 48, 40, 32, 24, 16, 8,
                                                     57, 49, 41, 33, 25, 17, 9, 1,
                                                     59, 51, 43, 35, 27, 19, 11, 3,
                                                     61, 53, 45, 37, 29, 21, 13, 5,
                                                     63, 55, 47, 39, 31, 23, 15, 7 };
            string plain_text_permutated = "";
            for (int i = 0; i < 64; ++i)
            {
                plain_text_permutated += binary_plain_text[initial_permutation[i] - 1];
            }

            // 2- split into right and left
            string left_plain_text = plain_text_permutated.Substring(0, 32);
            string right_plain_text = plain_text_permutated.Substring(32);

            // 3- perform expansion d-box, xor, then combine
            for (int i = 0; i < 16; ++i)
            {
                string right_expanded = Right_expansion(right_plain_text);
                string xored = XOR(right_expanded, Round_keys_in_binary[i]);

                string op = "";
                for (int j = 0; j < 8; j++)
                {
                    int row = 2 * (xored[j * 6] - '0') + (xored[j * 6 + 5] - '0');
                    int col = 8 * (xored[j * 6 + 1] - '0') + 4 * (xored[j * 6 + 2] - '0') + 2 *
                        (xored[j * 6 + 3] - '0') + (xored[j * 6 + 4] - '0');
                    int val = s_box[j, row, col];
                    op += Convert.ToChar(val / 8 + '0');
                    val = val % 8;
                    op += Convert.ToChar(val / 4 + '0');
                    val = val % 4;
                    op += Convert.ToChar(val / 2 + '0');
                    val = val % 2;
                    op += Convert.ToChar(val + '0');
                }
                string new_op = "";
                new_op = Straight_permutation(op);
                string left_xored = XOR(new_op, left_plain_text);
                left_plain_text = left_xored;

                string temp = "";
                if (i != 15)
                {
                    temp = left_plain_text;
                    left_plain_text = right_plain_text;
                    right_plain_text = temp;
                }
            }

            string whole_plain_text = left_plain_text + right_plain_text;

            // 4- perform final permutation
            string final = "";
            for (int i = 0; i < 64; ++i)
            {
                final += whole_plain_text[final_permutation[i] - 1];
            }
            final = ToHex(final);
            return ("0x" + final);
        }

        public static string XOR(string s1, string s2)
        {
            string xored = "";
            int len = s1.Length;
            for (int i = 0; i < len; ++i)
            {
                if (s1[i].Equals(s2[i])) xored += "0";
                else xored += "1";
            }
            return xored;
        }
        public static string Right_expansion(string s)
        {
            string new_s = "";
            for (int i = 0; i < 48; ++i)
            {
                new_s += s[expansion_d_box[i] - 1];
            }
            return new_s;
        }

        public static string Straight_permutation(string s)
        {
            int[] straight_per = new int[] {16, 7, 20, 21,
                                         29, 12, 28, 17,
                                         1, 15, 23, 26,
                                         5, 18, 31, 10,
                                         2, 8, 24, 14,
                                         32, 27, 3, 9,
                                         19, 13, 30, 6,
                                         22, 11, 4, 25};
            string new_s = "";
            for (int i = 0; i < 32; ++i)
            {
                new_s += s[straight_per[i] - 1];
            }
            return new_s;
        }
        public static void Key_operations(string key)
        {
            int len = key.Length;
            /// 1- permutate the key without parity
            int[] key_permutation = new int[] {57, 49, 41, 33, 25, 17, 9,
                                             1, 58, 50, 42, 34, 26, 18,
                                             10, 2, 59, 51, 43, 35, 27,
                                             19, 11, 3, 60, 52, 44, 36,
                                             63, 55, 47, 39, 31, 23, 15,
                                             7, 62, 54, 46, 38, 30, 22,
                                             14, 6, 61, 53, 45, 37, 29,
                                             21, 13, 5, 28, 20, 12, 4};

            string key_permutated = "";
            for (int i = 0; i < 56; ++i)
            {
                key_permutated += key[key_permutation[i] - 1];
            }

            // 2- split the key
            string left_key = key_permutated.Substring(0, 28);
            string right_key = key_permutated.Substring(28);

            // 3- shift left the keys based on this table, combine then permutate last time
            int[] shifts = new int[] { 1, 1, 2, 2,
                                       2, 2, 2, 2,
                                       1, 2, 2, 2,
                                       2, 2, 2, 1};
            for (int i = 0; i < 16; ++i)
            {
                left_key = Shift(shifts[i], left_key);
                right_key = Shift(shifts[i], right_key);

                string whole_key = left_key + right_key;
                string new_round_key = Last_key_permutation(whole_key);
                Round_keys_in_binary[i] = new_round_key;
                Round_keys_in_hex[i] = ToHex(new_round_key);
            }
        }
        public static string Shift(int num_of_shifts, string s)
        {
            string new_s = "";
            new_s = s.Substring(num_of_shifts);
            if (num_of_shifts == 1) new_s += s[0];
            else
            {
                new_s += s[0];
                new_s += s[1];
            }
            return new_s;
        }

        public static string Last_key_permutation(string key)
        {
            int[] key_permutation = new int[] {14, 17, 11, 24, 1, 5,
                                             3, 28, 15, 6, 21, 10,
                                             23, 19, 12, 4, 26, 8,
                                             16, 7, 27, 20, 13, 2,
                                             41, 52, 31, 37, 47, 55,
                                             30, 40, 51, 45, 33, 48,
                                             44, 49, 39, 56, 34, 53,
                                             46, 42, 50, 36, 29, 32};
            string key_permutated = "";
            for (int i = 0; i < 48; ++i)
            {
                key_permutated += key[key_permutation[i] - 1];
            }
            return key_permutated;
        }
    }
}
