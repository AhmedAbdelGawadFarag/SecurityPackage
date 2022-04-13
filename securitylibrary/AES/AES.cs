using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    /// 

    public class AES : CryptographicTechnique
    {
        string[] Rcon;
        int numberOfRounds = 10;
        string[,] keySchedule = new string[4, 44];
        string[,] state = new string[4, 4];
        string[,] sBox;
        string[,] mixColumns = new string[4, 4] { { "02", "03", "01", "01" }, { "01", "02", "03", "01" }, { "01", "01", "02", "03" }, { "03", "01", "01", "02" } };
        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        string XOR(string A, string B)
        {
            if (A == "") return B;
            char[] output = new char[8];
            for (int i = 0; i < A.Length; i++)
            {
                if (A.Substring(i, 1) == B.Substring(i, 1)) output[i] = '0';
                else output[i] = '1';
            }
            return new string(output);
        }
        string multiplyBy02(string input, bool Converted = true)
        {
            string binary = "";
            if (!Converted) binary = Convert.ToString(Convert.ToInt32(input, 16), 2).PadLeft(8, '0');
            else binary = input;

            string output;
            if (binary.Substring(0, 1) == "1")
            {
                binary = binary.Remove(0, 1);
                binary = binary + "0";
                output = XOR(binary, "00011011");
            }
            else
            {
                binary = binary.Remove(0, 1);
                binary = binary + "0";
                output = binary;
            }
            return output;
        }
        string multiplyBy03(string input)
        {
            string binary = Convert.ToString(Convert.ToInt32(input, 16), 2).PadLeft(8, '0');
            string output = multiplyBy02(binary, true);
            output = XOR(output, binary);
            return output;
        }
        void mixColumnsOperation()
        {
            for (int col = 0; col < 4; col++)
            {
                string[,] tempState = new string[4, 1];
                for (int i = 0; i < 4; i++)
                {
                    tempState[i, 0] = state[i, col];
                }

                string[,] tempColMixMatrix = new string[4, 1];
                /* for(int i = 0; i < 4; i++)
                 {
                     tempColMixMatrix[i, 0] = mixColumns[col, i ];
                 }*/
                for (int i = 0; i < 4; i++)
                {
                    for (int z = 0; z < 4; z++)
                    {
                        tempColMixMatrix[z, 0] = mixColumns[i, z];
                    }
                    string temp = "";
                    for (int j = 0; j < 4; j++)
                    {
                        if (tempColMixMatrix[j, 0] == "02") temp = XOR(temp, multiplyBy02(tempState[j, 0], false));
                        else if (tempColMixMatrix[j, 0] == "03") temp = XOR(temp, multiplyBy03(tempState[j, 0]));
                        else temp = XOR(temp, Convert.ToString(Convert.ToInt32(tempState[j, 0], 16), 2).PadLeft(8, '0'));

                        //Console.WriteLine(temp);
                    }
                    //Console.WriteLine($"{i}, {col}");
                    state[i, col] = Convert.ToString(Convert.ToInt32(temp, 2), 16);
                    //Console.WriteLine(state[i, col]);
                }
            }
        }
        void buildRconMatrix()
        {
            // build Rcon matrix
            Rcon = new string[11];
            Rcon[0] = "01";
            Rcon[1] = "02";
            Rcon[2] = "04";
            Rcon[3] = "08";
            Rcon[4] = "10";
            Rcon[5] = "20";
            Rcon[6] = "40";
            Rcon[7] = "80";
            Rcon[8] = "1b";
            Rcon[9] = "36";
            Rcon[10] = "6c";

        } // done
        void sBoxSubistitution(ref string[,] inputMatrix, int numberofrows, int numberofcols)
        {
            for (int i = 0; i < numberofrows; i++)
            {
                for (int j = 0; j < numberofcols; j++)
                {
                    string cell = inputMatrix[i, j];
                    if (cell.Length == 1)
                    {
                        cell = "0" + cell;
                    }
                    int row = Convert.ToInt32(cell.Substring(0, 1), 16);
                    int col = Convert.ToInt32(cell.Substring(1, 1), 16);
                    inputMatrix[i, j] = sBox[row, col];
                }
            }
        } // done
        void buildKeySchedule(string key)
        {
            // remove 0x, initial Round
            // first 4 columns of key Schedule
            key = key.Substring(2);
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    keySchedule[i, j] = key.Substring(0, 2);
                    key = key.Substring(2);
                }
            }
            int round = 1;
            for (int col = 4; col < 44; col++)
            {
                // first column of key schedule
                if (col % 4 == 0)
                {
                    string[,] temp = new string[4, 1];
                    for (int i = 0; i < 4; i++)
                    {
                        temp[i, 0] = keySchedule[i, col - 1];
                    }
                    // shift temp
                    string tempValue = temp[0, 0];
                    for (int i = 0; i < 3; i++)
                    {
                        temp[i, 0] = temp[i + 1, 0];
                    }
                    temp[3, 0] = tempValue;
                    // subsistute with SBox
                    sBoxSubistitution(ref temp, 4, 1);
                    // XOR with Rcon
                    //Console.WriteLine(Rcon[round-1]);
                    temp[0, 0] = Convert.ToString(Convert.ToInt32(temp[0, 0], 16) ^ Convert.ToInt32(Rcon[round - 1], 16), 16);
                    round++;
                    // add to keySchedule
                    for (int i = 0; i < 4; i++)
                    {
                        keySchedule[i, col] = Convert.ToString(Convert.ToInt32(keySchedule[i, col - 4], 16) ^ Convert.ToInt32(temp[i, 0], 16), 16);
                    }
                }
                else
                {
                    for (int i = 0; i < 4; i++)
                    {
                        keySchedule[i, col] = Convert.ToString(Convert.ToInt32(keySchedule[i, col - 1], 16) ^ Convert.ToInt32(keySchedule[i, col - 4], 16), 16);
                    }
                }
            }
        } // done
        void printState()
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    Console.Write(state[i, j] + " ");
                }
                Console.WriteLine();

            }
            Console.WriteLine();
        } // done
        void buildPlainTextMatrix(string plainText)
        {
            // remove 0x
            plainText = plainText.Substring(2);
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    state[i, j] = plainText.Substring(0, 2);
                    plainText = plainText.Substring(2);
                }
            }
        } // done
        void buildSBox()
        {
            sBox = new string[16, 16] {
                { "63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76" },
                { "CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0" },
                { "B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15" },
                { "04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75" },
                { "09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84" },
                { "53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF" },
                { "D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8" },
                { "51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2" },
                { "CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73" },
                { "60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB" },
                { "E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79" },
                { "E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08" },
                { "BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A" },
                { "70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E" },
                { "E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF" },
                { "8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16" }
            };
        } // done
        void shiftRowsLeft()
        {
            // shift state matrix rows 
            string[,] temp = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    temp[i, j] = state[i, j];
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[i, j] = temp[i, (j + i) % 4];
                }
            }
        } // done
        void addRoundKey(int round)
        {
            // add round key

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    state[i, j] = Convert.ToString(Convert.ToInt32(state[i, j], 16) ^ Convert.ToInt32(keySchedule[i, j + round * 4], 16), 16);
                    //Console.Write(j + round * 4);
                }
            }
            //printState();
        }
        public override string Encrypt(string plainText, string key)
        {
            numberOfRounds = 10;
            buildSBox();
            buildRconMatrix();
            buildKeySchedule(key);
            buildPlainTextMatrix(plainText);
            addRoundKey(0);

            for (int round = 1; round <= 9; round++)
            {
                sBoxSubistitution(ref state, 4, 4);
                shiftRowsLeft();
                mixColumnsOperation();
                addRoundKey(round);
            }
            sBoxSubistitution(ref state, 4, 4);
            shiftRowsLeft();
            addRoundKey(10);
            //printState();
            string cipherText = "";
            for (int i = 0; i < 4; i++)
            {
                for(int j = 0; j < 4; j++)
                {
                    if (state[j, i].Length < 2)
                    {
                        state[j, i] = "0" + state[j, i];
                    }
                    cipherText += state[j, i].ToUpper();
                }
            }
            return "0x" + cipherText;
        }
    }
}
