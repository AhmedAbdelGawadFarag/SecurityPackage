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
        string[,] invMixColumns = new string[4, 4] { { "0e", "0b", "0d", "09" }, { "09", "0e", "0b", "0d" }, { "0d", "09", "0e", "0b" }, { "0b", "0d", "09", "0e" } };
        string[,] invSBox;
        void buildCipherTextMatrix(string cipherText)
        {
            cipherText = cipherText.Substring(2);
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    state[i, j] = cipherText.Substring(0, 2);
                    cipherText = cipherText.Substring(2);
                }
            }
        }
        void invShiftRowsRight()
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
                    state[i, j] = temp[i, (((j - i) % 4) + 4) % 4];
                }
            }
        }
        void invbuildSBox()
        {
            invSBox = new string[16, 16] {
                { "52", "09", "6A", "D5", "30", "36", "A5", "38", "BF", "40", "A3", "9E", "81", "F3", "D7", "FB" },
                { "7C", "E3", "39", "82", "9B", "2F", "FF", "87", "34", "8E", "43", "44", "C4", "DE", "E9", "CB" },
                { "54", "7B", "94", "32", "A6", "C2", "23", "3D", "EE", "4C", "95", "0B", "42", "FA", "C3", "4E" },
                { "08", "2E", "A1", "66", "28", "D9", "24", "B2", "76", "5B", "A2", "49", "6D", "8B", "D1", "25" },
                { "72", "F8", "F6", "64", "86", "68", "98", "16", "D4", "A4", "5C", "CC", "5D", "65", "B6", "92" },
                { "6C", "70", "48", "50", "FD", "ED", "B9", "DA", "5E", "15", "46", "57", "A7", "8D", "9D", "84" },
                { "90", "D8", "AB", "00", "8C", "BC", "D3", "0A", "F7", "E4", "58", "05", "B8", "B3", "45", "06" },
                { "D0", "2C", "1E", "8F", "CA", "3F", "0F", "02", "C1", "AF", "BD", "03", "01", "13", "8A", "6B" },
                { "3A", "91", "11", "41", "4F", "67", "DC", "EA", "97", "F2", "CF", "CE", "F0", "B4", "E6", "73" },
                { "96", "AC", "74", "22", "E7", "AD", "35", "85", "E2", "F9", "37", "E8", "1C", "75", "DF", "6E" },
                { "47", "F1", "1A", "71", "1D", "29", "C5", "89", "6F", "B7", "62", "0E", "AA", "18", "BE", "1B" },
                { "FC", "56", "3E", "4B", "C6", "D2", "79", "20", "9A", "DB", "C0", "FE", "78", "CD", "5A", "F4" },
                { "1F", "DD", "A8", "33", "88", "07", "C7", "31", "B1", "12", "10", "59", "27", "80", "EC", "5F" },
                { "60", "51", "7F", "A9", "19", "B5", "4A", "0D", "2D", "E5", "7A", "9F", "93", "C9", "9C", "EF" },
                { "A0", "E0", "3B", "4D", "AE", "2A", "F5", "B0", "C8", "EB", "BB", "3C", "83", "53", "99", "61" },
                { "17", "2B", "04", "7E", "BA", "77", "D6", "26", "E1", "69", "14", "63", "55", "21", "0C", "7D" }
    };
        }
        void invsBoxSubistitution(ref string[,] inputMatrix, int numberofrows, int numberofcols)
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
                    inputMatrix[i, j] = invSBox[row, col];
                }
            }
        }
        void invbuildKeySchedule(string key)
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
        string[,] ETable;
        void buildETable()
        {
            ETable = new string[16, 16]
            {
        { "01", "03", "05", "0F", "11", "33", "55", "FF", "1A", "2E", "72", "96", "A1", "F8", "13", "35"},
        { "5F", "E1", "38", "48", "D8", "73", "95", "A4", "F7", "02", "06", "0A", "1E", "22", "66", "AA"},
        { "E5", "34", "5C", "E4", "37", "59", "EB", "26", "6A", "BE", "D9", "70", "90", "AB", "E6", "31"},
        { "53", "F5", "04", "0C", "14", "3C", "44", "CC", "4F", "D1", "68", "B8", "D3", "6E", "B2", "CD"},
        { "4C", "D4", "67", "A9", "E0", "3B", "4D", "D7", "62", "A6", "F1", "08", "18", "28", "78", "88"},
        { "83", "9E", "B9", "D0", "6B", "BD", "DC", "7F", "81", "98", "B3", "CE", "49", "DB", "76", "9A"},
        { "B5", "C4", "57", "F9", "10", "30", "50", "F0", "0B", "1D", "27", "69", "BB", "D6", "61", "A3"},
        { "FE", "19", "2B", "7D", "87", "92", "AD", "EC", "2F", "71", "93", "AE", "E9", "20", "60", "A0"},
        { "FB", "16", "3A", "4E", "D2", "6D", "B7", "C2", "5D", "E7", "32", "56", "FA", "15", "3F", "41"},
        { "C3", "5E", "E2", "3D", "47", "C9", "40", "C0", "5B", "ED", "2C", "74", "9C", "BF", "DA", "75"},
        { "9F", "BA", "D5", "64", "AC", "EF", "2A", "7E", "82", "9D", "BC", "DF", "7A", "8E", "89", "80"},
        { "9B", "B6", "C1", "58", "E8", "23", "65", "AF", "EA", "25", "6F", "B1", "C8", "43", "C5", "54"},
        { "FC", "1F", "21", "63", "A5", "F4", "07", "09", "1B", "2D", "77", "99", "B0", "CB", "46", "CA" },
        { "45", "CF", "4A", "DE", "79", "8B", "86", "91", "A8", "E3", "3E", "42", "C6", "51", "F3", "0E"},
        { "12", "36", "5A", "EE", "29", "7B", "8D", "8C", "8F", "8A", "85", "94", "A7", "F2", "0D", "17"},
        { "39", "4B", "DD", "7C", "84", "97", "A2", "FD", "1C", "24", "6C", "B4", "C7", "52", "F6", "01"}
            };
        }
        string[,] LTable;
        void buildLTable()
        {
            LTable = new string[16, 16]
            {
        { "","00", "19", "01", "32", "02", "1A", "C6", "4B", "C7", "1B", "68", "33", "EE", "DF", "03"},
        { "64", "04", "E0", "0E", "34", "8D", "81", "EF", "4C", "71", "08", "C8", "F8", "69", "1C", "C1"},
        { "7D", "C2", "1D", "B5", "F9", "B9", "27", "6A", "4D", "E4", "A6", "72", "9A", "C9", "09", "78"},
        { "65", "2F", "8A", "05", "21", "0F", "E1", "24", "12", "F0", "82", "45", "35", "93", "DA", "8E"},
        { "96", "8F", "DB", "BD", "36", "D0", "CE", "94", "13", "5C", "D2", "F1", "40", "46", "83", "38"},
        { "66", "DD", "FD", "30", "BF", "06", "8B", "62", "B3", "25", "E2", "98", "22", "88", "91", "10"},
        { "7E", "6E", "48", "C3", "A3", "B6", "1E", "42", "3A", "6B", "28", "54", "FA", "85", "3D", "BA"},
        { "2B", "79", "0A", "15", "9B", "9F", "5E", "CA", "4E", "D4", "AC", "E5", "F3", "73", "A7", "57"},
        { "AF", "58", "A8", "50", "F4", "EA", "D6", "74", "4F", "AE", "E9", "D5", "E7", "E6", "AD", "E8"},
        { "2C", "D7", "75", "7A", "EB", "16", "0B", "F5", "59", "CB", "5F", "B0", "9C", "A9", "51", "A0" },
        { "7F", "0C", "F6", "6F", "17", "C4", "49", "EC", "D8", "43", "1F", "2D", "A4", "76", "7B", "B7"},
        { "CC", "BB", "3E", "5A", "FB", "60", "B1", "86", "3B", "52", "A1", "6C", "AA", "55", "29", "9D"},
        { "97", "B2", "87", "90", "61", "BE", "DC", "FC", "BC", "95", "CF", "CD", "37", "3F", "5B", "D1"},
        { "53", "39", "84", "3C", "41", "A2", "6D", "47", "14", "2A", "9E", "5D", "56", "F2", "D3", "AB"},
        { "44", "11", "92", "D9", "23", "20", "2E", "89", "B4", "7C", "B8", "26", "77", "99", "E3", "A5"},
        { "67", "4A", "ED", "DE", "C5", "31", "FE", "18", "0D", "63", "8C", "80", "C0", "F7", "70", "07"}
            };
        }
        string multiplyForInverseMixColumns(string A, string B)
        {
            buildETable();
            buildLTable();
            if (A.Length < 2) A = "0" + A;
            if (B.Length < 2) B = "0" + B;
            if (A == "00" || B == "00") return "00";
            int row1 = Convert.ToInt32(A.Substring(0, 1), 16);
            int col1 = Convert.ToInt32(A.Substring(1, 1), 16);

            int row2 = Convert.ToInt32(B.Substring(0, 1), 16);
            int col2 = Convert.ToInt32(B.Substring(1, 1), 16);

            int sum = Convert.ToInt32(LTable[row1, col1], 16) + Convert.ToInt32(LTable[row2, col2], 16);
            if (sum > Convert.ToInt32("FF", 16))
            {
                sum = sum - Convert.ToInt32("FF", 16);
            }

            string ans = sum.ToString("X2");
            int row = Convert.ToInt32(ans.Substring(0, 1), 16);
            int col = Convert.ToInt32(ans.Substring(1, 1), 16);
            return ETable[row, col];
        }
        void invmixColumnsOperation()
        {
            for (int col = 0; col < 4; col++)
            {
                string[,] tempState = new string[4, 1];
                for (int i = 0; i < 4; i++)
                {
                    tempState[i, 0] = state[i, col];
                }

                string[,] tempColMixMatrix = new string[4, 1];

                for (int i = 0; i < 4; i++)
                {
                    for (int z = 0; z < 4; z++)
                    {
                        tempColMixMatrix[z, 0] = invMixColumns[i, z];
                    }
                    string temp = "";
                    for (int j = 0; j < 4; j++)
                    {
                        string ans = multiplyForInverseMixColumns(tempColMixMatrix[j, 0], tempState[j, 0]);
                        // convert temp and ans to binary
                        //temp = Convert.ToString(Convert.ToInt32(temp, 16), 2).PadLeft(8, '0');
                        ans = Convert.ToString(Convert.ToInt32(ans, 16), 2).PadLeft(8, '0');
                        temp = XOR(temp, ans);
                    }
                    //Console.WriteLine($"{i}, {col}");
                    state[i, col] = Convert.ToString(Convert.ToInt32(temp, 2), 16);
                    //Console.WriteLine(state[i, col]);
                }
            }
        }


        public override string Decrypt(string cipherText, string key)
        {
            numberOfRounds = 10;
            buildSBox();
            invbuildSBox();
            buildRconMatrix();
            invbuildKeySchedule(key);
            buildCipherTextMatrix(cipherText);
            addRoundKey(numberOfRounds);
            numberOfRounds--;
            invShiftRowsRight();
            invsBoxSubistitution(ref state, 4, 4);
            for (int i = numberOfRounds; i > 0; i--)
            {
                addRoundKey(i);
                invmixColumnsOperation();
                invShiftRowsRight();
                invsBoxSubistitution(ref state, 4, 4);
            }

            addRoundKey(0);
            string output = "";
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (state[j, i].Length < 2)
                    {
                        state[j, i] = "0" + state[j, i];
                    }
                    output += state[j, i];
                }
            }
            Console.WriteLine("0x" + output);
            return "0x"+output;
            //throw new NotImplementedException();
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
