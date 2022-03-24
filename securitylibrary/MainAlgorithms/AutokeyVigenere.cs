using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public char[,] implement_tableau()
        {
            char[,] tableau = new char[26, 26];
            int first_letter;
            for (int i = 0; i < 26; ++i)
            {
                first_letter = 65;
                first_letter += i;
                for (int j = 0; j < 26; ++j)
                {
                    tableau[i, j] = (char)(first_letter);
                    first_letter++;
                    if (first_letter >= 91)
                        first_letter = 65;
                    Console.Write(tableau[i, j]);
                }
                Console.WriteLine();
            }
            return tableau;
        }
        public string Analyse(string plainText, string cipherText)
        {
            int CipherText_len = cipherText.Length;
            int plain_text_len = plainText.Length;

            //implement the tableaux
            char[,] tableau = implement_tableau();

            // search in the tableau
            char[] key = new char[CipherText_len];

            for (int i = 0; i < CipherText_len; ++i)
            {
                int plain_text_letter = plainText[i] - 'a';
                for (int j = 0; j < 26; ++j)
                {
                    int tableau_int_value = (int)tableau[j, plain_text_letter];
                    int cipher_int_value = (int)cipherText[i];
                    if (tableau_int_value == cipher_int_value)
                    {
                        key[i] = Convert.ToChar(j + 65);
                        break;
                    }
                }
            }
            string return_string = new string(key).ToLower();
            string sub_of_plain = plainText.Substring(0, 3);
            int last_index_of_key = return_string.IndexOf(sub_of_plain);
            return_string = return_string.Substring(0, last_index_of_key);
            return return_string;
        }

        public string Decrypt(string cipherText, string key)
        {
            int CipherText_len = cipherText.Length;
            int key_len = key.Length;

            char[] new_key = key.ToCharArray();
            int key_pointer = 0;

            //Check if one word's length is smaller than the other and fill it
            if (CipherText_len > key_len)
            {
                new_key = new char[CipherText_len];

                for (int i = 0; i < key_len; ++i)
                {

                    new_key[key_pointer] = key[i];
                    key_pointer++;

                }
                Console.WriteLine(new_key);
            }


            //implement the tableaux
            char[,] tableau = implement_tableau();


            // search in the tableau
            cipherText = cipherText.ToUpper();
            char[] plain_text = new char[CipherText_len];

            int plain_text_pointer = 0;

            for (int i = 0; i < CipherText_len; ++i)
            {
                if (i >= key_len)
                {
                    new_key[i] = plain_text[plain_text_pointer];
                    new_key[i] = char.ToLower(new_key[i]);
                    plain_text_pointer++;
                }
                int key_letter = new_key[i] - 'a';
                for (int j = 0; j < 26; ++j)
                {
                    int tableau_int_value = (int)tableau[j, key_letter];
                    int cipher_int_value = (int)cipherText[i];
                    if (tableau_int_value == cipher_int_value)
                    {
                        plain_text[i] = Convert.ToChar(j + 65);
                        break;
                    }
                }
            }
            string return_string = new string(plain_text);
            return return_string;
        }

        public string Encrypt(string plainText, string key)
        {
            int plain_text_len = plainText.Length;
            int key_len = key.Length;
            char[] new_key = { };

            //Check if one word's length is smaller than the other and fill it
            if (plain_text_len > key_len)
            {
                new_key = new char[plain_text_len];
                int key_pointer = 0;
                int plain_text_pointer = 0;
                for (int i = 0; i < plain_text_len || key_pointer < plain_text_len; ++i)
                {
                    if (key_pointer >= key_len)
                    {
                        new_key[key_pointer] = plainText[plain_text_pointer];
                        key_pointer++;
                        plain_text_pointer++;
                        continue;
                    }
                    new_key[key_pointer] = key[i];
                    key_pointer++;

                }
            }

            //implement the tableaux
            char[,] tableau = implement_tableau();

            // search in the tableau
            char[] cipher_text = new char[plain_text_len];
            for (int i = 0; i < plain_text_len; ++i)
            {
                int plain_letter = plainText[i] - 'a';
                int key_letter = new_key[i] - 'a';
                cipher_text[i] = tableau[plain_letter, key_letter];
            }
            string return_string = new string(cipher_text);
            return return_string;
        }
    }
}
