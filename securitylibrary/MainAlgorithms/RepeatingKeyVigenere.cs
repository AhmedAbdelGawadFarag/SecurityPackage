using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
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
            string return_string = new string(key);
            string first_letters_of_key = return_string.Substring(0, 3);
            int first_repeated_substring = return_string.IndexOf(first_letters_of_key, 3);
            return_string = return_string.Substring(0, first_repeated_substring);
            return return_string;
        }

        public string Decrypt(string cipherText, string key)
        {
            int CipherText_len = cipherText.Length;
            int key_len = key.Length;

            char[] new_CipherText = { };
            char[] new_key = { };

            //Check if one word's length is smaller than the other and fill it
            if (CipherText_len > key_len)
            {
                new_key = new char[CipherText_len];
                int key_pointer = 0;
                new_CipherText = cipherText.ToCharArray();
                for (int i = 0; i < CipherText_len; ++i)
                {

                    new_key[i] = key[key_pointer];
                    key_pointer++;
                    if (key_pointer == key_len)
                        key_pointer = 0;
                }
            }
            

            string s = new string(new_CipherText);
            //get the new size
            int new_size = new_CipherText.Length;

            //implement the tableaux
            char[,] tableau = implement_tableau();

            // search in the tableau
            char[] plain_text = new char[new_size];

            for (int i = 0; i < new_size; ++i)
            {
                int key_letter = new_key[i] - 'a';
                for (int j = 0; j < 26; ++j)
                {
                    int tableau_int_value = (int)tableau[j, key_letter];
                    int cipher_int_value = (int)new_CipherText[i];
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

            int plainText_len = plainText.Length;
            int key_len = key.Length;

            char[] new_plainText = { };
            char[] new_key = { };

            //Check if one word's length is smaller than the other and fill it
            if (plainText_len > key_len)
            {
                new_key = new char[plainText_len];
                int key_pointer = 0;
                new_plainText = plainText.ToCharArray();
                for (int i = 0; i < plainText_len; ++i)
                {

                    new_key[i] = key[key_pointer];
                    key_pointer++;
                    if (key_pointer == key_len)
                        key_pointer = 0;
                }
            }
            

            string s = new string(new_plainText);
            //get the new size
            int new_size = new_plainText.Length;

            //implement the tableaux
            char[,] tableau = implement_tableau();

            // search in the tableau
            char[] cipher_text = new char[new_size];
            for (int i = 0; i < new_size; ++i)
            {
                int plain_letter = new_plainText[i] - 'a';
                int key_letter = new_key[i] - 'a';
                cipher_text[i] = tableau[plain_letter, key_letter];
            }
            string return_string = new string(cipher_text);
            Console.WriteLine(return_string);

            return return_string;
        }
    }
}