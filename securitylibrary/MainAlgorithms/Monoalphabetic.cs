using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            char[] arr = new char[27];

            string ans = "";

            Dictionary<char, bool> mp = new Dictionary<char, bool>();
            
            for(int i = 0; i < plainText.Length; i++)
            {
                arr[plainText[i] - 'a'] = cipherText[i];

                if(!mp.ContainsKey(cipherText[i]))
                mp.Add(cipherText[i],true);

            }

            string notAssignedChar="";


            for(char c='a';c<='z';c++)
            {
                if (!mp.ContainsKey(c))
                    notAssignedChar += c;
                
            }
            
            for(int i = 0; i <26; i++)
            {
                if (arr[i] == '\0')
                {
                    arr[i] = notAssignedChar[notAssignedChar.Length - 1];
                    ans += notAssignedChar[notAssignedChar.Length - 1];
                    notAssignedChar = notAssignedChar.Remove(notAssignedChar.Length - 1,1);
                }
                else
                    ans += arr[i];
            }

            return ans;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();

            string ans = "";
            Dictionary<char, char> mp = new Dictionary<char, char>();

            char c = 'a';
            for(int i=0; i < key.Length; i++,c++)
            {
                mp.Add(key[i],c);
            }
            
            for (int i = 0; i < cipherText.Length; i++)
            {
                ans += mp[cipherText[i]];
            }

            return ans;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            key = key.ToLower();

            string ans = "";
            for(int i = 0; i < plainText.Length; i++)
            {
                ans += key[plainText[i]-'a'];   
            }

            return ans;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToLower();


            Tuple<int,char>[] arr = new Tuple<int,char>[26];

            for (int i = 0; i < 26; i++) arr[i] = new Tuple<int, char>(0,'0');
            for(int i = 0; i < cipher.Length; i++)
            {
                arr[cipher[i]-'a'] = new Tuple<int, char>(arr[cipher[i]-'a'].Item1 + 1,cipher[i]);
            }

            
            Array.Sort(arr);

            string mostFreq = "ETAOINSRHLDCUMFPGWYBVKXJQZ";
            mostFreq = mostFreq.ToLower();

            
            Dictionary<char, char> mp = new Dictionary<char, char>();
            for (int i = 25,j=0; i >= 0; i--,j++)
            {

                if (!mp.ContainsKey(arr[i].Item2))
                {
                    mp.Add(arr[i].Item2,mostFreq[j]);
                }
            }

            string ans = "";

            for(int i = 0; i < cipher.Length; i++)
            {
                ans += mp[cipher[i]];
            }
           
            return ans;
        }
    }
}
