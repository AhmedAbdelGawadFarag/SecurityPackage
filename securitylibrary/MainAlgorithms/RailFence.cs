using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            if (plainText.Length == 1) return 1;

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();


            for (int i = 2; i < plainText.Length; i++)
            {
                if (this.Encrypt(plainText, i) == cipherText) return i;
            }

            return 1;


        }

        public string Decrypt(string cipherText, int key)
        {
            List<string> ls = new List<string>();

            int sz = (cipherText.Length + key - 1) / key;
            ls.Add("");
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (ls[ls.Count - 1].Length == sz)
                    ls.Add("");

                ls[ls.Count - 1] += cipherText[i];

            }

            string ans = "";
            for (int i = 0; i < ls[0].Length; i++)
            {
                for (int j = 0; j < ls.Count; j++)
                {
                    if (ls[j].Length - 1 >= i)
                        ans += ls[j][i];
                }
            }

            return ans;

        }

        public string Encrypt(string plainText, int key)
        {
            List<string> ls = new List<string>();


            for (int i = 0, indx = 0; i < plainText.Length; i++, indx = (indx + 1) % key)
            {
                if (indx >= ls.Count) ls.Add("");//no string is added yet

                ls[indx] += plainText[i];

            }


            string ans = "";
            for (int i = 0; i < ls.Count; i++)
            {
                for (int j = 0; j < ls[i].Length; j++) ans += ls[i][j];
            }

            return ans;
        }
    }
}
