using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public int getMod(int a,int md)
        {
            return ((a % md) + md) % md;
        }
        public string Encrypt(string plainText, int key)
        {
            string d = "abcdefghijklmnopqrstuvwxyz";
            plainText = plainText.ToLower();

            string ans="";

            for(int i = 0; i < plainText.Length; i++)
            {
                int nindx = getMod((plainText[i]-'a')+key,26);
                ans += d[nindx];
            }

            return ans;
            
        }

        public string Decrypt(string cipherText, int key)
        {
            string d = "abcdefghijklmnopqrstuvwxyz";
            cipherText = cipherText.ToLower();

            string ans = "";
            for(int i = 0; i < cipherText.Length; i++)
            {
                int  nindx = getMod( (cipherText[i]-'a') - key ,26);
                ans += d[nindx];
            }

            return ans;

        }

        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            int k = getMod(cipherText[0]-plainText[0],26);
            return k;
        }
    }
}
