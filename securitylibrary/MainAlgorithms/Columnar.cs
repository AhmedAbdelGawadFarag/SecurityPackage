using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public void getPermutation(int indx,List<int> ans, ref List<List<int>> fans,int count,ref Dictionary<int,bool> dt)
        {
            if(indx == count)
            {
                fans.Add(new List<int>());
                for (int i = 0; i < ans.Count; i++)
                {
                  
                    fans[fans.Count - 1].Add(ans[i]);
                }
               
                return;
            }
            for (int i = 1; i <= count; i++)
            {
                if (!dt[i])
                {
                    ans.Add(i);
                    dt[i] = true;
                    getPermutation(indx + 1, ans,ref fans,count,ref dt);
                    dt[i] = false;
                    ans.RemoveAt(ans.Count - 1);
                }
            }
            return;
        }
        public List<List<int>> getPermutation(int count)
        {
            Dictionary<int, bool> dt = new Dictionary<int, bool>();

            for (int i = 0; i < 10; i++) dt.Add(i, false);

            List<List<int>> ans = new List<List<int>>();

            getPermutation(0, new List<int>(),ref ans, count, ref dt);


            return ans;

        }
        

        public List<int> Analyse(string plainText, string cipherText)
        {
           

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            List<int> temp = new List<int>();

            for (int i = 1; i <= 7; i++)
            {
                temp.Add(i);
                List<List<int>> ans = getPermutation(i);
                foreach (List<int> ls in ans) {
                
                    string dd = (this.Encrypt(plainText,ls));
                    if (cipherText == dd) return ls;
                  }
            }


            return temp;

        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int n = (cipherText.Length + key.Count - 1) / key.Count;
            int m = key.Count;

            char[,] arr = new char[n, m];

            Dictionary<int, int> dt = new Dictionary<int, int>();

            for (int i = 0; i < key.Count; i++)
            {
                dt.Add(key[i], i);
            }


            for (int i = 1,strindx=0; i <= key.Count; i++)
            {
                for (int j = 0; j < n && strindx < cipherText.Length; j++, strindx++)
                {
                    arr[j, dt[i]] = cipherText[strindx];
                }
            }

            StringBuilder ans = new StringBuilder();

            for(int i = 0; i < n; i++)
            {
                for(int j = 0; j < m; j++)
                {
                  
                    ans.Append(arr[i,j]);
                }
                
            }

            return ans.ToString();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int n = (plainText.Length + key.Count - 1)  / key.Count;
            int m = key.Count;

            char[,] arr = new char[n,m];

            Dictionary<int, int> dt = new Dictionary<int, int>();

            for(int i = 0; i < key.Count; i++)
            {
                dt.Add(key[i],i);
            }

            for(int i = 0,row=0,column=0; i < plainText.Length; i++)
            {
                if (column == m)
                {
                    row++;
                    column = 0;
                }

                arr[row,column] = plainText[i];

                column++;
            }

            StringBuilder ans = new StringBuilder();
            
            for(int i = 1; i <= key.Count; i++)
            {
                for(int j=0;j<n;j++)
                    ans.Append(arr[j,dt[i]]);   
            }

            return ans.ToString();
        }
    }
}
