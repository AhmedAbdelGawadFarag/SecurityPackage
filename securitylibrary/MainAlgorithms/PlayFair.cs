using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
         

            cipherText = cipherText.ToLower();
            key = key.ToLower();

          

            char[,] arr = new char[5, 5];

            fillArr(ref arr, key);

            Dictionary<char, Tuple<int, int>> mp = new Dictionary<char, Tuple<int, int>>();


            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    mp.Add(arr[i, j], new Tuple<int, int>(i, j));
                    Console.Write(arr[i, j]);
                    Console.Write(" ");
                }
                Console.WriteLine();
            }

            mp['j'] = mp['i'];

            string ans = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
              
                        ans += getCorrsponding(mp[cipherText[i]], mp[cipherText[i + 1]], arr,false);
                        i++;  
            }

           
            if (ans[ans.Length - 1] == 'x')
            {    
                ans = ans.Remove(ans.Length - 1, 1);
            }
           
            string dd = "";



            for (int i = 0; i < ans.Length; i++)
            {
                if (i + 1 < ans.Length && i - 1 >= 0 && ans[i] == 'x' && ans[i - 1] == ans[i + 1])
                {
                    if ((i - 1) % 2 == 0 && (i + 1) % 2 == 0) continue;
                }
                dd += ans[i];

            }

            return dd;


        }
        void fillArr(ref char [,]arr,string key)
        {
            bool[] doExist = new bool[26];

            string uniqueChar = "";

            for (int i = 0; i < key.Length; i++)
            {
                if (!doExist[key[i] - 'a'])
                {
                    uniqueChar += key[i];
                }
                doExist[key[i] - 'a'] = true;
            }


            for (int i = 0, strindx = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (strindx < uniqueChar.Length)
                    {
                        arr[i, j] = uniqueChar[strindx];
                        strindx++;
                    }
                  
                }
            }
            for(int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (arr[i, j] == '\0')
                    {
                        for (char c = 'a'; c <= 'z'; c++)
                        {
                            if (!doExist[c-'a']&&c!='j')
                            {
                                arr[i, j] = c;
                                doExist[c-'a'] = true;
                                break;
                            }

                        }

                    }
                }
            }
            

        }
         int getIndx(int indx,int add)
        {
            if (indx + add >= 5) return 0;
            if (indx + add < 0) return 4;
            return indx + add;
        }
        string getCorrsponding(Tuple<int,int> p1,Tuple<int,int> p2,char [,]mp,bool enc)
        {
            string ans="";

            int add = (enc == true) ? 1 : -1;

            if(p1.Item1 == p2.Item1)//same row
            {

                int col1 = getIndx(p1.Item2,add);
                int col2 = getIndx(p2.Item2, add);

                ans += mp[p1.Item1,col1];
                ans += mp[p2.Item1,col2];

            }else if (p1.Item2 == p2.Item2)//same colmn
            {
                int row1 = getIndx(p1.Item1, add);
                int row2 = getIndx(p2.Item1, add);

                ans += mp[row1,p1.Item2];
                ans += mp[row2,p2.Item2];
            }
            else
            {
                ans += mp[p1.Item1,p2.Item2];
                ans += mp[p2.Item1,p1.Item2];
            }

            return ans;
        }
        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            key = key.ToLower();

            char[,] arr = new char[5, 5];

            fillArr(ref arr,key);

            Dictionary<char, Tuple<int, int>> mp = new Dictionary<char, Tuple<int, int>>();
            

            for(int i = 0; i < 5; i++)
            {
                for(int j = 0; j < 5; j++)
                {
                    mp.Add(arr[i, j], new Tuple<int, int>(i,j));
                }
            }

            mp['j'] = mp['i'];

            string ans="";
            for(int i = 0; i < plainText.Length; i++)
            {
                if (i + 1 >= plainText.Length)
                {
                    ans += getCorrsponding(mp[plainText[i]], mp['x'], arr,true);
                }
                else
                {
                    if (plainText[i] != plainText[i + 1])
                    {
                        ans += getCorrsponding(mp[plainText[i]], mp[plainText[i+1]], arr,true);
                        i++;
                    }
                    else
                    {
                        ans += getCorrsponding(mp[plainText[i]], mp['x'], arr,true);
                    }
                }
            }


            return ans;

        }
    }
}
