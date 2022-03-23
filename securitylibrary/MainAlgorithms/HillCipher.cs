using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<List<int>> PT = InitMatrix(2, 2);
            List<List<int>> CT = InitMatrix(2, 2);

            int indx = 0;
            for(int i = 0; i < 2; ++i)
            {
                for(int j = 0; j < 2; ++j)
                {
                    PT[i][j] = plainText[indx];
                    CT[i][j] = cipherText[indx];
                    indx++;

                }
            }

           for(int r1c1 = 0; r1c1 <= 25; ++r1c1)
            {
                for(int r1c2 = 0; r1c2 <= 25; ++r1c2)
                {
                    for(int r2c1 = 0; r2c1 <= 25; ++r2c1)
                    {
                        for(int r2c2 = 0; r2c2 <= 25; ++r2c2)
                        {
                            List<List<int>> Key = InitMatrix(2,2);
                            Key[0][0] = r1c1; Key[0][1] = r1c2;
                            Key[1][0] = r2c1; Key[1][1] = r2c2;
                            if(IsCorrectKey(plainText, cipherText, Key))
                            {
                                return FlattenMatrix(Key);
                            }
                           
                        }
                    }
                }
            }
            throw new InvalidAnlysisException();

        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        { 
            int size = (int)Math.Sqrt(key.Count);
            List<int> res = new List<int>();
            List<List<int>> Key = CreateKeyMatrix(key);

            if (!IsValidKey(Key))
                throw new InvalidAnlysisException();

            List<List<int>> InvKey = GetMatInv(Key);

            for (int i = 0; i < cipherText.Count; i += size)
            {
                List<List<int>> CT = InitMatrix(size, 1);
                for (int j = i; j < i + size; ++j)
                    CT[j-i][0] = cipherText[j];
                
                List<List<int> > PT = MulMatrix(InvKey, CT);

                List<int> flatPT = FlattenMatrix(PT);
                foreach (int c in flatPT)
                    res.Add(c);
            }
            return res;
      
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
         
            int len = (int)Math.Sqrt(key.Count);
            List<int> res = new List<int>();
            List<List<int>> K = CreateKeyMatrix(key);

            if (!IsValidKey(K))
                throw new InvalidAnlysisException();

            for (int i = 0; i < plainText.Count; i += len)
            {
               List<List<int> > PT = InitMatrix(len,1);
                for (int j = i; j < i + len; ++j)
                    PT[j-i][0] = plainText[j];

                List<List<int> > CT = MulMatrix(K, PT);

                List<int> flatCT = FlattenMatrix(CT);
                foreach (int c in flatCT)
                    res.Add(c);
                
            }
            return res;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {

            List<List<int>> PT = InitMatrix(3,3);
            List<List<int>> CT = InitMatrix(3,3);
           
            int indx = 0;
            for(int i = 0; i < 3; ++i)
            {
                for(int j = 0; j < 3; ++j)
                {
                    PT[j][i] = plainText[indx];
                    CT[j][i] = cipherText[indx];
                    indx++;

                }
            }
            List<List<int>> InvPT = GetMatInv(PT);
            List<List<int> > Key = MulMatrix(CT, InvPT);

            if (!IsValidKey(Key))
                throw new InvalidAnlysisException();

            List<int> flatKey = FlattenMatrix(Key);
            return flatKey;

        }

        // Strings 
        public string Analyse(string plainText, string cipherText)
        {
            List<int> PT = StringToList(plainText.ToUpper());
            List<int> CT = StringToList(cipherText.ToUpper());
            List<int> Key = Analyse(PT, CT);
            string txtKey = ListToString(Key);
            return txtKey;
        }


        public string Decrypt(string cipherText, string key)
        {
            List<int> CT = StringToList(cipherText.ToUpper());
            List<int> Key = StringToList(key.ToUpper());
            List<int> PT = Decrypt(CT, Key);
            string txtPT = ListToString(PT);
            return txtPT;
        }



        public string Encrypt(string plainText, string key)
        {
            List<int> PT = StringToList(plainText.ToUpper());
            foreach(var x in PT)
            {
                Console.Write(x);
                Console.Write(' ');
            }
            Console.WriteLine();
            List<int> Key = StringToList(key.ToUpper());
            List<int> CT = Encrypt(PT, Key);
            string txtCT = ListToString(CT);
            return txtCT;
        }



        public string Analyse3By3Key(string plainText, string cipherText)
        {
            List<int> PT = StringToList(plainText.ToUpper());
            List<int> CT = StringToList(cipherText.ToUpper());
            List<int> Key = Analyse3By3Key(PT, CT);
            string txtKey = ListToString(Key);
            return txtKey;
        }

        bool IsCorrectKey(List<int> plainText, List<int> cipherText, List<List<int>> Key)
        {

            if (!IsValidKey(Key))
                return false;
            List<int> res = new List<int>();
            int len = 2;

            for (int i = 0; i < plainText.Count; i += len)
            {
                List<List<int>> PT = InitMatrix(len, 1);
                for (int j = i; j < i + len; ++j)
                    PT[j - i][0] = plainText[j];

                List<List<int>> CT = MulMatrix(Key, PT);

                List<int> flatCT = FlattenMatrix(CT);
                foreach (int c in flatCT)
                    res.Add(c);

            }
            return IsEqual(res, cipherText);
        }
        bool IsEqual(List<int> a, List<int> b)
        {
            for(int i = 0; i < a.Count; ++i)
            {
                if (a[i] != b[i])
                    return false;
            }
            return true;
        }
        private List< List<int> > CreateKeyMatrix (List<int> key)
        {
            int len = (int)Math.Sqrt(key.Count);

            List<List<int>> matrix = new List<List<int>>();
            List<int> row = new List<int>();
            
            for(int i = 0; i < key.Count; ++i)
            {
                row.Add(key[i]);
                if((i + 1) % len == 0)
                {
                    matrix.Add(row);
                    row = new List<int>();
                }
            }
            return matrix;
        }
        private List<List<int> >  MulMatrix(List<List<int>> K, List<List<int> >  PT)
        {
            List<List<int>> res = InitMatrix(K[0].Count, PT[0].Count);
            
            for(int i = 0; i < K.Count; ++i)
            {
                for(int j = 0; j < PT[0].Count; ++j)
                {
                    for(int u = 0; u < K.Count; ++u)
                    {
                        
                            res[i][j] = AddInt(res[i][j], MulInt(K[i][u], PT[u][j]));
                    }
                }
            }
            return res;
        }
        private int GetMatDet(List<List<int>> Key)
        {
            int det = 0;
            if(Key.Count == 2)
            {
                det = SubInt(MulInt(Key[0][0], Key[1][1]), MulInt(Key[0][1], Key[1][0]));
            }
            else
            {
                int d1 = SubInt(MulInt(Key[1][1], Key[2][2]), MulInt(Key[2][1], Key[1][2]));
                int d2 = SubInt(MulInt(Key[1][0], Key[2][2]), MulInt(Key[2][0], Key[1][2]));
                int d3 = SubInt(MulInt(Key[1][0], Key[2][1]), MulInt(Key[2][0], Key[1][1]));
                det = SubInt(AddInt(Key[0][0] * d1, Key[0][2] * d3), Key[0][1] * d2);
                
           
            }
            return det;
        }
        private List<List<int>> GetMatInv(List<List<int> > Key)
        {
            int size = Key.Count;
     
            List<List<int>> InvKey = InitMatrix(size, size);

            if (size == 2)
            {
                int det = GetMatDet(Key);
                int mulInv = GetMulInv(det);
                for(int i = 0; i < size; ++i)
                {
                    for(int j = 0; j < size; ++j)
                    {
                        InvKey[i][j] = MulInt(mulInv, Key[i][j]);
                    }
                }
                
            }
            else
            {

                int det = GetMatDet(Key);
                int mulInv = GetMulInv(det);
                for (int i = 0; i < size; ++i)
                {
                    for (int j = 0; j < size; ++j)
                    {
                        InvKey[i][j] = MulInt(MulInt(mulInv, (int)Math.Pow(-1, i + j)), GetDet(Key, i, j));
                        InvKey[i][j] += 26;
                        InvKey[i][j] %= 26;

                    }
                }

            }
            // Transpose the matrix
            List<List<int>> T = GetTranspose(InvKey);

            return T;
        }
        private int GetDet(List<List<int>> Key, int x, int y)
        {
       
            List<int> vals = new List<int>();
            for(int i = 0; i < Key.Count; ++i)
            {
                if(i == x)continue;
                for(int j = 0; j < Key.Count; ++j)
                {
                    if(j == y)continue;
                    vals.Add(Key[i][j]);
                }
            }
            List<List<int> > mat = CreateKeyMatrix(vals);
            int det = SubInt( MulInt(mat[0][0], mat[1][1]), MulInt(mat[0][1], mat[1][0]));
            return det;
        }
        private int GetMulInv(int det)
        {
            int res = -1;
            for(int i = 1; i < 26; ++i)
            {
                if((i * det) % 26 == 1)
                {
                    res = i;
                    break;
                }
            }
            return res;
        }
        private bool IsValidKey(List<List<int> >  Key)
        {
            for (int i = 0; i < Key.Count; ++i)
            {
                for(int j = 0; j < Key.Count; ++j)
                {
                    if (Key[i][j] >= 26 || Key[i][j] < 0)
                        return false;
                }
            }
            int det = GetMatDet(Key);
            if (det == 0) return false;
            if (Gcd(det, 26) != 1) return false;

            int b = GetMulInv(det);
            if (b == -1) return false;

            return true;
        }
        private List<List<int> > GetTranspose(List<List<int>> mat)
        {
            List<List<int>> res = InitMatrix(mat.Count, mat.Count);
            if(mat.Count == 2)
            {
                res[1][0] = ((mat[1][0] * -1) + 26) % 26;
                res[0][1] = ((mat[0][1] * -1) + 26) % 26 ;
                res[0][0] = mat[1][1];
                res[1][1] = mat[0][0];

            }else
            {
                for (int i = 0; i < mat.Count; ++i)
                {
                    for (int j = 0; j < mat.Count; ++j)
                    {
                        res[j][i] = mat[i][j];
                    }
                }
            }
            
            return res;
        }
        private List<List<int>> InitMatrix(int row, int col)
        {
            List<List<int>> res = new List<List<int>>();
            for(int i = 0; i < row; ++i)
            {
                res.Add(new List<int> ());
                for(int j = 0; j < col; ++j)
                {
                    res[i].Add(0);
                }
            }
            return res;
        }
        private List<int> StringToList(string text)
        {
            List<int> res = new List<int>();
            foreach(char element in text)
            {
                res.Add((int)(element - 'A'));
            }
            return res;
        }
        private string ListToString(List<int> list)
        {
            string res = "";
            foreach(int element in list)
            {

                res += Convert.ToChar('A' + element);
            }
            return res;
        }
        private List<int> FlattenMatrix  (List<List<int>> matrix)
        {
            List<int> flat = new List<int>();
            for(int i = 0; i < matrix.Count; ++i)
            {
                for(int j = 0; j < matrix[0].Count; ++j)
                {
                    flat.Add(matrix[i][j]);
                }
            }
            return flat;
        }
        private int Gcd(int a, int b)
        {
            return b == 0 ? a : Gcd(b, a % b);
        }

        private int MulInt(int a, int b)
        {
            return (((a * b) % 26) + 26) % 26;
        }
        private int AddInt(int a, int b)
        {
            return (a + b + 26) % 26;
        }
        private int SubInt(int a, int b)
        {
            return ((a - b) % 26 + 26) % 26;
        }
    }
}
