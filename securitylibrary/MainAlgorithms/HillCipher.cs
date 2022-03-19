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
            throw new NotImplementedException();


        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {

            if (!IsValidKey(key))
                throw new InvalidAnlysisException();

            int size = (int)Math.Sqrt(key.Count);
            List<int> res = new List<int>();
            List<List<int>> InvKey = GetKeyInv(key);

            for (int i = 0; i < cipherText.Count; i += size)
            {
                List<int> CT = new List<int>();
                for (int j = i; j < i + size; ++j)
                    CT.Add(cipherText[j]);

                List<int> PT = MulMatrix(InvKey, CT);
                
                foreach(int p in PT)
                {
                    res.Add(p);
                }
            }
            return res;
      
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            if (!IsValidKey(key))
                throw new InvalidAnlysisException();

            int len = (int)Math.Sqrt(key.Count);
            List<int> res = new List<int>();

            List<List<int>> K = CreateKeyMatrix(key);
            for(int i = 0; i < plainText.Count; i += len)
            {
                List<int> PT = new List<int>();
                for (int j = i; j < i + len; ++j)
                    PT.Add(plainText[j]);

                List<int> CT = MulMatrix(K, PT);
                
                foreach(int c in CT)
                {
                    res.Add(c);
                }
            }
            return res;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            throw new InvalidAnlysisException();
        }

        public List< List<int> > CreateKeyMatrix (List<int> key)
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
        public List<int> MulMatrix(List<List<int>> K, List<int> PT)
        {
            List<int> res = new List<int>() ;
            for (int i = 0; i < K.Count; ++i)
                res.Add(0);

            for(int i = 0; i < K.Count; ++i)
            {
                for(int j = 0; j < K.Count; ++j)
                {
                    res[i] = AddInt(res[i], MulInt(K[i][j], PT[j]));
                }
            }
            return res;
        }
        int GetMatDet(List<List<int>> Key)
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
        public List<List<int>> GetKeyInv(List<int> K)
        {
            int size = (int) Math.Sqrt(K.Count);
            List<List<int>> Key = CreateKeyMatrix(K);
            List<List<int>> InvKey = InitMatrix(size);

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
        public int GetDet(List<List<int>> Key, int x, int y)
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
        int GetMulInv(int det)
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
        bool IsValidKey(List<int> k)
        {
            List<List<int>> Key = CreateKeyMatrix(k);
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
        List<List<int> > GetTranspose(List<List<int>> mat)
        {
            List<List<int>> res = InitMatrix(mat.Count);
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
        public List<List<int>> InitMatrix(int size)
        {
            List<List<int>> res = new List<List<int>>();
            for(int i = 0; i < size; ++i)
            {
                res.Add(new List<int> ());
                for(int j = 0; j < size; ++j)
                {
                    res[i].Add(0);
                }
            }
            return res;
        }
        public int Gcd(int a, int b)
        {
            return b == 0 ? a : Gcd(b, a % b);
        }
        
        public int MulInt(int a, int b)
        {
            return (((a * b) % 26) + 26) % 26;
        }
        public int AddInt(int a, int b)
        {
            return (a + b + 26) % 26;
        }
        public int SubInt(int a, int b)
        {
            return ((a - b) % 26 + 26) % 26;
        }
    }
}
