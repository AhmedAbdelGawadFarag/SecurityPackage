using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        /// <summary>
        /// Encryption
        /// </summary>
        /// <param name="alpha"></param>
        /// <param name="q"></param>
        /// <param name="y"></param>
        /// <param name="k"></param>
        /// <returns>list[0] = C1, List[1] = C2</returns>
        /// 
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            int key = fastPower(y, k, q);
            long c1 = (long)(fastPower(alpha, k, q));
            long c2 = ((long)key * (long)m) % q;

            return new List<long>() { c1, c2 };
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            int cipherText = c1*c2;
            int k = fastPower(c1,x,q);
            int t1 = c2 % q;
            int t2 = modInverse(k,q);

            int m = (t1 * t2) % q;
            return m;
        }

        int modInverse(int a, int m)
        {
            for (int i = 1; i < m; i++)
                if (((a % m) * (i % m)) % m == 1)
                    return i;
            return 1;
        }

        int mul(int a, int b, int mod)
        {
            long x = (long)a;
            long y = (long)b;
            long res = x * y;
            res %= mod;
            return (int)(res);
        }
        int fastPower(int b, int p, int m)
        {
            int res = 1;
            while (p > 0)
            {
                if (p % 2 == 1)
                    res = mul(res, b, m);
                b = mul(b, b, m);
                p /= 2;
            }
            return res;
        }


    }
}
