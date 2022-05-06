using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {

        public int Encrypt(int p, int q, int M, int e)
        {
            int n = (p) * (q);
            int c = fastPower(M, e, n);
            return c;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int n = (p) * (q);
            int ph = (p - 1) * (q - 1);
            int d = modInverse(e, ph);
            int M = fastPower(C, d, n);
            return M;    
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
        int modInverse(int a, int m)
        {
            
            for (int i = 1; i < m; i++)
                if (((a % m) * (i % m)) % m == 1)
                    return i;
            return 1;
        }
    }
}
