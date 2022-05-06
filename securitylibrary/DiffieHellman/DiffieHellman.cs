using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
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
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int ya = fastPower(alpha,xa,q);
            int yb = fastPower(alpha, xb, q);

            int k1 = fastPower(yb, xa, q);
            int k2 = fastPower(ya, xb, q);

            return new List<int>() { k1, k2 };
        }

    }
}
