using System;
using System.Collections.Generic;

namespace CipherBox.PasswordGeneration
{
    public class PasswordGenerator
    {
        #region char set
        // total = 26+26+10+32+1 = 95
        private const string _chars = "abcdefghijklmnopqrstuvwxyz"; // 26
        private const string _CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; // 26
        private const string _digits = "0123456789"; // 10
        private const string _symbols = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"; // 32
        private const string _space = " "; // 1

        public bool IncludeChars = true;
        public bool IncludeCHARS = false;
        public bool IncludeDigits = true;
        public bool IncludeSymbols = false;
        public bool IncludeSpace = false;
        public bool IncludeNull = false; // TODO: for wild-match

        public int BaseNum { get { return CharSet.Length; } }

        private string _charset = null;

        public string CharSet
        {
            get
            {
                if (!string.IsNullOrEmpty(_charset)) return _charset;
                string az = "";
                if (IncludeChars) az += _chars;
                if (IncludeDigits) az += _digits;
                if (IncludeCHARS) az += _CHARS;
                if (IncludeSymbols) az += _symbols;
                if (IncludeSpace) az += _space;
                return az;
            }
            set
            {
                _charset = value;  // set directly
            }
        }
        #endregion

        private int _length = 6; // password total length
        private int _maskLength = 6; // length for password mask
        private string _mask = null; // password mask string like "pass**rd"

        public int Length
        {
            get
            {
                return _length;
            }
            set
            {
                _length = value;
                _maskLength = value;
            }
        }

        // the count of all password with given length (or less) and charset
        public static decimal Count( int maxlen, int basenum )
        {
            {
                decimal cnt = 0;
                try
                {
                    checked
                    {
                        for (int i = 0; i < maxlen; i++)
                        {
                            cnt = (cnt + 1) * basenum;
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("arithmetic overflow: " + ex.Message);
                    cnt = decimal.MaxValue;
                }

                return cnt;
            }
        }

        // the count of password with given length
        public decimal Count()
        {
            return Count(_maskLength, BaseNum) - Count(_maskLength -1, BaseNum);
        }

        public decimal StartIndex()
        {
            return Count(_maskLength - 1, BaseNum);
        }

        public decimal EndIndex()
        {
            return Count(_maskLength, BaseNum);
        }



        // default
        public PasswordGenerator()
        {
        }

        // from password mask
        public PasswordGenerator(string mask)
        {
            _maskLength = 0; // for unspecified chars
            for (int i = 0; i < mask.Length; i++)
            {
                if (mask[i] == '*') _maskLength++;
            }

            _mask = mask;
            _length = mask.Length;
        }



        // get the char of charset based num
        private string GetChar(int i)
        {
            if (i < 0 || i >= BaseNum) return "";
            return "" + CharSet[i];
        }

        // transform an integer into a password string within base num and max length
        private string Transform(decimal dec)
        {
            if (dec < BaseNum) return GetChar((int)dec);
            return Transform((dec / BaseNum) - 1) + Transform(dec % BaseNum);
        }

        public string Password(decimal dec)
        {
            string result = Transform(dec);

            if (_mask == null) return result;

            // map to mask
            string password = "";
            int j = 0;
            for (int i = 0; i < _mask.Length; i++)
            {
                if (_mask[i] == '*')
                {
                    if (j < result.Length)
                    {
                        password = password + result[j];
                        j++;
                    }
                    else
                    {
                        // no pad
                    }
                }
                else
                {
                    password = password + _mask[i];
                }
            }

            return password;
        }

        // the longest password string
        public string LongestPassword()
        {
            return Transform(decimal.MaxValue);
        }

        // random password string
        public string RandomPassword()
        {
            Random rand = new Random();
            return Transform((decimal)(rand.NextDouble() * (double)decimal.MaxValue));
        }

    }

    /*
    class Program
    {
        static void Main()
        {
            // 最大的单词
            Console.WriteLine(GenPassword.LongestString());
            Console.WriteLine("-------");

            // 随机输出10个单词
            for (int i = 0; i < 10; i++)
            {
                Console.WriteLine(GenPassword.RandString());
            }
            Console.WriteLine("-------");

            // 输出1至3个字母的单词
            for (decimal i = GenPassword.MaxCount(7); i < GenPassword.MaxCount(8); i++)
            {
                Console.WriteLine(GenPassword.DEC_to_AZ(i));
            }

        }
    }
    */


}




/* output: 
dzjotjvdimnzicgssaefn
-------
tabvzrnlzyndopqndesu
bkqvwzzolfjmniymogrrs
dqkslasmefypcoufhnpwq
csaduswxikqbrxfyvewvw
lehrfqbmkjpwuiwltmea
khllveyptzqcthtuyewu
bkpikunptnnoiyuroytfs
fsrfzevlwyctionjnddo
jeoqmyvdcucjgruigbvk
beylmhkguiziwhkrxnbho
-------
a
b
c
d
e
f
g
h
i
j
k
l
m
n
o
p
q
r
s
t
u
v
w
x
y
z
-------
aa
ab
ac
...
zw
zx
yz
zz
-------
aaa
aab
aac
...
zzw
zzx
zzy
zzz
*/