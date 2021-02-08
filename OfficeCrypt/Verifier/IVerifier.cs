using System;
using System.IO;

namespace CipherBox
{
    public interface IVerifier
    {
        bool VerifyPassword(string password);
    }
}