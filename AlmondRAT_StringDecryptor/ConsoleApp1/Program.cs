using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;



class Program
{
    static void Main(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("Usage: decryptor.exe <path_to_file>");
            return;
        }
        string inputPath = args[0];

        if (!File.Exists(inputPath))
        {
            Console.WriteLine("File does not exist.");
            return;
        }
        string outputPath = Path.Combine(
            Path.GetDirectoryName(inputPath),
            Path.GetFileNameWithoutExtension(inputPath) + "_cleaned" +
            Path.GetExtension(inputPath)
        );

        AssemblyDef asm = AssemblyDef.Load(inputPath);
        List<MethodDef> decryptFunc = new List<MethodDef>();
        ModuleDef mod = asm.ManifestModule;
        foreach (TypeDef type in mod.Types)
        {
            if (!type.HasMethods)
                continue;
            foreach (MethodDef method in type.Methods)
            {
                if (!method.HasBody)
                    continue;
                CilBody body = method.Body;
                int flagRfc2898DeriveBytes = 0;
                int flagAes = 0;
                foreach (Local local in body.Variables)
                {
                    string localString = local.Type.ToString();
                    if (localString.Contains("Rfc2898DeriveBytes"))
                        flagRfc2898DeriveBytes = 1;
                    if (localString.Contains("Aes"))
                        flagAes = 1;
                }
                if (flagAes == 1 && flagRfc2898DeriveBytes == 1)
                    decryptFunc.Add(method);
            }

        }
        if (decryptFunc.Count != 1)
        {
            Console.WriteLine("Something went wrong");
            return;
        }
        MethodDef decrypt = decryptFunc[0];
        Console.WriteLine(decrypt.Name);
        int token = decrypt.MDToken.ToInt32();
        Assembly reflectAasm = Assembly.LoadFrom(inputPath);
        Module mod_ = reflectAasm.ManifestModule;
        MethodBase decrypt_dynamic = mod_.ResolveMethod(token);
        Type type_ = decrypt_dynamic.DeclaringType;
        object obj = Activator.CreateInstance(type_);

        List<string> encStrings = new List<string>();
        foreach (TypeDef type in mod.Types)
        {
            if (!type.HasMethods)
                continue;
            foreach (MethodDef method in type.Methods)
            {
                if (!method.HasBody)
                    continue;
                CilBody body = method.Body;
                for (int i = 0; i < body.Instructions.Count; i++)
                {
                    Instruction insn = body.Instructions[i];
                    if (insn.OpCode == OpCodes.Call || insn.OpCode == OpCodes.Callvirt)
                    {
                        var called = (IMethod)insn.Operand;
                        if (called.ResolveMethodDef() == decrypt)
                        {
                            Instruction ldstrInsn = body.Instructions[i - 1];
                            if (ldstrInsn.OpCode == OpCodes.Ldstr)
                            {
                                string enc = ldstrInsn.Operand.ToString();
                                string dec = (string)decrypt_dynamic.Invoke(obj, new object[] { enc });
                                ldstrInsn.Operand = dec;
                                Console.WriteLine($"Patched {enc} with {dec}");
                            }
                        }
                    }
                }
            }

        }
        mod.Write(outputPath);

    }
}
