
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace FckRansom.VashSorena
{
    internal class Decryption
    {
        private const string _fileSearchPattern = "*.Email=[*]ID=[*]*";

        private static readonly System.Security.Cryptography.MD5 _md5 = System.Security.Cryptography.MD5.Create();
        private static readonly System.Security.Cryptography.SHA1 _sha1 = System.Security.Cryptography.SHA1.Create();

        private static readonly EnumerationOptions _fileSearchEnumerationOptions = new()
        {
            MatchCasing = MatchCasing.CaseInsensitive,
            RecurseSubdirectories = true
        };

        private readonly ConcurrentDictionary<string, byte[]> KeyDerivations = new();

        private readonly ILogger _logger;

        public Regex EncryptedFileRegex { get; } = new(@"\.Email\=\[(?<Email>.+?)\]ID\=\[(?<Key>[A-Z]+?)\]", RegexOptions.IgnoreCase);

        public Decryption(ILogger<Decryption> logger)
        {
            _logger = logger;
        }

        public async Task DecryptFileAsync(string source, string destination, IBufferedCipher readCipher, CancellationToken cancellationToken)
        {
            try
            {
                await using var inFile = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.None);
                await using var cipherStream = new CipherStream(inFile, readCipher, null);
                await using var outFile = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None);

                await cipherStream.CopyToAsync(outFile, cancellationToken).ConfigureAwait(false);
                await outFile.FlushAsync(cancellationToken).ConfigureAwait(false);

                _logger.LogDebug($"{source} decrypted to {destination}.");
            }
            catch (TaskCanceledException)
            {
                File.Delete(destination);
            }
            catch (Exception e)
            {
                _logger.LogError(e, $"Could not decrypt {source} see inner exception for details.");
            }
        }

        public IEnumerable<T> EnumerateEncryptedFiles<T>(string sourcePath, Func<string, Match, T?> handler)
        {
            foreach (var sourceFile in Directory.EnumerateFiles(sourcePath, _fileSearchPattern, _fileSearchEnumerationOptions))
            {
                var match = EncryptedFileRegex.Match(sourceFile);

                if (!match.Success)
                {
                    continue;
                }

                var result = handler(sourceFile, match);

                if (result != null)
                {
                    yield return result;
                }
            }
        }

        [SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "Want this to only be accessible as a instance member.")]
        public IBufferedCipher GetNonCachedMD5SHA1DecryptCipher(string key, int md5Count, int sha1Count)
        {
            var pbkdf2 = GetKeyDerivation(key, md5Count, sha1Count);

            return CreateAESOFBCipher(pbkdf2, new byte[16]);
        }

        public IBufferedCipher GetMD5SHA1DecryptCipher(string key, int md5Count, int sha1Count)
        {
            var pbkdf2 = KeyDerivations.GetOrAdd(key, _ => GetKeyDerivation(key, md5Count, sha1Count));

            return CreateAESOFBCipher(pbkdf2, new byte[16]);
        }

#nullable disable //Method may set attacker and key to null if no match is found.
        public bool TryGetFileRansomInfo(string sourceFile, out string attacker, out string key)
        {
            var match = EncryptedFileRegex.Match(sourceFile);

            if (!match.Success)
            {
                attacker = key = null;

                return false;
            }

            attacker = match.Groups["Email"].Value;
            key = match.Groups["Key"].Value;

            return true;
        }
#nullable enable

        private static byte[] GetKeyDerivation(string key, int md5Count, int sha1Count)
        {
            var hash = key;
            for (var i = 0; i < md5Count; i++)
            {
                hash = MD5(hash);
            }

            for (var i = 0; i < sha1Count; i++)
            {
                hash = SHA1(hash);
            }

            return KeyDerivation.Pbkdf2(hash, Encoding.UTF8.GetBytes(hash), KeyDerivationPrf.HMACSHA256, 1000, 32);
        }

        private static string MD5(string val)
        {
            return ToHexString(_md5.ComputeHash(Encoding.UTF8.GetBytes(val)));
        }

        private static string SHA1(string val)
        {
            return ToHexString(_sha1.ComputeHash(Encoding.UTF8.GetBytes(val)));
        }

        private static string ToHexString(byte[] val)
        {
            var sb = new StringBuilder();

            foreach (var b in val)
            {
                sb.Append(b.ToString("x2"));
            }

            return sb.ToString();
        }

        private static IBufferedCipher CreateAESOFBCipher(byte[] pbkdf2, byte[] iv)
        {
            var aesKey = ParameterUtilities.CreateKeyParameter("AES", pbkdf2);
            var cipher = CipherUtilities.GetCipher("AES/OFB/NOPADDING");
            cipher.Init(false, new ParametersWithIV(aesKey, iv));

            return cipher;
        }
    }
}
