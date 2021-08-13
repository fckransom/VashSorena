using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FckRansom.VashSorena.Constants;
using FckRansom.VashSorena.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FckRansom.VashSorena
{
    internal class DetectService : BackgroundService
    {
        private readonly Decryption _decryption;
        private readonly Configuration _configuration;
        private readonly ILogger<DetectService> _logger;
        private readonly IHostApplicationLifetime _applicationLifetime;

        public DetectService(Decryption decryption, IOptions<Configuration> configuration, ILogger<DetectService> logger, IHostApplicationLifetime applicationLifetime)
        {
            _decryption = decryption;
            _configuration = configuration.Value;
            _logger = logger;
            _applicationLifetime = applicationLifetime;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await Task.Yield();

            string source;
            string destination;

            try
            {
                try
                {
                    (source, destination) = VerifyAndExpandPaths();
                }
                catch (InvalidOperationException e)
                {
                    _logger.LogError(e.Message);
                    return;
                }

                WriteDetectionInfo(source, destination);

                if (!_decryption.TryGetFileRansomInfo(source, out var attacker, out var key))
                {
                    WriteIncorrectRansomError(source);
                    return;
                }

                if (await CheckForExistingDetectionConfigurationAsync(attacker, stoppingToken).ConfigureAwait(true))
                {
                    WriteExistingDetectionConfig(attacker);
                    return;
                }

                var keyCombination = await GetKeyCombinationsAsync(source, destination, key, stoppingToken).ConfigureAwait(true);

                if (keyCombination == null)
                {
                    WriteDetectionFailure(source);
                    return;
                }

                await UpdateCustomDecryptionFile(attacker, keyCombination.Value.md5, keyCombination.Value.sha1).ConfigureAwait(true);

                WriteDetectionSuccess();
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning($"Detection cancelled.");
            }
            catch (Exception e)
            {
                _logger.LogCritical(e, "Unexpected exception occurred. See exception details for information.");
            }
            finally
            {
                _applicationLifetime.StopApplication();
            }
        }

        private static async Task<bool> CheckForExistingDetectionConfigurationAsync(string email, CancellationToken cancellationToken)
        {
            CustomDecryption? customDecryption = null;
            if (File.Exists("decryptionsettings.json"))
            {
                await using var readStream = File.OpenRead("decryptionsettings.json");
                customDecryption = await JsonSerializer.DeserializeAsync<CustomDecryption>(readStream, cancellationToken: cancellationToken).ConfigureAwait(true);
            }

            return customDecryption?.Attackers.Any(a => a.Email.Equals(email, StringComparison.OrdinalIgnoreCase)) == true;
        }

        private async Task<(int md5, int sha1)?> GetKeyCombinationsAsync(string source, string destination, string key, CancellationToken cancellationToken)
        {
            for (var sha1 = 1; sha1 <= 10; sha1++)
            {
                for (var md5 = 1; md5 <= 10; md5++)
                {
                    _logger.LogDebug($"Trying to decrypt {source} using MD5 {md5} and SHA1 {sha1}.");
                    var cipher = _decryption.GetNonCachedMD5SHA1DecryptCipher(key, md5, sha1);

                    await _decryption.DecryptFileAsync(source, destination, cipher, cancellationToken).ConfigureAwait(true);

                    Console.Write($"Decryption attempt complete, check {destination}. Is the file decrypted correctly? (y/N) ");

                    var result = IsComplete();

                    if (result)
                    {
                        _logger.LogDebug($"Decrypt {source} using MD5 {md5} and SHA1 {sha1} succeeded.");
                        Console.WriteLine();
                        return (md5, sha1);
                    }

                    _logger.LogDebug($"Decrypt {source} using MD5 {md5} and SHA1 {sha1} failed.");

                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("You have indicated that the current decrypted file is incorrect. Continuing...");
                    Console.ResetColor();

                    while (File.Exists(destination))
                    {
                        try
                        {
                            File.Delete(destination);
                        }
                        catch (IOException)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.Write($"Could not delete {destination}, do you have the file open? Close it and press Enter to retry.");
                            Console.ResetColor();
                            Console.ReadLine();
                        }
                    }
                    Console.WriteLine();
                }
            }

            return null;
        }

        private static bool IsComplete()
        {
            while (true)
            {
                var keyInfo = Console.ReadKey(true);

                if ((keyInfo.Modifiers & ConsoleModifiers.Alt) == ConsoleModifiers.Alt ||
                   (keyInfo.Modifiers & ConsoleModifiers.Control) == ConsoleModifiers.Control)
                {
                    continue;
                }

                switch (keyInfo.Key)
                {
                    case ConsoleKey.Y:
                        Console.WriteLine(keyInfo.KeyChar);
                        return true;
                    case ConsoleKey.N:
                        Console.WriteLine(keyInfo.KeyChar);
                        return false;
                    case ConsoleKey.Enter:
                        Console.WriteLine("N");
                        return false;
                }
            }
        }

        private static async Task UpdateCustomDecryptionFile(string email, int md5, int sha1)
        {
            CustomDecryption? customDecryption = null;
            if (File.Exists("decryptionsettings.json"))
            {
                await using var readStream = File.OpenRead("decryptionsettings.json");
                customDecryption = await JsonSerializer.DeserializeAsync<CustomDecryption>(readStream).ConfigureAwait(true);
            }

            if (customDecryption == null)
            {
                customDecryption = new CustomDecryption();
            }

            var attacker = customDecryption.Attackers.FirstOrDefault(a => a.Email.Equals(email, StringComparison.OrdinalIgnoreCase));

            if (attacker == null)
            {
                attacker = new Attacker
                {
                    Email = email
                };

                customDecryption.Attackers.Add(attacker);
            }

            attacker.MD5 = md5;
            attacker.SHA1 = sha1;

            await using var writeStream = File.Create("decryptionsettings.json");
            await JsonSerializer.SerializeAsync(writeStream, customDecryption,
                                                new JsonSerializerOptions
                                                {
                                                    AllowTrailingCommas = false,
                                                    WriteIndented = true
                                                })
                                .ConfigureAwait(true);
            await writeStream.FlushAsync().ConfigureAwait(true);
        }

        private (string source, string destination) VerifyAndExpandPaths()
        {
            var source = _configuration.Source ?? throw new InvalidOperationException($"Missing configuration {nameof(_configuration.Source)}");
            var dest = _configuration.Destination ?? throw new InvalidOperationException($"Missing configuration {nameof(_configuration.Destination)}");
            var expandedSource = Environment.ExpandEnvironmentVariables(source);
            var expandedDest = Environment.ExpandEnvironmentVariables(dest);

            if (!File.Exists(expandedSource))
            {
                throw new InvalidOperationException($"{source} is does not exist.");
            }

            if (!Path.EndsInDirectorySeparator(expandedDest))
            {
                expandedDest += Path.DirectorySeparatorChar;
            }

            if (!Directory.Exists(expandedDest))
            {
                Directory.CreateDirectory(expandedDest);
            }

            var fileName = Path.GetFileNameWithoutExtension(expandedSource);
            var realFileName = _decryption.EncryptedFileRegex.Replace(fileName, "");
            var destination = Path.Combine(expandedDest, realFileName);

            return (expandedSource, destination);
        }

        private void WriteDetectionSuccess()
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("CONGRATULATIONS! You have indicated that the detection mode found the correct combination!");
            Console.ResetColor();
            Console.WriteLine();
            Console.WriteLine($"The decryption combination is written to decryptionsettings.json. Rerun this application without the {nameof(_configuration.Operation)} set to {Operation.Detect} to decrypt your files.");
        }

        private static void WriteDetectionInfo(string source, string destination)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("RUNNING IN DETECTION MODE");
            Console.ResetColor();
            Console.WriteLine();
            Console.Write($"The detection mode will traverse through different combinations and try to decrypt ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write(source);
            Console.ResetColor();
            Console.Write(" to ");
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write(destination);
            Console.ResetColor();
            Console.WriteLine(".");
            Console.WriteLine();
            Console.WriteLine("After each decryption verify the decrypted file if it is correctly confirm this when asked.");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Press ENTER to start detection.");
            Console.ResetColor();
            Console.ReadLine();
        }

        private static void WriteDetectionFailure(string source)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Could not find any valid decryption combinations for {Path.GetFileName(source)}, either the ransomware isn't Vash Sorena or it is an unknown combination, please refer to https://github.com/fckransom/VashSorena for more information and help.");
            Console.ResetColor();
        }

        private void WriteExistingDetectionConfig(string attacker)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;

            Console.WriteLine($"A configuration for {attacker} already exists. Run this application without the {nameof(Configuration.Operation)} parameter and {nameof(Configuration.Source)} set to the source of encrypted files to decrypt files.");

            Console.ResetColor();
        }

        private static void WriteIncorrectRansomError(string source)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"Could not detect attacker and key from {Path.GetFileName(source)}, the ransomware is probably not Vash Sorena, please refer to https://github.com/fckransom/VashSorena for more information and help.");
            Console.ResetColor();
        }
    }
}
