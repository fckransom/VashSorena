using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FckRansom.VashSorena.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;

namespace FckRansom.VashSorena
{
    internal class DecryptService : BackgroundService
    {
        private readonly Decryption _decryption;
        private readonly Configuration _configuration;
        private readonly ILogger<DecryptService> _logger;
        private readonly IHostApplicationLifetime _applicationLifetime;

        private int _globalCounter;

        public DecryptService(Decryption decryption, IOptions<Configuration> configuration, ILogger<DecryptService> logger, IHostApplicationLifetime applicationLifetime)
        {
            _decryption = decryption;
            _configuration = configuration.Value;
            _logger = logger;
            _applicationLifetime = applicationLifetime;

            if (_configuration.DecryptConcurrency <= 0)
            {
                _logger.LogError($"{nameof(_configuration.DecryptConcurrency)} must be greater than 0.");
                _applicationLifetime.StopApplication();
            }
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await Task.Yield();

            string sourcePath;
            string destinationPath;

            try
            {
                try
                {
                    (sourcePath, destinationPath) = VerifyAndExpandPaths();
                }
                catch (InvalidOperationException e)
                {
                    _logger.LogError(e.Message);
                    return;
                }

                _logger.LogInformation($"Decrypting files from {sourcePath} to {destinationPath}.");

                try
                {
                    foreach (var keyInfo in GetRansomKeyInfos(sourcePath))
                    {
                        if (stoppingToken.IsCancellationRequested)
                        {
                            break;
                        }

                        await DecryptAllFilesAsync(sourcePath, destinationPath, keyInfo, stoppingToken).ConfigureAwait(false);
                    }

                    _logger.LogInformation($"Decrypting files done, all files that is decrypted exists on {destinationPath}.");
                }
                catch (OperationCanceledException)
                {
                    _logger.LogWarning($"Decrypting files cancelled.");
                }
                catch (Exception e)
                {
                    _logger.LogCritical(e, "Unexpected exception occurred. See exception details for information.");
                }
            }
            finally
            {
                _applicationLifetime.StopApplication();
            }
        }

        private async Task DecryptAllFilesAsync(string sourcePath, string destinationPath, KeyInfo keyInfo, CancellationToken cancellationToken)
        {
            var attacker = _configuration.Attackers?.FirstOrDefault(a => a.Email.Equals(keyInfo.Email, StringComparison.OrdinalIgnoreCase));

            if (attacker == null)
            {
                _logger.LogError($"Could not get any valid configuration for attacker {keyInfo.Email}, please refer to https://github.com/fckransom/VashSorena for more information and help.");
                return;
            }

            _logger.LogInformation($"Decrypting files for attacker {keyInfo.Email} with key {keyInfo.Key}.");

            var decryptTasks = new List<Task>(_configuration.DecryptConcurrency);
            var fileEnumeration = _decryption.EnumerateEncryptedFiles<(string, string)?>(sourcePath, (source, match) =>
            {
                var matchKey = match.Groups["Key"].Value;

                if (!keyInfo.Key.Equals(matchKey, StringComparison.Ordinal))
                {
                    return null;
                }

                var fileName = Path.GetFileNameWithoutExtension(source);
                var realFileName = _decryption.EncryptedFileRegex.Replace(fileName, "");
                var destination = Path.Combine(destinationPath, realFileName);

                return (source, destination);
            });

            foreach (var (sourceFile, destinationFile) in fileEnumeration.OfType<(string, string)>())
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                var destFileDirectory = Path.GetDirectoryName(destinationFile);

                if (string.IsNullOrWhiteSpace(destFileDirectory))
                {
                    _logger.LogError($"Could not get directory name from {destinationFile} when trying to decrypt {sourceFile}.");
                    continue;
                }

                if (!Directory.Exists(destFileDirectory))
                {
                    Directory.CreateDirectory(destFileDirectory);
                }

                var cipher = _decryption.GetMD5SHA1DecryptCipher(keyInfo.Key, attacker.MD5, attacker.SHA1);

                decryptTasks.Add(DecryptFileAsync(sourceFile, destinationFile, cipher, cancellationToken));

                if (decryptTasks.Count == _configuration.DecryptConcurrency)
                {
                    decryptTasks.Remove(await Task.WhenAny(decryptTasks).ConfigureAwait(false));

                    if (Interlocked.Increment(ref _globalCounter) % 1000 == 0)
                    {
                        _logger.LogInformation($"Still working...");
                    }
                }
            }

            await Task.WhenAll(decryptTasks).ConfigureAwait(false);

            _logger.LogInformation($"Decrypting files for attacker {keyInfo.Email} with key {keyInfo.Key} done.");
        }

        private async Task DecryptFileAsync(string source, string destination, IBufferedCipher readCipher, CancellationToken cancellationToken)
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

        private IEnumerable<KeyInfo> GetRansomKeyInfos(string sourcePath)
        {
            var readKeys = new List<string>();

            return _decryption.EnumerateEncryptedFiles(sourcePath, (sourceFile, match) =>
            {
                var key = match.Groups["Key"].Value;

                if (readKeys.Contains(key))
                {
                    return null;
                }

                readKeys.Add(key);

                return new KeyInfo(key, match.Groups["Email"].Value);

            });
        }

        private (string expandedSource, string expandedDest) VerifyAndExpandPaths()
        {
            var source = _configuration.Source ?? throw new InvalidOperationException($"Missing configuration {nameof(_configuration.Source)}");
            var dest = _configuration.Destination ?? throw new InvalidOperationException($"Missing configuration {nameof(_configuration.Destination)}");

            var expandedSource = Environment.ExpandEnvironmentVariables(source);
            var expandedDest = Environment.ExpandEnvironmentVariables(dest);


            if (!Path.EndsInDirectorySeparator(expandedSource))
            {
                expandedSource += Path.DirectorySeparatorChar;
            }

            if (!Path.EndsInDirectorySeparator(expandedDest))
            {
                expandedDest += Path.DirectorySeparatorChar;
            }

            if (expandedSource.Equals(expandedDest))
            {
                throw new InvalidOperationException($"{nameof(_configuration.Source)} cannot be the same as {nameof(_configuration.Destination)}");
            }

            if (!Directory.Exists(expandedSource))
            {
                throw new InvalidOperationException($"{nameof(_configuration.Source)} does not exist.");
            }

            if (!expandedDest.Equals(Directory.GetDirectoryRoot(expandedDest)))
            {
                if (!Directory.Exists(expandedDest))
                {
                    Directory.CreateDirectory(expandedDest);
                }
            }
            else if (!Directory.Exists(Directory.GetDirectoryRoot(expandedDest)))
            {
                throw new InvalidOperationException($"{nameof(_configuration.Destination)} does not exist.");
            }

            return (expandedSource, expandedDest);
        }
    }
}
