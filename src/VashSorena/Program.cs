using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using FckRansom.VashSorena.Constants;
using FckRansom.VashSorena.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace FckRansom.VashSorena
{
    internal class Program
    {
        private static async Task Main(string[] args)
        {
            await CreateHostBuilder(args)
                .Build()
                .RunAsync()
                .ConfigureAwait(false);
        }

        public static IHostBuilder CreateHostBuilder(string[] args)
        {
            return Host.CreateDefaultBuilder(args)
                        .ConfigureAppConfiguration(builder =>
                        {
                            builder.AddJsonFile("appsettings.json", false, false);
                            builder.AddJsonFile("decryptionsettings.json", true);
                            builder.AddEnvironmentVariables();
                            builder.AddCommandLine(args, new Dictionary<string, string>
                            {
                                { "-o", nameof(Configuration.Operation) },
                                { "-s", nameof(Configuration.Source) },
                                { "-d", nameof(Configuration.Destination) },
                                { "-dc", nameof(Configuration.DecryptConcurrency) }
                            });
                        })
                       .ConfigureServices((context, services) =>
                       {
                           services.Configure<Configuration>(context.Configuration);
                           services.AddSingleton<Decryption>();

                           var config = context.Configuration.Get<Configuration>();

                           switch (config.Operation)
                           {
                               case Operation.Decrypt:
                                   services.AddHostedService<DecryptService>();
                                   break;
                               case Operation.Detect:
                                   services.AddHostedService<DetectService>();
                                   break;
                               default:
                                   throw new ArgumentOutOfRangeException(nameof(config.Operation), config.Operation, $"{nameof(config.Operation)} is invalid.");
                           }
                       });
        }
    }
}
