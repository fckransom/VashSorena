using System.Collections.Generic;
using FckRansom.VashSorena.Constants;

namespace FckRansom.VashSorena.Models
{
    internal class Configuration
    {
        public Operation Operation { get; set; }

        public int DecryptConcurrency { get; set; }

        public string Source { get; set; } = default!;

        public string Destination { get; set; } = default!;

        public IEnumerable<Attacker> Attackers { get; set; } = default!;
    }
}
