namespace FckRansom.VashSorena.Models
{
    internal sealed class Attacker
    {
        public string Email { get; set; } = default!;

        public int MD5 { get; set; }

        public int SHA1 { get; set; }
    }
}
