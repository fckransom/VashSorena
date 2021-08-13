namespace FckRansom.VashSorena.Models
{
    internal class KeyInfo
    {
        public string Key { get; }
        public string Email { get; }

        public KeyInfo(string key, string email)
        {
            Key = key;
            Email = email;
        }
    }
}
