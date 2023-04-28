namespace AuthenticationApi.Config
{
    public class TokenConfiguration
    {
        public string Audience { get; set; }
        public string Issuer { get; set; }
        public int ExpireHours { get; set; }
    }
}
