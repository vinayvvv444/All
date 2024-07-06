using All.Models.User;
using System.ComponentModel.DataAnnotations;

namespace All.Models.jwt
{
    public class RefreshToken
    {
        [Key]
        public int Id { get; set; }
        public string Token { get; set; }
        public string UserId { get; set; }
        public ApplicationUser User { get; set; }
        public DateTime ExpiryDate { get; set; }
    }
}
