using System.ComponentModel.DataAnnotations;

namespace PasswordManager.Models
{
    public class PasswordEntry
    {
        public int Id { get; set; }
        public string UserId { get; set; }

        [Required]
        public string Title { get; set; }

        [Required]
        public string EncryptedPassword { get; set; }
    }
}
