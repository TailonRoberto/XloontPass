using System.ComponentModel.DataAnnotations;

namespace PasswordManager.Models
{
    public class PasswordEntryViewModel
    {
        public int Id { get; set; }

        [Required]
        public string Title { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string EncryptedPassword { get; set; }
    }
}
