using System.ComponentModel.DataAnnotations;

namespace STB.MAP.UI.Models
{ 
public class RegisterViewModel

    {
        [Required(ErrorMessage = "Kullanıcı adı zorunludur.")]
        public required string Username { get; set; }

        [Required(ErrorMessage = "E-posta adresi zorunludur.")]
        [EmailAddress(ErrorMessage = "Geçersiz e-posta adresi.")]
        public required string Email { get; set; }

        [Required(ErrorMessage = "Şifre zorunludur.")]
        public required string Password { get; set; }

        [Required(ErrorMessage = "Şifre tekrarı zorunludur.")]

        [Compare("Password", ErrorMessage = "Şifreler uyuşmuyor.")]
        public required string ConfirmPassword { get; set; }
    }

}
