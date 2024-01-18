using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using System.ComponentModel.DataAnnotations;

namespace STB.MAP.UI.Models
{
    public class Proje
    {
        [Key]
        public int IdProject { get; set; }

        [Required]
        public required string NameProject { get; set; }


        [ValidateNever]
        public string? UrlTest { get; set; }


        [ValidateNever]
        public string? UrlCanli { get; set; }

    }
}
