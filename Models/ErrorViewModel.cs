using STB.MAP.UI.Models;
using Microsoft.AspNetCore.Identity;


namespace STB.MAP.UI.Models
{

    public class ErrorViewModel
    {
        public required string RequestId { get; set; }

        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);

        public  string ErrorMessage { get; set; }
    }

}