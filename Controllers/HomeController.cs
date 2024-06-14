using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using PasswordManager.Data;
using PasswordManager.Models;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace PasswordManager.Controllers
{
    public class HomeController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ApplicationDbContext _context;

        public HomeController(UserManager<IdentityUser> userManager, ApplicationDbContext context)
        {
            _userManager = userManager;
            _context = context;
        }

        public async Task<IActionResult> Index()
        {
            if (User.Identity.IsAuthenticated)
            {
                var userId = _userManager.GetUserId(User);
                var passwords = await _context.PasswordEntries
                    .Where(p => p.UserId == userId)
                    .ToListAsync();

                // return View(passwords);
                return RedirectToAction("Index", "Passwords");
            }

           // return RedirectToAction("Index", "Passwords");
            return View(Enumerable.Empty<PasswordEntry>());
        }
    }
}
