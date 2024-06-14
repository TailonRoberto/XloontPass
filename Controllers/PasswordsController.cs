using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using PasswordManager.Data;
using PasswordManager.Helpers;
using PasswordManager.Models;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace PasswordManager.Controllers
{
    [Authorize]
    public class PasswordsController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<PasswordsController> _logger;

        public PasswordsController(ApplicationDbContext context, ILogger<PasswordsController> logger)
        {
            _context = context;
            _logger = logger;
        }

        public IActionResult Index()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var passwords = _context.PasswordEntries
                .Where(p => p.UserId == userId)
                .ToList();

            foreach (var password in passwords)
            {
                password.EncryptedPassword = EncryptionHelper.DecryptString(password.EncryptedPassword);
            }

            return View(passwords);
        }

        public IActionResult Create()
        {
            _logger.LogInformation("Rendering Create view.");
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(PasswordEntryViewModel model)
        {
            _logger.LogInformation("Received POST request for Create.");
            if (ModelState.IsValid)
            {


                var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
                var encryptedPassword = EncryptionHelper.EncryptString(model.EncryptedPassword);
                _logger.LogInformation($"User ID: {userId}");
                _logger.LogInformation($"Title: {model.Title}");
                _logger.LogInformation($"Encrypted Password: {encryptedPassword}");

                var passwordEntry = new PasswordEntry
                {
                    UserId = userId,
                    Title = model.Title,
                    EncryptedPassword = encryptedPassword
                };
                _context.Add(passwordEntry);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));










            }
            _logger.LogWarning("Model state is invalid.");
            foreach (var state in ModelState)
            {
                _logger.LogWarning($"Error in field '{state.Key}': {string.Join(", ", state.Value.Errors.Select(e => e.ErrorMessage))}");
            }
            return View(model);
        }






        public async Task<IActionResult> Edit(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var passwordEntry = await _context.PasswordEntries.FindAsync(id);
            if (passwordEntry == null)
            {
                return NotFound();
            }

            var model = new PasswordEntryViewModel
            {
                Id = passwordEntry.Id,
                Title = passwordEntry.Title,
                EncryptedPassword = EncryptionHelper.DecryptString(passwordEntry.EncryptedPassword)
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("Id,Title,EncryptedPassword")] PasswordEntryViewModel model)
        {
            if (id != model.Id)
            {
                return NotFound();
            }

            if (ModelState.IsValid)
            {
                try
                {
                    var passwordEntry = await _context.PasswordEntries.FindAsync(id);
                    passwordEntry.Title = model.Title;
                    passwordEntry.EncryptedPassword = EncryptionHelper.EncryptString(model.EncryptedPassword);
                    _context.Update(passwordEntry);
                    await _context.SaveChangesAsync();
                }
                catch (DbUpdateConcurrencyException)
                {
                    if (!PasswordEntryExists(model.Id))
                    {
                        return NotFound();
                    }
                    else
                    {
                        throw;
                    }
                }
                return RedirectToAction(nameof(Index));
            }
            return View(model);
        }

        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null)
            {
                return NotFound();
            }

            var passwordEntry = await _context.PasswordEntries
                .FirstOrDefaultAsync(m => m.Id == id);
            if (passwordEntry == null)
            {
                return NotFound();
            }

            return View(passwordEntry);
        }

        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            var passwordEntry = await _context.PasswordEntries.FindAsync(id);
            _context.PasswordEntries.Remove(passwordEntry);
            await _context.SaveChangesAsync();
            return RedirectToAction(nameof(Index));
        }

        private bool PasswordEntryExists(int id)
        {
            return _context.PasswordEntries.Any(e => e.Id == id);
        }
    }
}
