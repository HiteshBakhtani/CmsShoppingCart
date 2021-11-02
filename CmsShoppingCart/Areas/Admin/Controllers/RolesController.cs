using CmsShoppingCart.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace CmsShoppingCart.Areas.Admin.Controllers
{
    [Authorize(Roles = "Admin")]
    [Area("Admin")]
    public class RolesController : Controller
    {
        private readonly RoleManager<IdentityRole> rolemanager;
        private readonly UserManager<AppUser> usermanager;

        public RolesController(RoleManager<IdentityRole> rolemanager, UserManager<AppUser> usermanager)
        {
            this.rolemanager = rolemanager;
            this.usermanager = usermanager;
        }

        // GET /admin/roles
        public IActionResult Index()
        {
            return View(rolemanager.Roles);
        }

        // GET /admin/roles/create
        public IActionResult Create()
        {
            return View();
        }

        // POST /admin/roles/create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([MinLength(2), Required] string name)
        {
            if (ModelState.IsValid)
            {
                IdentityResult result = await rolemanager.CreateAsync(new IdentityRole(name));
                if (result.Succeeded)
                {
                    TempData["Success"] = "The role has been created!";
                    return RedirectToAction("Index");
                }
                else
                {
                    foreach (IdentityError error in result.Errors) ModelState.AddModelError("", error.Description);
                }
            }
            ModelState.AddModelError("", "Minimum length is 2");
            return View();
        }

        // GET /admin/roles/edit/5
        public async Task<IActionResult> Edit(string id)
        {
            IdentityRole role = await rolemanager.FindByIdAsync(id);

            List<AppUser> members = new List<AppUser>();
            List<AppUser> nonMembers = new List<AppUser>();

            foreach (AppUser user in usermanager.Users)
            {
                var list = await usermanager.IsInRoleAsync(user, role.Name) ? members : nonMembers;
                list.Add(user);
            }
            return View(new RoleEdit
            {
                Role = role,
                Members = members,
                NonMembers = nonMembers
            });
        }

        // POST /admin/roles/edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(RoleEdit roleEdit)
        {
            IdentityResult result;

            foreach (string userId in roleEdit.AddIds ?? new string[] { })
            {
                AppUser user = await usermanager.FindByIdAsync(userId);
                result = await usermanager.AddToRoleAsync(user, roleEdit.RoleName);
            }

            foreach (string userId in roleEdit.DeleteIds ?? new string[] { })
            {
                AppUser user = await usermanager.FindByIdAsync(userId);
                result = await usermanager.RemoveFromRoleAsync(user, roleEdit.RoleName);
            }
            return Redirect(Request.Headers["Referer"].ToString());
        }
    }
}
