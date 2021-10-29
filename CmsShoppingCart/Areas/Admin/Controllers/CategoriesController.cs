﻿using CmsShoppingCart.Infrastructure;
using CmsShoppingCart.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CmsShoppingCart.Areas.Admin.Controllers
{
    [Area("Admin")]
    public class CategoriesController : Controller
    {
        private readonly CmsShoppingCartContext context;

        public CategoriesController(CmsShoppingCartContext context)
        {
            this.context = context;
        }
        // GET /admin/categories
        public async Task<IActionResult> Index()
        {
            return View(await context.Categories.OrderBy(x=>x.Sorting).ToListAsync());
        }

        // GET /admin/categories/Create
        public IActionResult Create()
        {
            return View();
        }

        // POST /admin/categories/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Category category)
        {
            if (ModelState.IsValid)
            {
                category.Slug = category.Name.ToLower().Replace(" ", "-");
                category.Sorting = 100;

                var slug = await context.Categories.FirstOrDefaultAsync(x => x.Slug == category.Slug);
                if (slug != null)
                {
                    ModelState.AddModelError("", "The Category already exists.");
                    return View(category);
                }

                context.Add(category);
                await context.SaveChangesAsync();

                TempData["Success"] = "The category has been added!";

                return RedirectToAction("Index");
            }
            return View(category);
        }

        // GET /admin/categories/Edit/5
        public async Task<IActionResult> Edit(int id)
        {
            Category category = await context.Categories.FindAsync(id);

            if (category == null)
            {
                return NotFound();
            }

            return View(category);
        }

        // POST /admin/categories/Edit
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, Category category)
        {
            if (ModelState.IsValid)
            {
                category.Slug = category.Name.ToLower().Replace(" ", "-");

                var slug = await context.Categories.Where(x => x.Id != id).FirstOrDefaultAsync(x => x.Slug == category.Slug);
                if (slug != null)
                {
                    ModelState.AddModelError("", "The category already exists.");
                    return View(category);
                }

                context.Update(category);
                await context.SaveChangesAsync();

                TempData["Success"] = "The category has been edited!";

                return RedirectToAction("Edit", new { id });
            }
            return View(category);
        }

        // GET /admin/categories/Delete/5
        public async Task<IActionResult> Delete(int id)
        {
            Category category = await context.Categories.FindAsync(id);

            if (category == null)
            {
                TempData["Error"] = "The Category does not exist!";
            }
            else
            {
                context.Categories.Remove(category);
                await context.SaveChangesAsync();

                TempData["Success"] = "The Category has been deleted!";
            }

            return RedirectToAction("Index");
        }

        // POST /admin/pages/categories
        [HttpPost]
        public async Task<IActionResult> Reorder(int[] id)
        {
            int count = 1;

            foreach (var categoryId in id)
            {
                Category category = await context.Categories.FindAsync(categoryId);
                category.Sorting = count;
                context.Update(category);
                await context.SaveChangesAsync();
                count++;
            }

            return Ok();
        }
    }
}