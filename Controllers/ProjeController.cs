using Microsoft.AspNetCore.Mvc;
using STB.MAP.UI.Models;
using System.Drawing;

public class ProjeController : Controller
{
    private readonly IProjeRepository _projeRepository;

    public ProjeController(IProjeRepository projeRepository)
    {
        _projeRepository = projeRepository;
    }

    public IActionResult Index()
    {
        var projeler = _projeRepository.GetAll();
        return View(projeler);
    }

    public IActionResult Create()
    {
        return View();
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Create(Proje proje)
    {
        if (ModelState.IsValid)
        {
            _projeRepository.Ekle(proje);
            _projeRepository.Kaydet();
            return RedirectToAction(nameof(Index));
        }
        return View(proje);
    }

    public IActionResult Edit(int? IdProject)
    {
        if (IdProject == null)
        {
            return NotFound();
        }

        var proje = _projeRepository.Get(IdProject.Value);

        if (proje == null)
        {
            return NotFound();
        }

        return View(proje);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public IActionResult Edit(int IdProject, Proje proje)
    {
        if (IdProject != proje.IdProject)
        {
            return NotFound();
        }

        if (ModelState.IsValid)
        {
            _projeRepository.Guncelle(proje);
            _projeRepository.Kaydet();
            return RedirectToAction(nameof(Index));
        }

        return View(proje);
    }

    public IActionResult Delete(int? IdProject)
    {
        if (IdProject == null)
        {
            return NotFound();
        }

        var proje = _projeRepository.Get(IdProject.Value);

        if (proje == null)
        {
            return NotFound();
        }

        return View(proje);
    }

    [HttpPost, ActionName("Delete")]
    [ValidateAntiForgeryToken]
    public IActionResult DeleteConfirmed(int IdProject)
    {
        _projeRepository.Sil(IdProject);
        _projeRepository.Kaydet();
        return RedirectToAction(nameof(Index));
    }
}



