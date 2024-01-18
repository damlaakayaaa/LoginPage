using Microsoft.EntityFrameworkCore;
using STB.MAP.UI.Utility;
using System;
using System.Linq;
using System.Linq.Expressions;

namespace STB.MAP.UI.Models
{
    public interface IProjeRepository
    {
        IEnumerable<Proje> GetAll();
        Proje Get(int id);
        void Ekle(Proje proje);
        void Guncelle(Proje proje);
        void Sil(int id);
        void Kaydet();
    }
}
