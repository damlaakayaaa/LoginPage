using STB.MAP.UI.Utility;
using System.Collections.Generic;

namespace STB.MAP.UI.Models
{
    

    public class ProjeRepository : IProjeRepository
    {
        private readonly ApplicationDbContext _dbContext;

        public ProjeRepository(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public IEnumerable<Proje> GetAll()
        {
            return _dbContext.Projeler;
        }

        public Proje Get(int id)
        {
            return _dbContext.Projeler.Find(id);
        }

        public void Ekle(Proje proje)
        {
            if (proje != null)
            {
                _dbContext.Projeler.Add(proje);
            }
        }

        public void Guncelle(Proje proje)
        {
            if (proje != null)
            {
                _dbContext.Projeler.Update(proje);
            }
        }

        public void Sil(int id)
        {
            var proje = _dbContext.Projeler.Find(id);
            if (proje != null)
            {
                _dbContext.Projeler.Remove(proje);
            }
        }

        public void Kaydet()
        {
            _dbContext.SaveChanges();
        }
    }
}

